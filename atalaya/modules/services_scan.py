"""Identificación por respuestas de protocolo; nunca se deduce el servicio del puerto."""

from __future__ import annotations

import asyncio
import contextlib
import re
import socket
import ssl

from pydantic import Field, field_validator

from ..core.finding import Finding, ScanOutput, Severity
from ..core.module import Category, Coverage, ScanModule
from .tcp_ports import TcpPortsInput, parse_ports


class ServicesInput(TcpPortsInput):
    http_ports: str = Field(
        default="80,8000,8080,8888", description="Puertos donde enviar una sonda HTTP HEAD."
    )
    ports: str = Field(
        default="21,22,25,80,110,143,443,8080,8443", description="Puertos a identificar."
    )
    tls_ports: str = Field(
        default="443,8443", description="Puertos donde negociar TLS antes de HTTP."
    )
    timeout: float = Field(
        default=3, gt=0, le=15, description="Presupuesto por servicio en segundos."
    )
    concurrency: int = Field(default=4, ge=1, le=16, description="Sondas simultáneas máximas.")

    @field_validator("tls_ports", "http_ports")
    @classmethod
    def valid_tls_ports(cls, value):
        parse_ports(value)
        return value


def identify(data: bytes) -> tuple[str | None, str | None]:
    """Solo versiones con formato reconocido; no publicar banners arbitrarios."""
    text = data.decode("ascii", errors="replace")
    ssh = re.search(r"(?m)^SSH-(\d\.\d)-([A-Za-z0-9_.+-]{1,100})", text)
    if ssh:
        return "SSH", ssh.group(2)
    if re.match(r"HTTP/1\.[01] \d{3}(?:\s|$)", text):
        server = re.search(r"(?im)^Server:\s*([A-Za-z0-9_. /()+-]{1,100})\r?$", text)
        return "HTTP", server.group(1).strip() if server else None
    if re.match(r"220[ -]", text) and "smtp" in text.lower():
        return "SMTP", None
    if re.match(r"220[ -]", text) and "ftp" in text.lower():
        return "FTP", None
    if text.startswith("+OK") and "pop" in text.lower():
        return "POP3", None
    if text.startswith("* OK") and "imap" in text.lower():
        return "IMAP", None
    return None, None


class ServicesModule(ScanModule):
    id = "services"
    name = "Identificador de servicios"
    description = "Identifica SSH, HTTP(S), SMTP, FTP, POP3 e IMAP mediante respuestas reales."
    category = Category.RECON
    InputModel = ServicesInput
    show_info = True

    def run(self, inputs: ServicesInput) -> ScanOutput:
        if len(parse_ports(inputs.ports)) > 128:
            raise ValueError("La identificación admite como máximo 128 puertos.")
        return asyncio.run(self._scan(inputs))

    async def _probe(self, inputs, family, address, port, tls):
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setblocking(False)
        writer = None
        try:
            await asyncio.get_running_loop().sock_connect(sock, (address[0], port, *address[2:]))
            context = None
            if tls:
                # Solo identificación. La validación de confianza corresponde al módulo tls.
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.open_connection(
                sock=sock,
                ssl=context,
                server_hostname=inputs.host if tls else None,
                limit=8192,
            )
            if tls or port in parse_ports(inputs.http_ports):
                # HEAD evita descargar páginas o enviar credenciales.
                host = inputs.host.encode("idna").decode("ascii")
                if ":" in host:
                    host = f"[{host}]"
                writer.write(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode("ascii"))
                await writer.drain()
            data = bytearray()
            while len(data) < 4096:
                chunk = await reader.read(4096 - len(data))
                if not chunk:
                    break
                data.extend(chunk)
                protocol, version = identify(bytes(data))
                if protocol and (protocol != "HTTP" or b"\r\n\r\n" in data):
                    return protocol, version, "identified"
            protocol, version = identify(bytes(data))
            return protocol, version, "identified" if protocol else "unknown"
        except ConnectionRefusedError:
            return None, None, "closed"
        except (OSError, ssl.SSLError):
            return None, None, "unknown"
        finally:
            if writer:
                writer.close()
                with contextlib.suppress(OSError, asyncio.TimeoutError):
                    await asyncio.wait_for(writer.wait_closed(), 0.2)
            else:
                sock.close()

    async def _scan(self, inputs):
        loop = asyncio.get_running_loop()
        deadline = loop.time() + inputs.total_timeout
        addresses = await asyncio.wait_for(
            loop.getaddrinfo(inputs.host, None, type=socket.SOCK_STREAM), inputs.total_timeout
        )
        family, _, _, _, address = addresses[0]
        ports = parse_ports(inputs.ports)
        tls_ports = set(parse_ports(inputs.tls_ports))
        results = {}
        pending = iter(ports)

        async def worker():
            for port in pending:
                try:
                    results[port] = await asyncio.wait_for(
                        self._probe(inputs, family, address, port, port in tls_ports),
                        inputs.timeout,
                    )
                except asyncio.TimeoutError:
                    results[port] = (None, None, "unknown")

        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(
                asyncio.gather(*(worker() for _ in range(min(inputs.concurrency, len(ports))))),
                max(0, deadline - loop.time()),
            )
        findings, cov = [], Coverage()
        for port in ports:
            protocol, version, state = results.get(port, (None, None, "unknown"))
            label = f"Servicio TCP {port}"
            if state in {"closed", "identified"}:
                cov.done(f"service-{port}", label, "Rechazo TCP" if state == "closed" else protocol)
            else:
                cov.undetermined(
                    f"service-{port}", label, "Protocolo no identificado o sin respuesta"
                )
            if protocol:
                secure = port in tls_ports
                display = "HTTPS" if protocol == "HTTP" and secure else protocol
                findings.append(
                    Finding(
                        severity=Severity.INFO,
                        rule_id="service.identified",
                        location=f"{port}/tcp",
                        attributes={
                            "protocol": display,
                            "product": version or "",
                            "confidence": "high",
                        },
                        title=f"{display} confirmado en TCP {port}",
                        description="Confianza alta en el protocolo por su respuesta. "
                        "La versión anunciada es orientativa y no demuestra un CVE.",
                        evidence=f"IP: {address[0]}; protocolo: {display}; "
                        f"producto anunciado: {version or 'no publicado'}; "
                        f"TLS: {'negociado, confianza no evaluada' if secure else 'no negociado'}",
                    )
                )
        return cov.output(findings, {"IP analizada": address[0], "Puertos": inputs.ports})
