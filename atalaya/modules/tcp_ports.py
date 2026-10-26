"""Reconocimiento TCP por conexión completa sobre un único host."""

from __future__ import annotations

import asyncio
import contextlib
import errno
import ipaddress
import socket

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..core.finding import Finding, ScanOutput, Severity
from ..core.module import Category, ScanModule

COMMON_PORTS = (
    "21,22,23,25,53,80,110,135,139,143,443,445,465,587,993,995,"
    "1433,1521,2049,2375,3306,3389,5432,5900,6379,8000,8080,8443,9200,27017"
)
SERVICE_HINTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    1433: "SQL Server",
    2375: "Docker",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP alternativo",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


def parse_ports(value: str) -> list[int]:
    ports: set[int] = set()
    for item in value.split(","):
        parts = item.strip().split("-")
        if len(parts) not in (1, 2) or any(not p.isascii() or not p.isdigit() for p in parts):
            raise ValueError(
                "Usa puertos separados por comas o rangos, por ejemplo 22,80,8000-8010."
            )
        start, end = int(parts[0]), int(parts[-1])
        if not 1 <= start <= end <= 65535:
            raise ValueError(
                "Los puertos deben estar entre 1 y 65535 y los rangos ser ascendentes."
            )
        if end - start + 1 > 4096:
            raise ValueError("Máximo 4096 puertos por análisis.")
        ports.update(range(start, end + 1))
        if len(ports) > 4096:
            raise ValueError("Máximo 4096 puertos por análisis.")
    return sorted(ports)


class TcpPortsInput(BaseModel):
    model_config = ConfigDict(allow_inf_nan=False)

    host: str = Field(description="Un dominio o una IP (IPv4/IPv6), sin URL ni rango de red.")
    ports: str = Field(default=COMMON_PORTS, max_length=24000, description="Puertos o rangos TCP.")
    timeout: float = Field(
        default=2.0, gt=0, le=30, description="Espera por conexión, en segundos."
    )
    concurrency: int = Field(default=16, ge=1, le=64, description="Conexiones simultáneas máximas.")
    total_timeout: float = Field(default=60, gt=0, le=600, description="Duración máxima total.")

    @field_validator("ports")
    @classmethod
    def valid_ports(cls, value: str) -> str:
        parse_ports(value)
        return value

    @field_validator("host")
    @classmethod
    def valid_host(cls, value: str) -> str:
        value = value.strip()
        if value.startswith("[") and value.endswith("]"):
            value = value[1:-1]
        if not value or any(c.isspace() or c in "/\\?#@%" for c in value):
            raise ValueError("Indica un único dominio o IP, sin URL ni CIDR.")
        if ":" in value:
            ipaddress.IPv6Address(value)
        return value


class TcpPortsModule(ScanModule):
    id = "tcp-ports"
    name = "Escáner de puertos TCP"
    description = "Descubre puertos TCP abiertos en un host mediante conexiones completas."
    category = Category.RECON
    InputModel = TcpPortsInput
    show_info = True

    def run(self, inputs: TcpPortsInput) -> ScanOutput:
        return asyncio.run(self._scan(inputs))

    async def _probe(self, family, address, port: int, timeout: float) -> str:
        endpoint = (address[0], port, *address[2:])
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.setblocking(False)
            try:
                await asyncio.wait_for(
                    asyncio.get_running_loop().sock_connect(sock, endpoint), timeout
                )
                return "open"
            except ConnectionRefusedError:
                return "closed"
            except asyncio.TimeoutError:
                return "unknown"
            except OSError as exc:
                return "closed" if exc.errno == errno.ECONNREFUSED else "unknown"

    async def _scan(self, inputs: TcpPortsInput) -> ScanOutput:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + inputs.total_timeout
        addresses = await asyncio.wait_for(
            loop.getaddrinfo(inputs.host, None, type=socket.SOCK_STREAM), inputs.total_timeout
        )
        # Un único destino fijado para toda la ejecución; no volver a resolver por puerto.
        family, _, _, _, address = addresses[0]
        ports = parse_ports(inputs.ports)
        pending = iter(ports)
        states: dict[int, str] = {}

        async def worker():
            for port in pending:
                states[port] = await self._probe(family, address, port, inputs.timeout)

        workers = [
            asyncio.create_task(worker()) for _ in range(min(inputs.concurrency, len(ports)))
        ]
        # wait_for cancela y espera a los workers; conservar lo completado.
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(asyncio.gather(*workers), max(0, deadline - loop.time()))
        unknown = len(ports) - sum(s in {"open", "closed"} for s in states.values())
        if unknown == len(ports):
            raise RuntimeError("No se pudo determinar el estado de ningún puerto TCP.")
        findings = []
        for port in sorted(p for p, state in states.items() if state == "open"):
            hint = SERVICE_HINTS.get(port)
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title=f"Puerto TCP {port} abierto",
                    rule_id="tcp.open",
                    location=f"{port}/tcp",
                    description=(
                        f"Servicio habitual: {hint} (inferido por puerto, sin confirmar). "
                        if hint
                        else ""
                    )
                    + "Un puerto abierto no demuestra por sí solo una vulnerabilidad.",
                    evidence=f"Conexión TCP completada con {address[0]}:{port}",
                    remediation="Comprueba el servicio y limita su exposición si no es necesaria.",
                )
            )
        findings.append(
            Finding(
                severity=Severity.INFO,
                title="Alcance del reconocimiento TCP",
                description="Los estados indeterminados no se consideran cerrados ni seguros.",
                evidence=f"IP: {address[0]}; solicitados: {len(ports)}; "
                f"abiertos: {sum(s == 'open' for s in states.values())}; "
                f"cerrados: {sum(s == 'closed' for s in states.values())}; "
                f"indeterminados/no probados: {unknown}",
            )
        )
        from ..core.module import Coverage

        cov = Coverage()
        for port in ports:
            name = f"TCP {port}"
            if states.get(port) in {"open", "closed"}:
                cov.done(f"tcp-{port}", name, states[port])
            else:
                cov.undetermined(f"tcp-{port}", name, "Sin respuesta o presupuesto agotado")
        return cov.output(
            findings, {"IP analizada": address[0], "Límite total": f"{inputs.total_timeout:g} s"}
        )
