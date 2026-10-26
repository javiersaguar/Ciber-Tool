import asyncio
import contextlib
import ssl
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from atalaya.core.finding import CheckStatus
from atalaya.modules.services_scan import ServicesInput, ServicesModule, identify


@pytest.mark.parametrize(
    "banner,protocol",
    [
        (b"SSH-2.0-OpenSSH_9.9\r\n", "SSH"),
        (b"HTTP/1.1 200 OK\r\nServer: nginx/1.26\r\n\r\n", "HTTP"),
        (b"220 service ESMTP ready\r\n", "SMTP"),
        (b"220 FTP ready\r\n", "FTP"),
        (b"* OK IMAP ready\r\n", "IMAP"),
        (b"+OK POP3 ready\r\n", "POP3"),
        (b"arbitrary PASSWORD=secret", None),
    ],
)
def test_protocol_signatures(banner, protocol):
    assert identify(banner)[0] == protocol


def test_real_ssh_banner_without_authentication():
    async def case():
        sent = []

        async def serve(reader, writer):
            writer.write(b"SSH-2.0-OpenSSH_9.9\r\n")
            await writer.drain()
            sent.append(await reader.read(1024))
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(serve, "127.0.0.1", 0)
        async with server:
            port = server.sockets[0].getsockname()[1]
            output = await ServicesModule()._scan(ServicesInput(host="127.0.0.1", ports=str(port)))
            await asyncio.sleep(0.01)
        assert output.findings[0].attributes["protocol"] == "SSH"
        assert output.findings[0].attributes["product"] == "OpenSSH_9.9"
        assert output.checks[0].status is CheckStatus.DONE
        assert sent == [b""]

    asyncio.run(case())


def test_http_sends_head_and_reads_headers_only():
    async def case():
        received = []

        async def serve(reader, writer):
            received.append(await reader.readuntil(b"\r\n\r\n"))
            writer.write(b"HTTP/1.0 200 OK\r\nServer: LocalTest/1.0\r\n\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(serve, "127.0.0.1", 0)
        async with server:
            port = server.sockets[0].getsockname()[1]
            output = await ServicesModule()._scan(
                ServicesInput(host="127.0.0.1", ports=str(port), http_ports=str(port))
            )
        assert received[0].startswith(b"HEAD / HTTP/1.0")
        assert output.findings[0].attributes["protocol"] == "HTTP"
        assert output.findings[0].attributes["product"] == "LocalTest/1.0"

    asyncio.run(case())


def test_silent_service_is_undetermined():
    async def case():
        tasks = []

        async def serve(reader, writer):
            tasks.append(asyncio.current_task())
            try:
                await reader.read(1)
            finally:
                writer.close()
                with contextlib.suppress(OSError):
                    await writer.wait_closed()

        server = await asyncio.start_server(serve, "127.0.0.1", 0)
        async with server:
            port = server.sockets[0].getsockname()[1]
            output = await ServicesModule()._scan(
                ServicesInput(host="127.0.0.1", ports=str(port), timeout=0.05)
            )
            await asyncio.gather(*tasks)
        assert not output.findings
        assert output.checks[0].status is CheckStatus.UNDETERMINED

    asyncio.run(case())


def test_large_port_set_is_rejected():
    assert ServicesModule().scan(ServicesInput(host="127.0.0.1", ports="1-129")).error


def test_https_identification_with_local_self_signed_certificate(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)

    async def case():
        async def serve(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.0 200 OK\r\nServer: LocalTLS/1.0\r\n\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(serve, "127.0.0.1", 0, ssl=context)
        async with server:
            port = server.sockets[0].getsockname()[1]
            output = await ServicesModule()._scan(
                ServicesInput(host="127.0.0.1", ports=str(port), tls_ports=str(port))
            )
        assert output.findings[0].attributes["protocol"] == "HTTPS"
        assert "confianza no evaluada" in output.findings[0].evidence

    asyncio.run(case())
