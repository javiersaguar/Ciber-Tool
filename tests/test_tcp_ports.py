"""Escaneo real en loopback y estados incompletos, sin objetivos externos."""

import asyncio
import json
import socket

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from atalaya.cli import app
from atalaya.modules.tcp_ports import TcpPortsInput, TcpPortsModule, parse_ports


def test_ranges_are_deduplicated():
    assert parse_ports("443,80,80-82") == [80, 81, 82, 443]


@pytest.mark.parametrize("value", ["", "0", "65536", "5-2", "1-4097", "22,,80", "abc", "-1"])
def test_invalid_ports(value):
    with pytest.raises(ValidationError):
        TcpPortsInput(host="127.0.0.1", ports=value)


@pytest.mark.parametrize("value", ["https://host", "10.0.0.0/24", "host:80", "host name", ""])
def test_single_host_only(value):
    with pytest.raises(ValidationError):
        TcpPortsInput(host=value)


def test_ipv6_brackets():
    assert TcpPortsInput(host="[::1]").host == "::1"


@pytest.mark.parametrize("family,host", [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")])
def test_open_and_closed_ports(family, host):
    with socket.socket(family) as listener, socket.socket(family) as closed:
        try:
            listener.bind((host, 0))
            closed.bind((host, 0))
        except OSError:
            pytest.skip("Loopback de esta familia no disponible")
        listener.listen()
        open_port = listener.getsockname()[1]
        closed_port = closed.getsockname()[1]
        closed.close()
        result = TcpPortsModule().scan(
            TcpPortsInput(host=host, ports=f"{open_port},{closed_port}", timeout=3)
        )
        assert result.error is None
        assert any(f.title == f"Puerto TCP {open_port} abierto" for f in result.findings)
        assert "cerrados: 1" in result.findings[-1].evidence


def test_unknown_ports_are_not_closed(monkeypatch):
    async def probe(self, family, address, port, timeout):
        return "open" if port == 80 else "unknown"

    monkeypatch.setattr(TcpPortsModule, "_probe", probe)
    result = TcpPortsModule().scan(TcpPortsInput(host="127.0.0.1", ports="80,443"))
    assert result.error is None
    assert "cerrados: 0" in result.findings[-1].evidence
    assert "indeterminados/no probados: 1" in result.findings[-1].evidence


def test_deadline_keeps_completed_results(monkeypatch):
    cancelled = []

    async def probe(self, family, address, port, timeout):
        if port == 80:
            return "open"
        try:
            await asyncio.sleep(10)
        finally:
            cancelled.append(port)

    monkeypatch.setattr(TcpPortsModule, "_probe", probe)
    result = TcpPortsModule().scan(
        TcpPortsInput(host="127.0.0.1", ports="80,443", concurrency=1, total_timeout=0.1)
    )
    assert result.error is None
    assert cancelled == [443]
    assert "indeterminados/no probados: 1" in result.findings[-1].evidence


def test_all_unknown_is_an_error(monkeypatch):
    async def probe(*args):
        return "unknown"

    monkeypatch.setattr(TcpPortsModule, "_probe", probe)
    assert TcpPortsModule().scan(TcpPortsInput(host="127.0.0.1", ports="80")).error


def test_cli_json_with_real_listener():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        result = CliRunner().invoke(
            app, ["tcp-ports", "127.0.0.1", "--ports", str(port), "--formato", "json"]
        )
        assert result.exit_code == 0, result.output
        report = json.loads(result.stdout)
        assert report["module_id"] == "tcp-ports"
        assert report["findings"][0]["title"] == f"Puerto TCP {port} abierto"
