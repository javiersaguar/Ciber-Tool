"""Pruebas con clientes SSH/HTTP reales sobre loopback, sin servidores externos."""

import asyncio
import contextlib
import json
import os
import socket
import subprocess
import sys
import time
from collections import Counter
from contextlib import asynccontextmanager

import aiohttp
import asyncssh
import pytest

from atalaya.core.service import ServiceContext
from atalaya.modules.ssh_honeypot import HoneypotInputs, SSHHoneypot
from atalaya.services.honeypot import Admission, DenySSH, SSHListener
from atalaya.services.storage import Pseudonymizer


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@asynccontextmanager
async def running(tmp_path, **kwargs):
    inputs = HoneypotInputs(
        data_dir=tmp_path / "state",
        port=free_port(),
        dashboard_port=free_port(),
        auth_delay=0.05,
        **kwargs,
    )
    module = SSHHoneypot()
    context = ServiceContext(module, module.target_of(inputs), inputs.report_window)
    task = asyncio.create_task(module.serve(inputs, context))
    ready = asyncio.create_task(context.ready.wait())
    try:
        done, _ = await asyncio.wait([task, ready], timeout=10, return_when=asyncio.FIRST_COMPLETED)
        assert ready in done, task.result() if task.done() else "startup timeout"
        yield inputs, context, task
    finally:
        ready.cancel()
        context.stop.set()
        await asyncio.wait_for(task, 10)


async def attack(
    inputs, username="real.person@example.org", password="leaked-credential", **kwargs
):
    with pytest.raises(asyncssh.Error):
        async with asyncssh.connect(
            "127.0.0.1",
            inputs.port,
            username=username,
            password=password,
            known_hosts=None,
            client_keys=[],
            agent_path=None,
            config=None,
            preferred_auth=["password"],
            client_version="testbot_1",
            **kwargs,
        ):
            pytest.fail("El honeypot ha concedido acceso")


def test_real_ssh_denies_and_emits_pseudonymized_attempt(tmp_path):
    async def scenario():
        async with running(tmp_path) as (inputs, context, task):
            events = context.subscribe()
            await attack(inputs)
            event = await asyncio.wait_for(events.get(), 3)
            assert event.kind == "ssh.attempt"
            assert event.data["ip"] == "127.0.0.1"
            assert event.data["client_version"] == "SSH-2.0-testbot_1"
            assert "leaked-credential" not in event.model_dump_json()
            assert "real.person@example.org" not in event.model_dump_json()
            assert not task.done()
        assert (await task).error is None
        raw = (inputs.data_dir / "events.sqlite3").read_bytes()
        assert b"leaked-credential" not in raw

    asyncio.run(scenario())


def test_empty_password_none_and_public_key_auth_never_succeed(tmp_path):
    async def scenario():
        async with running(tmp_path) as (inputs, _, _):
            await attack(inputs, username="", password="")
            with pytest.raises(asyncssh.Error):
                await asyncssh.connect(
                    "127.0.0.1",
                    inputs.port,
                    username="root",
                    known_hosts=None,
                    client_keys=[asyncssh.generate_private_key("ssh-ed25519")],
                    agent_path=None,
                    config=None,
                    preferred_auth=["publickey"],
                )

    asyncio.run(scenario())


def test_multiple_passwords_on_one_real_connection_are_capped(tmp_path):
    class Bot(asyncssh.SSHClient):
        def __init__(self):
            self.number = 0

        def password_auth_requested(self):
            self.number += 1
            return f"guess-{self.number}"

    async def scenario():
        async with running(tmp_path, max_attempts=3, alert_threshold=3) as (inputs, context, task):
            queue = context.subscribe()
            with pytest.raises(asyncssh.Error):
                await asyncssh.connect(
                    "127.0.0.1",
                    inputs.port,
                    username="root",
                    known_hosts=None,
                    client_keys=[],
                    agent_path=None,
                    config=None,
                    preferred_auth=["password"],
                    client_factory=Bot,
                )
            attempts, findings = [], []
            while not findings:
                event = await asyncio.wait_for(queue.get(), 3)
                (findings if event.finding else attempts).append(event)
            assert len(attempts) == 3
            assert context.snapshot().grade == "C"
        assert (await task).findings

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "method,args",
    [
        ("session_requested", ()),
        ("connection_requested", ("169.254.169.254", 80, "127.0.0.1", 123)),
        ("server_requested", ("0.0.0.0", 8888)),
        ("unix_connection_requested", ("/var/run/docker.sock",)),
        ("unix_server_requested", ("/tmp/bridge",)),
        ("tun_requested", (0,)),
        ("tap_requested", (0,)),
    ],
)
def test_every_channel_and_forward_handler_is_explicitly_denied(method, args):
    server = DenySSH(HoneypotInputs(), "127.0.0.1", None, None, Counter())
    assert getattr(server, method)(*args) is False


def test_global_and_per_ip_admission_rate_and_concurrency():
    limits = Admission(
        HoneypotInputs(max_connections=2, max_per_ip=1, ip_rate=1, connection_rate=2)
    )
    assert limits.acquire("a", 10)
    assert not limits.acquire("a", 10.1)
    assert limits.acquire("b", 10.1)
    assert not limits.acquire("c", 10.2)
    limits.release("a")
    assert not limits.acquire("a", 10.3)
    assert not limits.acquire("c", 10.3)
    assert limits.acquire("a", 11.1)
    limits.release("a")
    limits.release("b")
    assert limits.acquire("z", 50)
    assert set(limits.by_ip) == {"z"}
    assert set(limits.active) == {"z"}


def test_quota_rejects_before_banner_and_idle_connection_expires(tmp_path):
    async def scenario():
        async with running(tmp_path, max_connections=1, max_per_ip=1, login_timeout=0.4) as (
            i,
            c,
            _,
        ):
            first, writer = await asyncio.open_connection("127.0.0.1", i.port)
            assert (await asyncio.wait_for(first.readline(), 2)).startswith(b"SSH-2.0-")
            second, other = await asyncio.open_connection("127.0.0.1", i.port)
            assert await asyncio.wait_for(second.read(), 2) == b""
            assert await asyncio.wait_for(first.read(), 2) == b""
            writer.close()
            other.close()
            await writer.wait_closed()
            await other.wait_closed()
            assert not c.stop.is_set()

    asyncio.run(scenario())


def test_byte_budget_stops_malicious_ssh_packet_length(tmp_path):
    async def scenario():
        async with running(tmp_path) as (i, _, task):
            reader, writer = await asyncio.open_connection("127.0.0.1", i.port)
            await reader.readline()
            # Declarar 2 GiB y transmitir > presupuesto no puede acumular 2 GiB.
            writer.write(b"SSH-2.0-malformed\r\n" + b"\x7f\xff\xff\xff" + b"x" * 150000)
            with contextlib.suppress(ConnectionError):
                await writer.drain()
                await asyncio.wait_for(reader.read(), 3)
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()
        assert int((await task).metadata.get("byte_limit_disconnects", "0")) >= 1

    asyncio.run(scenario())


def test_output_budget_is_enforced_before_writing():
    async def scenario():
        key = asyncssh.generate_private_key("ssh-ed25519").export_private_key()
        stats = Counter()
        listener = SSHListener(HoneypotInputs(), None, key, None, stats)
        source, producer = socket.socketpair()
        sink, consumer = socket.socketpair()
        for sock in (source, producer, sink, consumer):
            sock.setblocking(False)
        try:
            task = asyncio.create_task(listener._pump(source, sink, 10))
            await asyncio.get_running_loop().sock_sendall(producer, b"x" * 11)
            await asyncio.wait_for(task, 1)
            assert stats["byte_limit_disconnects"] == 1
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.get_running_loop().sock_recv(consumer, 1), 0.05)
        finally:
            for sock in (source, producer, sink, consumer):
                sock.close()

    asyncio.run(scenario())


def test_queue_overflow_and_large_credentials_fail_closed():
    class Conn:
        closed = False

        def get_extra_info(self, *args):
            return "test"

        def abort(self):
            self.closed = True

    async def scenario():
        queue = asyncio.Queue(maxsize=1)
        queue.put_nowait({})
        stats = Counter()
        server = DenySSH(HoneypotInputs(), "127.0.0.1", Pseudonymizer(b"k" * 32), queue, stats)
        conn = Conn()
        server.connection_made(conn)
        assert await server.validate_password("a", "b") is False
        assert conn.closed and stats["dropped_attempts"] == 1
        assert await server.validate_password("a", "x" * 1025) is False
        assert stats["rejected_payloads"] == 1

    asyncio.run(scenario())


def test_private_dashboard_auth_host_origin_sse_and_report(tmp_path):
    async def scenario():
        async with running(tmp_path, alert_threshold=2) as (i, c, _):
            url = c.metadata["dashboard"]
            token = (i.data_dir / "dashboard.token").read_text().strip()
            auth = {"Authorization": f"Bearer {token}"}
            async with aiohttp.ClientSession() as client:
                for path in ("/api/snapshot", "/api/report", "/api/events"):
                    async with client.get(url + path) as r:
                        assert r.status == 401
                        assert r.headers["Cache-Control"] == "no-store"
                async with client.get(
                    url + "/api/snapshot", headers={**auth, "Origin": "https://evil.test"}
                ) as r:
                    assert r.status == 403
                async with client.get(
                    url + "/api/snapshot", headers={**auth, "Host": "evil.test"}
                ) as r:
                    assert r.status == 403
                for path in ("/", "/app.js", "/style.css"):
                    async with client.get(url + path) as r:
                        assert r.status == 200
                        assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
                        assert token not in await r.text()
                await attack(i, password="one")
                await attack(i, password="two")
                async with client.get(url + "/api/events", headers=auth) as r:
                    assert r.status == 200
                    for _ in range(5):
                        line = await asyncio.wait_for(r.content.readline(), 3)
                        if line.startswith(b"data: "):
                            payload = json.loads(line[6:])
                            if payload["total"] == 2:
                                break
                    assert payload["total"] == 2
                    assert payload["report"]["grade"] == "C"
                async with client.get(url + "/api/report", headers=auth) as r:
                    assert (await r.json())["grade"] == "C"
                async with client.get(url + "/api/snapshot", headers=auth) as r:
                    assert (await r.json())["recent"][0]["ip"] == "127.0.0.1"

    asyncio.run(scenario())


def test_dashboard_stream_limit(tmp_path):
    async def scenario():
        async with running(tmp_path) as (i, c, _):
            auth = {
                "Authorization": "Bearer " + (i.data_dir / "dashboard.token").read_text().strip()
            }
            async with aiohttp.ClientSession() as client:
                streams = [
                    await client.get(c.metadata["dashboard"] + "/api/events", headers=auth)
                    for _ in range(5)
                ]
                try:
                    assert [r.status for r in streams] == [200, 200, 200, 200, 503]
                finally:
                    for r in streams:
                        r.close()

    asyncio.run(scenario())


def test_disk_failure_stops_listener_and_releases_state_lock(tmp_path, monkeypatch):
    def broken(*args):
        raise OSError("out of disk; do not echo attacker credentials")

    monkeypatch.setattr("atalaya.services.storage.Store.record", broken)

    async def scenario():
        async with running(tmp_path) as (i, _, task):
            await attack(i)
            result = await asyncio.wait_for(task, 5)
            assert result.error
            assert "attacker credentials" not in result.error
            with pytest.raises(OSError):
                await asyncio.open_connection("127.0.0.1", i.port)
        from atalaya.services.state_lock import state_lock

        with state_lock(i.data_dir):
            pass

    asyncio.run(scenario())


def test_cancelling_live_service_closes_ports_and_drains_events(tmp_path):
    async def scenario():
        inputs = HoneypotInputs(
            data_dir=tmp_path / "state", port=free_port(), dashboard_port=free_port()
        )
        module = SSHHoneypot()
        context = ServiceContext(module, "local")
        task = asyncio.create_task(module.serve(inputs, context))
        await asyncio.wait_for(context.ready.wait(), 10)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        for port in (inputs.port, inputs.dashboard_port):
            with pytest.raises(OSError):
                await asyncio.open_connection("127.0.0.1", port)

    asyncio.run(scenario())


def test_cli_duration_emits_valid_json(tmp_path):
    from typer.testing import CliRunner

    from atalaya.cli import app

    result = CliRunner().invoke(
        app,
        [
            "ssh-honeypot",
            "--duration",
            "0.1",
            "--formato",
            "json",
            "--data-dir",
            str(tmp_path / "state"),
            "--port",
            str(free_port()),
            "--dashboard-port",
            str(free_port()),
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["metadata"]["kind"] == "service-window"


@pytest.mark.parametrize(
    "request_kind", ["session", "direct-tcpip", "tcpip-forward", "streamlocal"]
)
def test_encrypted_channel_requests_before_auth_cannot_reach_a_target(tmp_path, request_kind):
    from asyncssh.constants import MSG_CHANNEL_OPEN, MSG_GLOBAL_REQUEST
    from asyncssh.packet import Boolean, String, UInt32

    async def scenario():
        reached = []

        async def destination(reader, writer):
            reached.append(True)
            writer.close()
            await writer.wait_closed()

        sentinel = await asyncio.start_server(destination, "127.0.0.1", 0)
        target_port = sentinel.sockets[0].getsockname()[1]

        class MalformedClient(asyncssh.SSHClient):
            def connection_made(self, conn):
                self.conn = conn

            def begin_auth(self, username):
                # Sólo en el cliente adversarial de prueba: saltar su propia
                # cola pre-auth para enviar paquetes cifrados fuera de orden.
                self.conn._auth_complete = True
                try:
                    if request_kind == "tcpip-forward":
                        self.conn.send_packet(
                            MSG_GLOBAL_REQUEST,
                            String("tcpip-forward"),
                            Boolean(True),
                            String("127.0.0.1"),
                            UInt32(target_port),
                        )
                    else:
                        kind = (
                            "direct-streamlocal@openssh.com"
                            if request_kind == "streamlocal"
                            else request_kind
                        )
                        extra = ()
                        if request_kind == "direct-tcpip":
                            extra = (
                                String("127.0.0.1"),
                                UInt32(target_port),
                                String("127.0.0.1"),
                                UInt32(1),
                            )
                        elif request_kind == "streamlocal":
                            extra = (String("/var/run/docker.sock"), String(""), UInt32(0))
                        self.conn.send_packet(
                            MSG_CHANNEL_OPEN,
                            String(kind),
                            UInt32(0),
                            UInt32(65536),
                            UInt32(32768),
                            *extra,
                        )
                finally:
                    self.conn._auth_complete = False

        try:
            async with running(tmp_path) as (inputs, _, _):
                with pytest.raises(asyncssh.Error):
                    await asyncssh.connect(
                        "127.0.0.1",
                        inputs.port,
                        username="root",
                        known_hosts=None,
                        client_keys=[],
                        agent_path=None,
                        config=None,
                        client_factory=MalformedClient,
                    )
                assert reached == []
        finally:
            sentinel.close()
            await sentinel.wait_closed()

    asyncio.run(scenario())


def test_restart_restores_current_findings_and_history(tmp_path):
    async def scenario():
        async with running(tmp_path, alert_threshold=2) as (inputs, context, task):
            queue = context.subscribe()
            await attack(inputs, password="one")
            await attack(inputs, password="two")
            while not (await asyncio.wait_for(queue.get(), 3)).finding:
                pass
        assert (await task).grade == "C"
        async with running(tmp_path, alert_threshold=2) as (inputs, context, _):
            assert context.snapshot().grade == "C"
            auth = {
                "Authorization": "Bearer "
                + (inputs.data_dir / "dashboard.token").read_text().strip()
            }
            async with (
                aiohttp.ClientSession() as client,
                client.get(context.metadata["dashboard"] + "/api/snapshot", headers=auth) as r,
            ):
                assert (await r.json())["total"] == 2

    asyncio.run(scenario())


@pytest.mark.skipif(os.name == "nt", reason="Windows usa Ctrl+C; SIGTERM se comprueba en Linux")
def test_sigterm_produces_final_report_and_zero_exit(tmp_path):
    port, dashboard_port = free_port(), free_port()
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "atalaya",
            "ssh-honeypot",
            "--port",
            str(port),
            "--dashboard-port",
            str(dashboard_port),
            "--data-dir",
            str(tmp_path / "state"),
            "--formato",
            "json",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.02)
        else:
            pytest.fail("El subproceso no arrancó")
        proc.terminate()
        stdout, _ = proc.communicate(timeout=10)
        assert proc.returncode == 0
        assert json.loads(stdout)["metadata"]["kind"] == "service-window"
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)
