"""SSH exclusivamente de autenticación, aislado mediante socketpair con cuotas."""

from __future__ import annotations

import asyncio
import contextlib
import functools
import socket
import time
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import asyncssh

from atalaya.core.service import ServiceContext, ServiceEvent

from .dashboard import Dashboard
from .storage import Store, initialize_secrets, normalize_ip


class Admission:
    """Cuotas antes del banner/KEX; las IP inactivas expiran tras un segundo."""

    def __init__(self, inputs):
        self.inputs = inputs
        self.active: Counter[str] = Counter()
        self.starts: deque[float] = deque()
        self.by_ip: dict[str, deque[float]] = {}

    def acquire(self, ip: str, now: float) -> bool:
        while self.starts and self.starts[0] <= now - 1:
            self.starts.popleft()
        self.by_ip = {key: times for key, times in self.by_ip.items() if times[-1] > now - 1}
        times = self.by_ip.get(ip, deque())
        while times and times[0] <= now - 1:
            times.popleft()
        if (
            sum(self.active.values()) >= self.inputs.max_connections
            or self.active[ip] >= self.inputs.max_per_ip
            or len(self.starts) >= self.inputs.connection_rate
            or len(times) >= self.inputs.ip_rate
        ):
            return False
        self.active[ip] += 1
        self.starts.append(now)
        times.append(now)
        self.by_ip[ip] = times
        return True

    def release(self, ip: str) -> None:
        self.active[ip] -= 1
        if self.active[ip] <= 0:
            del self.active[ip]


class DenySSH(asyncssh.SSHServer):
    def __init__(self, inputs, ip: str, pseudonyms, queue, stats):
        self.inputs = inputs
        self.ip = ip
        self.pseudonyms = pseudonyms
        self.queue = queue
        self.stats = stats
        self.attempts = 0
        self.conn = None

    def connection_made(self, conn):
        self.conn = conn

    def begin_auth(self, username):
        return True  # Incluso usuario vacío: SIEMPRE requiere autenticación.

    def auth_completed(self):
        # Invariante adicional frente a cambios de configuración/librería.
        self.conn.abort()

    def password_auth_supported(self):
        return True

    def public_key_auth_supported(self):
        return False

    def kbdint_auth_supported(self):
        return False

    async def validate_password(self, username, password):
        self.attempts += 1
        if self.attempts > self.inputs.max_attempts or len(username) > 256 or len(password) > 1024:
            self.stats["rejected_payloads"] += 1
            self.conn.abort()
            return False
        event = self.pseudonyms.attempt(
            self.ip, username, password, self.conn.get_extra_info("client_version", ""), time.time()
        )
        # No mantener las cadenas en este frame durante el await.
        del username, password
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            self.stats["dropped_attempts"] += 1
            self.conn.abort()
            return False
        await asyncio.sleep(self.inputs.auth_delay)
        if self.attempts >= self.inputs.max_attempts:
            self.conn.abort()
        return False

    def session_requested(self):
        return False  # Incluye shell, exec y subsistemas (SFTP/SCP).

    def connection_requested(self, dest_host, dest_port, orig_host, orig_port):
        return False

    def server_requested(self, listen_host, listen_port):
        return False

    def unix_connection_requested(self, dest_path):
        return False

    def unix_server_requested(self, listen_path):
        return False

    def tun_requested(self, unit):
        return False

    def tap_requested(self, unit):
        return False


class SSHListener:
    INPUT_BUDGET = 128 * 1024
    OUTPUT_BUDGET = 64 * 1024

    def __init__(self, inputs, pseudonyms, key, queue, stats):
        self.inputs = inputs
        self.pseudonyms = pseudonyms
        self.key = asyncssh.import_private_key(key)
        self.queue = queue
        self.stats = stats
        self.admission = Admission(inputs)
        self.connections: set[asyncio.Task] = set()
        self.socket = None
        self.failure = asyncio.get_running_loop().create_future()

    def open(self):
        family = socket.AF_INET6 if ":" in self.inputs.host else socket.AF_INET
        self.socket = socket.socket(family, socket.SOCK_STREAM)
        try:
            if family == socket.AF_INET6:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            self.socket.setblocking(False)
            self.socket.bind((self.inputs.host, self.inputs.port))
            self.socket.listen(128)
        except BaseException:
            self.socket.close()
            raise

    async def accept(self):
        loop = asyncio.get_running_loop()
        while True:
            client, address = await loop.sock_accept(self.socket)
            ip = normalize_ip(address[0])
            if not self.admission.acquire(ip, loop.time()):
                self.stats["rejected_connections"] += 1
                client.close()  # Sin banner, KEX ni respuesta a una dirección ajena.
                continue
            self.stats["accepted_connections"] += 1
            task = asyncio.create_task(self._connection(client, ip))
            self.connections.add(task)
            task.add_done_callback(self._finished)

    def _finished(self, task):
        self.connections.discard(task)
        if not task.cancelled() and task.exception() is not None and not self.failure.done():
            self.failure.set_result(task.exception())

    async def watch_failure(self):
        raise await self.failure

    async def _pump(self, source, destination, limit):
        loop = asyncio.get_running_loop()
        used = 0
        while True:
            data = await loop.sock_recv(source, min(16384, limit - used + 1))
            if not data:
                return
            used += len(data)
            if used > limit:
                self.stats["byte_limit_disconnects"] += 1
                return
            await loop.sock_sendall(destination, data)

    async def _connection(self, client, ip):
        tasks = []
        sockets = [client]
        handler = DenySSH(self.inputs, ip, self.pseudonyms, self.queue, self.stats)
        try:
            # Sólo un socketpair local, sin dirección de destino ni DNS. Permite
            # acotar bytes antes del parser usando la API pública run_server.
            relay, ssh_socket = socket.socketpair()
            sockets.extend((relay, ssh_socket))
            for sock in sockets:
                sock.setblocking(False)
            tasks = [
                asyncio.create_task(self._pump(client, relay, self.INPUT_BUDGET)),
                asyncio.create_task(self._pump(relay, client, self.OUTPUT_BUDGET)),
                asyncio.ensure_future(
                    asyncssh.run_server(
                        ssh_socket,
                        config=None,
                        server_factory=lambda: handler,
                        server_host_keys=[self.key],
                        server_version="Atalaya",
                        password_auth=True,
                        public_key_auth=False,
                        kbdint_auth=False,
                        host_based_auth=False,
                        gss_auth=False,
                        gss_kex=False,
                        compression_algs=["none"],
                        login_timeout=self.inputs.login_timeout,
                        allow_pty=False,
                        x11_forwarding=False,
                        agent_forwarding=False,
                    )
                ),
            ]
            done, _ = await asyncio.wait(
                tasks, timeout=self.inputs.login_timeout, return_when=asyncio.FIRST_COMPLETED
            )
            for task in done:
                task.result()
        except (asyncssh.Error, OSError, ValueError):
            # No registrar excepciones de protocolo ni su entrada no confiable.
            self.stats["protocol_disconnects"] += 1
        finally:
            if handler.conn:
                handler.conn.abort()
            for task in tasks:
                task.cancel()
            for sock in sockets:
                sock.close()
            await asyncio.gather(*tasks, return_exceptions=True)
            self.admission.release(ip)

    async def close(self):
        if self.socket:
            self.socket.close()
        tasks = list(self.connections)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def serve_honeypot(inputs, context: ServiceContext):
    from .state_lock import state_lock

    loop = asyncio.get_running_loop()
    stats = Counter()
    queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=1024)
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="atalaya-store")

    async def disk(fn, *args):
        return await loop.run_in_executor(executor, functools.partial(fn, *args))

    store = listener = dashboard = None
    tasks = []
    stack = contextlib.ExitStack()
    cleanup = contextlib.AsyncExitStack()
    try:
        stack.enter_context(state_lock(inputs.data_dir))
        pseudonyms, token, key = await disk(initialize_secrets, inputs.data_dir)
        store = await disk(Store, inputs)
        cleanup.push_async_callback(disk, store.close)
        dashboard = Dashboard(inputs, context, token, stats)
        cleanup.push_async_callback(dashboard.close)
        for epoch, finding in await disk(store.restore_findings, time.time()):
            stamp = datetime.fromtimestamp(epoch, timezone.utc)
            context.observation_started_at = min(context.observation_started_at, stamp)
            context.emit(ServiceEvent(kind="finding", timestamp=stamp, finding=finding))
        dashboard.data = await disk(store.dashboard, time.time())
        await dashboard.start()
        listener = SSHListener(inputs, pseudonyms, key, queue, stats)
        listener.open()
        context.metadata.update(
            {
                "dashboard": dashboard.url,
                "token_file": str((inputs.data_dir / "dashboard.token").resolve()),
                "retention_hours": str(inputs.retention_hours),
                "detection": f"{inputs.alert_threshold} claves distintas / {inputs.alert_window}s",
            }
        )

        async def persist():
            refreshed = 0.0
            while not context.stop.is_set():  # MUTANTE: sin drenar al parar
                batch = []
                with contextlib.suppress(asyncio.TimeoutError):
                    batch.append(await asyncio.wait_for(queue.get(), timeout=0.5))
                while not queue.empty() and len(batch) < 64:
                    batch.append(queue.get_nowait())
                if batch:
                    for event, finding in await disk(store.record, batch, time.time()):
                        context.emit(
                            ServiceEvent(
                                kind="ssh.attempt",
                                timestamp=datetime.fromisoformat(event["timestamp"]),
                                data=event,
                            )
                        )
                        if finding:
                            context.emit(ServiceEvent(kind="finding", finding=finding))
                if loop.time() - refreshed >= 1:
                    dashboard.data = await disk(store.dashboard, time.time())
                    refreshed = loop.time()

        worker = asyncio.create_task(persist())
        tasks = [
            asyncio.create_task(listener.accept()),
            worker,
            asyncio.create_task(context.stop.wait()),
            asyncio.create_task(listener.watch_failure()),
        ]
        context.ready.set()
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()  # Fallo de persistencia/listener: cerrar y reportar error.
    finally:
        context.stop.set()
        if tasks:
            tasks[0].cancel()
            tasks[2].cancel()
            tasks[3].cancel()
        if listener:
            await listener.close()
        if tasks:
            drained = await asyncio.gather(
                asyncio.wait_for(tasks[1], timeout=5), return_exceptions=True
            )
            if isinstance(drained[0], BaseException):
                context.error = "Persistencia incompleta al cerrar el servicio"
            await asyncio.gather(*tasks, return_exceptions=True)
        try:
            await cleanup.aclose()
        finally:
            context.metadata.update({key: str(value) for key, value in stats.items()})
            executor.shutdown(wait=True, cancel_futures=True)
            stack.close()
