"""Servicios: ciclo asíncrono, eventos acotados e informes de ventana móvil."""

from __future__ import annotations

import asyncio
import signal
from abc import abstractmethod
from collections import deque
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

from pydantic import BaseModel, Field

from .finding import Finding, ScanResult
from .module import ModuleDescriptor


class ServiceEvent(BaseModel):
    kind: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    data: dict[str, Any] = Field(default_factory=dict)
    finding: Finding | None = None


class ServiceContext:
    """Estado de una ejecución, siempre confinado al mismo event loop.

    Los suscriptores reciben eventos en vivo, sin garantía de replay. Una cola
    llena descarta su evento más antiguo y cuenta la pérdida. La persistencia
    de eventos de dominio corresponde al servicio, no a este bus en memoria.
    """

    def __init__(self, module: ServiceModule, target: str, window_seconds: int = 300):
        self.module = module
        self.target = target
        self.window_seconds = window_seconds
        self.started_at = datetime.now(timezone.utc)
        self.observation_started_at = self.started_at
        self.stop = asyncio.Event()
        self.ready = asyncio.Event()
        self.metadata: dict[str, str] = {}
        self.error: str | None = None
        self.dropped_events = 0
        self.dropped_findings = 0
        self._findings: deque[tuple[datetime, Finding]] = deque(maxlen=1000)
        self._subscribers: set[asyncio.Queue[ServiceEvent]] = set()

    def subscribe(self) -> asyncio.Queue[ServiceEvent]:
        if len(self._subscribers) >= 16:
            raise RuntimeError("Límite de suscriptores alcanzado")
        queue: asyncio.Queue[ServiceEvent] = asyncio.Queue(maxsize=128)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[ServiceEvent]) -> None:
        self._subscribers.discard(queue)

    def emit(self, event: ServiceEvent) -> None:
        if event.finding is not None:
            if len(self._findings) == self._findings.maxlen:
                self.dropped_findings += 1
            self._findings.append((event.timestamp, event.finding.model_copy(deep=True)))
        for queue in self._subscribers:
            if queue.full():
                queue.get_nowait()
                self.dropped_events += 1
            queue.put_nowait(event)

    def snapshot(self, now: datetime | None = None) -> ScanResult:
        now = now or datetime.now(timezone.utc)
        start = max(self.observation_started_at, now - timedelta(seconds=self.window_seconds))
        while self._findings and self._findings[0][0] < start:
            self._findings.popleft()
        return ScanResult(
            module_id=self.module.id,
            module_name=self.module.name,
            target=self.target,
            started_at=start,
            duration_seconds=max(0, (now - start).total_seconds()),
            findings=[f.model_copy(deep=True) for at, f in self._findings if start <= at <= now],
            error=self.error,
            metadata={
                **self.metadata,
                "kind": "service-window",
                "window_end": now.isoformat(),
                "service_started_at": self.started_at.isoformat(),
                "score_scope": "Actividad detectada; no mide la seguridad del VPS",
                "dropped_bus_events": str(self.dropped_events),
                "dropped_window_findings": str(self.dropped_findings),
            },
        )


class ServiceModule(ModuleDescriptor):
    """Hermana de ScanModule: run vive hasta stop y emite en context."""

    @classmethod
    def info(cls) -> dict:
        return {**super().info(), "kind": "service"}

    @abstractmethod
    async def run(self, inputs: BaseModel, context: ServiceContext) -> None:
        """Abrir recursos, emitir eventos y cerrarlos en finally al parar/cancelar."""

    def target_of(self, inputs: BaseModel) -> str:
        return str(getattr(inputs, next(iter(type(inputs).model_fields))))

    async def serve(self, inputs: BaseModel, context: ServiceContext) -> ScanResult:
        try:
            await self.run(inputs, context)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # No reflejar mensajes arbitrarios que puedan contener credenciales.
            context.error = f"{type(exc).__name__}: el servicio no pudo continuar"
        return context.snapshot()


def run_service(
    module: ServiceModule,
    inputs: BaseModel,
    on_ready: Callable[[ServiceContext], None] | None = None,
) -> ScanResult:
    """Adaptador CLI: SIGINT/SIGTERM en Windows/Linux; un informe al terminar."""

    async def execute() -> ScanResult:
        context = ServiceContext(
            module, module.target_of(inputs), getattr(inputs, "report_window", 300)
        )
        loop = asyncio.get_running_loop()
        previous = {}
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous[sig] = signal.signal(
                sig, lambda *_: loop.call_soon_threadsafe(context.stop.set)
            )
        duration = getattr(inputs, "duration", 0)
        timer = loop.call_later(duration, context.stop.set) if duration else None
        task = asyncio.create_task(module.serve(inputs, context))
        ready = asyncio.create_task(context.ready.wait())
        try:
            await asyncio.wait([task, ready], return_when=asyncio.FIRST_COMPLETED)
            if ready.done() and on_ready:
                on_ready(context)
            return await task
        finally:
            ready.cancel()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, ready, return_exceptions=True)
            if timer:
                timer.cancel()
            for sig, handler in previous.items():
                signal.signal(sig, handler)

    return asyncio.run(execute())
