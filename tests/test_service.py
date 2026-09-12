"""Compatibilidad del contrato hermano, ventanas, pérdidas y adaptador CLI."""

import asyncio
import inspect
import json
from datetime import timedelta

import pytest
from pydantic import BaseModel
from typer.testing import CliRunner

from atalaya.cli import Umbral, _codigo_salida, app
from atalaya.core import Category, Finding, ScanModule, ServiceContext, ServiceEvent, ServiceModule
from atalaya.core.finding import Severity
from atalaya.core.registry import ModuleRegistry, get_registry
from atalaya.core.report import render_html, render_json


class Inputs(BaseModel):
    target: str = "local"


class ExampleService(ServiceModule):
    id = "example-service"
    name = "Servicio de prueba"
    description = "Prueba"
    category = Category.INTEL
    InputModel = Inputs

    async def run(self, inputs, context):
        context.emit(ServiceEvent(kind="finding", finding=Finding(severity="high", title="Prueba")))
        context.ready.set()
        await context.stop.wait()


def test_service_is_sibling_and_discovered():
    module = get_registry().get("ssh-honeypot")
    assert isinstance(module, ServiceModule)
    assert not isinstance(module, ScanModule)
    assert not hasattr(module, "scan")
    assert inspect.iscoroutinefunction(module.run)
    assert module.info()["input_schema"] == module.input_schema()
    assert "ssh-honeypot" in CliRunner().invoke(app, ["list"]).stdout


def test_both_kinds_share_id_namespace():
    registry = ModuleRegistry()
    registry.register(ExampleService())
    with pytest.raises(ValueError, match="registrado"):
        registry.register(ExampleService())


def test_service_is_abstract():
    with pytest.raises(TypeError):
        ServiceModule()


def test_live_service_emits_before_stop_and_final_report_reuses_pipeline():
    async def scenario():
        module = ExampleService()
        context = ServiceContext(module, "local")
        queue = context.subscribe()
        task = asyncio.create_task(module.serve(Inputs(), context))
        event = await asyncio.wait_for(queue.get(), 1)
        assert event.finding.severity is Severity.HIGH
        assert not task.done()
        assert context.snapshot().grade == "C"
        context.stop.set()
        result = await task
        assert _codigo_salida(result, Umbral.high) == 2
        assert json.loads(render_json(result))["score"] == 75
        assert "Prueba" in render_html(result)
        context.unsubscribe(queue)

    asyncio.run(scenario())


def test_snapshot_expires_findings_and_is_independent():
    module = ExampleService()
    context = ServiceContext(module, "local", 120)
    context.emit(ServiceEvent(kind="finding", finding=Finding(severity="high", title="Original")))
    snapshot = context.snapshot()
    snapshot.findings[0].title = "Mutado"
    assert context.snapshot().findings[0].title == "Original"
    assert context.snapshot(context.started_at + timedelta(seconds=121)).findings == []
    assert snapshot.findings  # Un informe ya cerrado no cambia cuando avanza la ventana.


def test_slow_subscribers_and_findings_have_bounded_memory_and_visible_loss():
    context = ServiceContext(ExampleService(), "local")
    queue = context.subscribe()
    for i in range(1100):
        context.emit(
            ServiceEvent(
                kind="finding", data={"sequence": i}, finding=Finding(severity="info", title=str(i))
            )
        )
    assert queue.qsize() == 128
    assert queue.get_nowait().data["sequence"] == 972
    result = context.snapshot()
    assert len(result.findings) == 1000
    assert result.metadata["dropped_bus_events"] == "972"
    assert result.metadata["dropped_window_findings"] == "100"
    for _ in range(15):
        context.subscribe()
    with pytest.raises(RuntimeError, match="suscriptores"):
        context.subscribe()


def test_service_failure_is_partial_report_without_exception_secrets():
    class Broken(ExampleService):
        async def run(self, inputs, context):
            context.emit(ServiceEvent(kind="finding", finding=Finding(severity="high", title="x")))
            raise OSError("credential-must-not-be-logged")

    module = Broken()
    result = asyncio.run(module.serve(Inputs(), ServiceContext(module, "local")))
    assert result.error and "OSError" in result.error
    assert "credential-must-not-be-logged" not in render_json(result)
    assert len(result.findings) == 1
    assert _codigo_salida(result, Umbral.nunca) == 1


def test_cancellation_propagates_after_cleanup():
    closed = []

    class Cancellable(ExampleService):
        async def run(self, inputs, context):
            try:
                context.ready.set()
                await context.stop.wait()
            finally:
                closed.append(True)

    async def scenario():
        module = Cancellable()
        context = ServiceContext(module, "local")
        task = asyncio.create_task(module.serve(Inputs(), context))
        await context.ready.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())
    assert closed == [True]


def test_service_cli_dispatch_keeps_common_options(monkeypatch):
    def run(module, inputs, on_ready=None):
        context = ServiceContext(module, module.target_of(inputs))
        context.emit(ServiceEvent(kind="finding", finding=Finding(severity="high", title="ñ")))
        return context.snapshot()

    monkeypatch.setattr("atalaya.cli.run_service", run)
    result = CliRunner().invoke(app, ["ssh-honeypot", "--formato", "json"])
    assert result.exit_code == 2
    assert json.loads(result.stdout)["findings"][0]["title"] == "ñ"
