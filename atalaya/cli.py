"""Interfaz de línea de comandos.

Los subcomandos no están escritos a mano: se generan a partir del registro de
módulos, y sus argumentos salen del `InputModel` de cada uno. Un módulo nuevo
aparece aquí sin tocar este archivo.
"""

from __future__ import annotations

import inspect
import json
import sqlite3
import sys
from enum import Enum
from pathlib import Path
from typing import Annotated, Any

import typer
from pydantic import ValidationError
from rich import box
from rich.console import Console
from rich.table import Table

from . import __version__
from .core.finding import EvaluationStatus, ScanResult, Severity
from .core.module import ScanModule
from .core.registry import get_registry
from .core.report import render_html, render_json, render_terminal
from .core.service import ServiceContext, ServiceModule, run_service

console = Console()
err_console = Console(stderr=True)

# Nombres reservados por las opciones comunes: un módulo no puede usarlos
# como campo de entrada.
OPCIONES_COMUNES = {"formato", "salida", "detallado", "fallar_en"}

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_HALLAZGOS = 2
EXIT_INCOMPLETO = 3


class Formato(str, Enum):
    terminal = "terminal"
    json = "json"
    html = "html"


class Umbral(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    nunca = "nunca"


app = typer.Typer(
    help="Atalaya · caja de herramientas modular de seguridad defensiva.",
    add_completion=False,
    no_args_is_help=True,
)


def _version_callback(valor: bool) -> None:
    if valor:
        console.print(f"Atalaya {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Muestra la versión y sale.",
    ),
) -> None:
    pass


@app.command("list")
def listar() -> None:
    """Lista los módulos disponibles."""
    registry = get_registry()
    tabla = Table(
        title=f"ATALAYA · {len(registry)} módulos",
        title_style="bold green",
        box=box.SIMPLE,
        padding=(0, 2),
        show_lines=False,
    )
    tabla.add_column("COMANDO", style="green bold")
    tabla.add_column("ÁREA", style="dim")
    tabla.add_column("Tipo")
    tabla.add_column("Descripción")

    for categoria, modulos in registry.by_category().items():
        for modulo in modulos:
            tipo = "servicio" if isinstance(modulo, ServiceModule) else "análisis"
            tabla.add_row(modulo.id, categoria.value, tipo, modulo.description)

    console.print()
    console.print(tabla)
    console.print("\n[dim]Detalle de un módulo: atalaya <id> --help[/dim]\n")
    console.print(
        "[dim]Auditoría conjunta: atalaya audit <url> · Historial: atalaya history list[/dim]"
    )


history_app = typer.Typer(help="Consulta y compara auditorías guardadas.", no_args_is_help=True)
app.add_typer(history_app, name="history")


def _audit_terminal(run, output):
    from .core.finding import Severity

    output.print("\n[bold green]ATALAYA[/bold green]  /  Auditoría de superficie")
    output.print(run.target, markup=False)
    output.print(f"[dim]{run.id} · {run.status.label}[/dim]\n")
    table = Table(box=box.SIMPLE, padding=(0, 2))
    for label in ("Módulo", "Estado", "Cobertura", "Nota", "Hallazgos"):
        table.add_column(label)
    for result in run.results:
        c = result.coverage()
        table.add_row(
            result.module_id,
            result.status.label,
            f"{c['done']}/{c['total']}",
            result.grade or "Sin nota",
            str(sum(f.severity not in {Severity.INFO, Severity.OK} for f in result.findings)),
        )
    output.print(table)
    if run.comparison:
        labels = {
            "new": "nuevos",
            "resolved": "resueltos",
            "changed": "cambiados",
            "unverified": "sin verificar",
            "unchanged": "sin cambios",
        }
        output.print(" · ".join(f"{len(v)} {labels[k]}" for k, v in run.comparison.items()))
    for result in run.results:
        render_terminal(result, output, verbose=True)


def _emit_audit(run, formato, salida):
    from .core.audit import audit_json
    from .core.workbench import render_workbench

    if formato is Formato.terminal:
        if salida:
            with salida.open("w", encoding="utf-8") as file:
                _audit_terminal(run, Console(file=file, width=110))
        else:
            _audit_terminal(run, console)
    else:
        text = (
            audit_json(run)
            if formato is Formato.json
            else render_workbench(
                run.results, run.target, "Auditoría de superficie", run.comparison, run.id
            )
        )
        if salida:
            salida.write_text(text, encoding="utf-8")
        else:
            _escribe_utf8(text)
    if salida:
        err_console.print(f"Informe guardado: {salida}", markup=False)


@app.command("audit")
def auditar(
    target: str = typer.Argument(..., help="URL base del objetivo."),
    modules: str = typer.Option(
        "http-headers,tls,tcp-ports,services,web-paths,web-crawl",
        help="IDs separados por comas; subdomains se activa explícitamente.",
    ),
    ports: str = typer.Option(
        "22,80,443,8080,8443", help="Puertos para reconocimiento e identificación."
    ),
    timeout: float = typer.Option(3, min=0.1, max=15, help="Presupuesto por conexión."),
    history_dir: Annotated[Path, typer.Option(help="Directorio privado del historial.")] = Path(
        ".atalaya/history"
    ),
    save: bool = typer.Option(
        True, "--save/--no-save", help="Guardar y comparar con la última ejecución."
    ),
    formato: Annotated[Formato, typer.Option("--formato", "-f")] = Formato.terminal,
    salida: Annotated[Path | None, typer.Option("--salida", "-o")] = None,
    fallar_en: Annotated[Umbral, typer.Option("--fallar-en")] = Umbral.high,
) -> None:
    """Ejecuta varios módulos y genera un informe conjunto con evolución histórica."""
    from .core.audit import HistoryStore, compare_runs, run_audit

    try:
        run = run_audit(
            target,
            modules,
            ports,
            timeout,
            on_module=lambda name: err_console.print(f"Analizando · {name}", markup=False),
        )
        if save:
            store = HistoryStore(history_dir)
            previous = store.latest(run)
            if previous:
                run.previous_id = previous.id
                run.comparison = compare_runs(previous, run)
            store.save(run)
            err_console.print(f"Historial · {run.id}", markup=False)
        _emit_audit(run, formato, salida)
    except (ValueError, OSError, sqlite3.Error) as exc:
        err_console.print(str(exc), markup=False)
        raise typer.Exit(EXIT_ERROR) from None
    codes = [_codigo_salida(result, fallar_en) for result in run.results]
    for code in (EXIT_ERROR, EXIT_HALLAZGOS, EXIT_INCOMPLETO):
        if code in codes:
            raise typer.Exit(code)


@history_app.command("list")
def historial(
    history_dir: Annotated[Path, typer.Option()] = Path(".atalaya/history"),
    limit: int = typer.Option(20, min=1, max=100),
    json_output: bool = typer.Option(False, "--json"),
):
    """Lista las auditorías guardadas, sin volver a escanear."""
    from .core.audit import HistoryStore

    try:
        runs = HistoryStore(history_dir).list(limit)
    except (ValueError, OSError, sqlite3.Error) as exc:
        err_console.print(str(exc), markup=False)
        raise typer.Exit(EXIT_ERROR) from None
    if json_output:
        _escribe_utf8(
            json.dumps(
                [
                    {
                        "id": r.id,
                        "target": r.target,
                        "status": r.status.value,
                        "started_at": r.started_at.isoformat(),
                    }
                    for r in runs
                ],
                indent=2,
            )
        )
        return
    table = Table(title="ATALAYA · Historial", box=box.SIMPLE)
    for title in ("ID", "Objetivo", "Fecha UTC", "Estado"):
        table.add_column(title)
    for run in runs:
        table.add_row(
            run.id, run.target, run.started_at.strftime("%Y-%m-%d %H:%M"), run.status.label
        )
    console.print(table if runs else "Aún no hay auditorías guardadas.")


@history_app.command("show")
def historial_ver(
    identifier: str,
    history_dir: Annotated[Path, typer.Option()] = Path(".atalaya/history"),
    formato: Annotated[Formato, typer.Option("--formato", "-f")] = Formato.terminal,
    salida: Annotated[Path | None, typer.Option("--salida", "-o")] = None,
):
    """Vuelve a generar un informe desde una auditoría guardada."""
    from .core.audit import HistoryStore

    try:
        _emit_audit(HistoryStore(history_dir).get(identifier), formato, salida)
    except (ValueError, OSError, sqlite3.Error) as exc:
        err_console.print(str(exc), markup=False)
        raise typer.Exit(EXIT_ERROR) from None


@history_app.command("compare")
def historial_comparar(
    previous_id: str,
    current_id: str,
    history_dir: Annotated[Path, typer.Option()] = Path(".atalaya/history"),
    formato: Annotated[Formato, typer.Option("--formato", "-f")] = Formato.terminal,
    salida: Annotated[Path | None, typer.Option("--salida", "-o")] = None,
):
    """Compara dos auditorías del mismo objetivo y configuración."""
    from .core.audit import HistoryStore, compare_runs

    try:
        store = HistoryStore(history_dir)
        previous, current = store.get(previous_id), store.get(current_id)
        current.comparison = compare_runs(previous, current)
        current.previous_id = previous.id
        _emit_audit(current, formato, salida)
    except (ValueError, OSError, sqlite3.Error) as exc:
        err_console.print(str(exc), markup=False)
        raise typer.Exit(EXIT_ERROR) from None


def _emitir(result: ScanResult, formato: Formato, salida: Path | None, detallado: bool) -> None:
    if formato is Formato.terminal:
        if salida:
            # Un informe de terminal a fichero se guarda sin códigos de color.
            fichero = Console(file=salida.open("w", encoding="utf-8"), width=100)
            render_terminal(result, fichero, detallado)
            fichero.file.close()
            console.print(f"[green]Informe guardado en {salida}[/green]")
        else:
            render_terminal(result, console, detallado)
        return

    texto = render_json(result) if formato is Formato.json else render_html(result, detallado)
    if salida:
        salida.write_text(texto, encoding="utf-8")
        console.print(f"[green]Informe guardado en {salida}[/green]")
    else:
        _escribe_utf8(texto)


def _escribe_utf8(texto: str) -> None:
    """Escribe en stdout siempre en UTF-8.

    Con `print` la codificación la decide la consola, que en Windows es cp1252,
    así que al redirigir `--formato json` a un fichero se rompían los acentos.
    """
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is None:  # stdout sustituido (por ejemplo, en los tests)
        print(texto)
        return
    buffer.write(texto.encode("utf-8"))
    buffer.write(b"\n")
    buffer.flush()


def _codigo_salida(result: ScanResult, umbral: Umbral) -> int:
    """Error, hallazgos por encima del umbral, análisis incompleto o todo bien.

    Un análisis incompleto no puede salir con 0: en un CI eso se leería como
    "revisado y limpio" cuando hay comprobaciones que no llegaron a concluir.
    """
    if result.error:
        return EXIT_ERROR
    if umbral is not Umbral.nunca:
        limite = Severity(umbral.value)
        orden = list(Severity)
        tope = orden.index(limite)
        if any(orden.index(f.severity) <= tope for f in result.findings):
            return EXIT_HALLAZGOS
    if result.status is not EvaluationStatus.COMPLETE:
        return EXIT_INCOMPLETO
    return EXIT_OK


def _parametros(modulo: ScanModule | ServiceModule) -> list[inspect.Parameter]:
    """Traduce el InputModel del módulo a parámetros de typer."""
    requeridos: list[inspect.Parameter] = []
    opcionales: list[inspect.Parameter] = []

    for nombre, campo in modulo.InputModel.model_fields.items():
        if nombre in OPCIONES_COMUNES:
            raise ValueError(
                f"El módulo '{modulo.id}' usa '{nombre}' como campo de entrada, "
                f"pero es una opción reservada de la CLI."
            )
        ayuda = campo.description or ""
        if campo.is_required():
            requeridos.append(
                inspect.Parameter(
                    nombre,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    annotation=campo.annotation,
                    default=typer.Argument(..., help=ayuda),
                )
            )
        else:
            opcionales.append(
                inspect.Parameter(
                    nombre,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    annotation=campo.annotation,
                    default=typer.Option(campo.default, help=ayuda),
                )
            )

    comunes = [
        inspect.Parameter(
            "formato",
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            annotation=Formato,
            default=typer.Option(Formato.terminal, "--formato", "-f", help="Formato del informe."),
        ),
        inspect.Parameter(
            "salida",
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            annotation=Path,
            default=typer.Option(None, "--salida", "-o", help="Guarda el informe en un fichero."),
        ),
        inspect.Parameter(
            "detallado",
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            annotation=bool,
            default=typer.Option(
                False, "--detallado", "-v", help="Incluye también lo que está correcto."
            ),
        ),
        inspect.Parameter(
            "fallar_en",
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            annotation=Umbral,
            default=typer.Option(
                Umbral.high,
                "--fallar-en",
                help="Gravedad a partir de la cual se sale con código 2 (útil en CI).",
            ),
        ),
    ]
    return requeridos + opcionales + comunes


def _construir_comando(modulo: ScanModule | ServiceModule):
    def comando(**kwargs: Any) -> None:
        formato: Formato = kwargs.pop("formato")
        salida: Path | None = kwargs.pop("salida")
        detallado: bool = kwargs.pop("detallado")
        fallar_en: Umbral = kwargs.pop("fallar_en")

        try:
            inputs = modulo.parse_inputs(**kwargs)
        except ValidationError as exc:
            err_console.print("[red]Entradas no válidas:[/red]")
            for error in exc.errors():
                campo = ".".join(str(p) for p in error["loc"]) or "(entrada)"
                err_console.print(f"  [cyan]{campo}[/cyan]: {error['msg']}")
            raise typer.Exit(EXIT_ERROR) from None

        if isinstance(modulo, ServiceModule):
            err_console.print("Servicio activo hasta Ctrl+C, SIGTERM o --duration.")
            result = run_service(
                modulo,
                inputs,
                on_ready=_servicio_listo,
                on_startup_error=_servicio_no_arranca,
            )
        else:
            result = modulo.scan(inputs)
        detallado = detallado or modulo.show_info
        _emitir(result, formato, salida, detallado)
        raise typer.Exit(_codigo_salida(result, fallar_en))

    comando.__name__ = modulo.id.replace("-", "_")
    comando.__doc__ = modulo.description
    comando.__signature__ = inspect.Signature(_parametros(modulo))  # type: ignore[attr-defined]
    return comando


def _servicio_no_arranca(detalle: str) -> None:
    """El informe solo dice el tipo de error; aquí se da el motivo concreto."""
    err_console.print(f"No se pudo arrancar el servicio: {detalle}", markup=False)


def _servicio_listo(context: ServiceContext) -> None:
    err_console.print(f"Escuchando: {context.target}", markup=False)
    for key, value in context.metadata.items():
        err_console.print(f"  {key}: {value}", markup=False)


def _registrar_comandos() -> None:
    for modulo in get_registry().all():
        app.command(modulo.id, help=modulo.description)(_construir_comando(modulo))


_registrar_comandos()


def main_cli() -> None:
    """Punto de entrada del comando `atalaya`.

    Se llama a la aplicación con `windows_expand_args=False` porque, en Windows,
    Click expande los comodines de los argumentos él mismo (cmd.exe no lo hace
    por ti, al contrario que un shell de Unix). Eso destroza cualquier opción
    cuyo valor sea justamente un patrón: `--exclude "tests/*"` llegaba
    convertido en la lista de archivos de esa carpeta.
    """
    app(windows_expand_args=False)


if __name__ == "__main__":  # pragma: no cover
    main_cli()
