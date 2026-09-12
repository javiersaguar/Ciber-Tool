"""Interfaz de línea de comandos.

Los subcomandos no están escritos a mano: se generan a partir del registro de
módulos, y sus argumentos salen del `InputModel` de cada uno. Un módulo nuevo
aparece aquí sin tocar este archivo.
"""

from __future__ import annotations

import inspect
from enum import Enum
from pathlib import Path
from typing import Any

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from . import __version__
from .core.finding import ScanResult, Severity
from .core.module import ScanModule
from .core.registry import get_registry
from .core.report import render_html, render_json, render_terminal

console = Console()
err_console = Console(stderr=True)

# Nombres reservados por las opciones comunes: un módulo no puede usarlos
# como campo de entrada.
OPCIONES_COMUNES = {"formato", "salida", "detallado", "fallar_en"}

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_HALLAZGOS = 2


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
    tabla = Table(title=f"Módulos disponibles ({len(registry)})", title_style="bold")
    tabla.add_column("ID", style="cyan bold")
    tabla.add_column("Categoría", style="magenta")
    tabla.add_column("Descripción")

    for categoria, modulos in registry.by_category().items():
        for modulo in modulos:
            tabla.add_row(modulo.id, categoria.value, modulo.description)

    console.print()
    console.print(tabla)
    console.print("\n[dim]Detalle de un módulo: atalaya <id> --help[/dim]\n")


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
        print(texto)


def _codigo_salida(result: ScanResult, umbral: Umbral) -> int:
    if result.error:
        return EXIT_ERROR
    if umbral is Umbral.nunca:
        return EXIT_OK
    limite = Severity(umbral.value)
    orden = list(Severity)
    tope = orden.index(limite)
    if any(orden.index(f.severity) <= tope for f in result.findings):
        return EXIT_HALLAZGOS
    return EXIT_OK


def _parametros(modulo: ScanModule) -> list[inspect.Parameter]:
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


def _construir_comando(modulo: ScanModule):
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

        result = modulo.scan(inputs)
        _emitir(result, formato, salida, detallado)
        raise typer.Exit(_codigo_salida(result, fallar_en))

    comando.__name__ = modulo.id.replace("-", "_")
    comando.__doc__ = modulo.description
    comando.__signature__ = inspect.Signature(_parametros(modulo))  # type: ignore[attr-defined]
    return comando


def _registrar_comandos() -> None:
    for modulo in get_registry().all():
        app.command(modulo.id, help=modulo.description)(_construir_comando(modulo))


_registrar_comandos()


if __name__ == "__main__":  # pragma: no cover
    app()
