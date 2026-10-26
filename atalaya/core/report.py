"""Renderizado de resultados: terminal, JSON y HTML.

Como todos los módulos devuelven `Finding`, estos tres renderizadores valen
para cualquier herramienta presente y futura.
"""

from __future__ import annotations

import json

from rich.console import Console, Group
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .finding import CheckStatus, EvaluationStatus, Finding, ScanResult, Severity

# Las que se enseñan siempre; OK e INFO solo en modo detallado.
_RUIDO = {Severity.OK, Severity.INFO}


def _grade_style(grade: str | None) -> str:
    if grade is None:
        return "bold black on yellow"
    if grade.startswith("A"):
        return "bold white on green"
    if grade == "B":
        return "bold black on bright_green"
    if grade == "C":
        return "bold black on yellow"
    if grade == "D":
        return "bold white on dark_orange"
    return "bold white on red"


def render_terminal(result: ScanResult, console: Console, verbose: bool = False) -> None:
    """Informe legible en terminal."""
    cabecera = Text()
    cabecera.append(f"{result.module_name}\n", style="bold")
    cabecera.append(result.target, style="cyan")
    if result.metadata:
        detalles = "  ·  ".join(f"{k}: {v}" for k, v in result.metadata.items())
        cabecera.append(f"\n{detalles}", style="dim")

    partes = [cabecera, Text(), _nota_terminal(result)]
    cobertura = _texto_cobertura(result)
    if cobertura:
        partes.append(Text(cobertura, style="dim"))

    console.print()
    console.print(Panel(Group(*partes), border_style="blue"))

    if result.error:
        console.print(
            Panel(
                Text(result.error, style="red"),
                title="El análisis no pudo completarse",
                border_style="red",
            )
        )
        if not result.findings:
            return

    _print_pendientes(result, console, verbose)

    mostrados = [f for f in result.by_severity() if verbose or f.severity not in _RUIDO]
    if not mostrados:
        console.print("  [green]Sin hallazgos que reportar.[/green]")
    for finding in mostrados:
        _print_finding(finding, console)

    console.print()
    console.print(_summary_table(result, verbose))
    console.print(f"[dim]Completado en {result.duration_seconds}s[/dim]")


def _nota_terminal(result: ScanResult) -> Text:
    estado = result.status
    if estado is EvaluationStatus.COMPLETE:
        nota = Text(f" {result.grade} ", style=_grade_style(result.grade))
        nota.append(f"  {result.score}/100", style="bold")
        return nota
    if estado is EvaluationStatus.INCOMPLETE:
        nota = Text(" ANÁLISIS INCOMPLETO ", style="bold black on yellow")
        nota.append(
            f"  sin nota · como máximo {result.score_upper_bound}/100 con lo comprobado",
            style="bold",
        )
        return nota
    nota = Text(" NO EVALUADO ", style="bold white on grey37")
    nota.append("  sin nota: no se llegó a comprobar nada", style="bold")
    return nota


def _texto_cobertura(result: ScanResult) -> str:
    """Una línea con cuántas comprobaciones concluyeron; vacía si el módulo no informa."""
    if not result.checks:
        return ""
    c = result.coverage()
    texto = f"Cobertura: {c['done']} de {c['total']} comprobaciones concluidas"
    if c["skipped"]:
        texto += f" · {c['skipped']} omitida(s)"
    if c["undetermined"]:
        texto += f" · {c['undetermined']} sin determinar"
    return texto


def _checks_visibles(result: ScanResult, verbose: bool):
    """Las pendientes siempre; las omitidas solo en modo detallado."""
    return [
        c
        for c in result.checks
        if c.status is CheckStatus.UNDETERMINED or (verbose and c.status is CheckStatus.SKIPPED)
    ]


def _print_pendientes(result: ScanResult, console: Console, verbose: bool) -> None:
    """Lo que no se pudo comprobar va siempre a la vista: es lo que impide dar nota."""
    visibles = _checks_visibles(result, verbose)
    if not visibles:
        return
    tabla = Table(show_header=False, box=None, padding=(0, 2, 0, 2))
    for check in visibles:
        estilo = "yellow" if check.status is CheckStatus.UNDETERMINED else "dim"
        tabla.add_row(
            Text(check.status.label, style=estilo),
            Text(check.name, style="bold"),
            Text(check.detail or "", style="dim"),
        )
    console.print(tabla)
    console.print()


# Ancho de la columna de gravedad más su separación: el cuerpo del hallazgo se
# sangra otro tanto para que las líneas partidas queden alineadas.
_SANGRIA = 10


def _print_finding(finding: Finding, console: Console) -> None:
    titulo = Text()
    titulo.append(f"{finding.severity.label:>8}", style=finding.severity.color)
    titulo.append(f"  {finding.title}", style="bold")
    if finding.kind is not None:
        titulo.append(f"  · {finding.kind.label}", style="dim")
    console.print(titulo)

    lineas: list[Text] = []
    if finding.description:
        lineas.append(Text(finding.description))
    if finding.evidence:
        lineas.append(Text(f"→ {finding.evidence}", style="dim italic"))
    if finding.remediation:
        lineas.append(Text(f"Solución: {finding.remediation}", style="green"))

    for linea in lineas:
        # Padding deja que rich ajuste el salto de línea al ancho ya reducido,
        # en vez de partir el texto y perder la sangría.
        console.print(Padding(linea, (0, 0, 0, _SANGRIA)))


def _summary_table(result: ScanResult, verbose: bool) -> Table:
    tabla = Table(show_header=False, box=None, padding=(0, 2, 0, 2))
    for severity in Severity:
        if severity in _RUIDO and not verbose:
            continue
        n = result.count(severity)
        if n:
            tabla.add_row(Text(severity.label, style=severity.color), str(n))
    if not tabla.row_count:
        tabla.add_row(Text("Sin hallazgos", style="green"), "")
    return tabla


def render_json(result: ScanResult, indent: int = 2) -> str:
    """Resultado como JSON, con la nota y el recuento ya calculados."""
    data = result.model_dump(mode="json")
    data["status"] = result.status.value
    data["score"] = result.score
    data["grade"] = result.grade
    data["score_upper_bound"] = result.score_upper_bound
    data["coverage"] = result.coverage()
    data["summary"] = {s.value: result.count(s) for s in Severity if result.count(s)}
    return json.dumps(data, indent=indent, ensure_ascii=False)


def render_html(result: ScanResult, verbose: bool = False) -> str:
    """Informe autocontenido en HTML, sin dependencias externas."""
    from .workbench import render_workbench

    return render_workbench([result], result.target, result.module_name, verbose=verbose)
