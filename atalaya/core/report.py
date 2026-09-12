"""Renderizado de resultados: terminal, JSON y HTML.

Como todos los módulos devuelven `Finding`, estos tres renderizadores valen
para cualquier herramienta presente y futura.
"""

from __future__ import annotations

import json
from html import escape

from rich.console import Console, Group
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .finding import Finding, ScanResult, Severity

# Las que se enseñan siempre; OK e INFO solo en modo detallado.
_RUIDO = {Severity.OK, Severity.INFO}


def _grade_style(grade: str) -> str:
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

    nota = Text(f" {result.grade} ", style=_grade_style(result.grade))
    nota.append(f"  {result.score}/100", style="bold")

    console.print()
    console.print(Panel(Group(cabecera, Text(), nota), border_style="blue"))

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

    mostrados = [f for f in result.by_severity() if verbose or f.severity not in _RUIDO]
    if not mostrados:
        console.print("  [green]Sin hallazgos que reportar.[/green]")
    for finding in mostrados:
        _print_finding(finding, console)

    console.print()
    console.print(_summary_table(result, verbose))
    console.print(f"[dim]Completado en {result.duration_seconds}s[/dim]")


# Ancho de la columna de gravedad más su separación: el cuerpo del hallazgo se
# sangra otro tanto para que las líneas partidas queden alineadas.
_SANGRIA = 10


def _print_finding(finding: Finding, console: Console) -> None:
    titulo = Text()
    titulo.append(f"{finding.severity.label:>8}", style=finding.severity.color)
    titulo.append(f"  {finding.title}", style="bold")
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
    data["score"] = result.score
    data["grade"] = result.grade
    data["summary"] = {s.value: result.count(s) for s in Severity if result.count(s)}
    return json.dumps(data, indent=indent, ensure_ascii=False)


_HTML_COLORS = {
    Severity.CRITICAL: "#b91c1c",
    Severity.HIGH: "#ea580c",
    Severity.MEDIUM: "#ca8a04",
    Severity.LOW: "#0891b2",
    Severity.INFO: "#64748b",
    Severity.OK: "#15803d",
}

_HTML_STYLES = """
  :root { color-scheme: light dark; }
  body { font: 15px/1.6 system-ui, sans-serif; max-width: 860px; margin: 0 auto;
         padding: 2rem 1.25rem; background: #fafafa; color: #18181b; }
  header { border-bottom: 2px solid #e4e4e7; padding-bottom: 1rem; margin-bottom: 2rem; }
  h1 { font-size: 1.4rem; margin: 0 0 .25rem; }
  .target { color: #3b82f6; font-family: ui-monospace, monospace; }
  .meta { color: #71717a; font-size: .85rem; margin-top: .5rem; }
  .grade { display: inline-block; font-size: 2rem; font-weight: 700; padding: .3rem 1rem;
           border-radius: .5rem; color: #fff; margin-top: 1rem; }
  .score { font-size: 1rem; color: #71717a; margin-left: .75rem; }
  .finding { background: #fff; border: 1px solid #e4e4e7; border-left-width: 4px;
             border-radius: .4rem; padding: 1rem 1.25rem; margin-bottom: 1rem; }
  .finding h3 { font-size: 1rem; margin: .5rem 0; }
  .sev { display: inline-block; color: #fff; font-size: .7rem; font-weight: 700;
         letter-spacing: .05em; padding: .15rem .5rem; border-radius: .25rem; }
  pre { background: #f4f4f5; padding: .6rem .8rem; border-radius: .3rem;
        overflow-x: auto; font-size: .8rem; margin: .5rem 0; }
  .fix { color: #15803d; }
  .refs { font-size: .8rem; }
  .error { background: #fef2f2; border: 1px solid #fecaca; color: #b91c1c;
           padding: 1rem; border-radius: .4rem; margin-bottom: 1.5rem; }
  footer { margin-top: 2.5rem; color: #a1a1aa; font-size: .8rem;
           border-top: 1px solid #e4e4e7; padding-top: 1rem; }
  @media (prefers-color-scheme: dark) {
    body { background: #18181b; color: #e4e4e7; }
    .finding { background: #27272a; border-color: #3f3f46; }
    pre { background: #18181b; }
    header, footer { border-color: #3f3f46; }
  }
"""


def _grade_color(score: int) -> str:
    if score >= 90:
        return "#15803d"
    if score >= 80:
        return "#4d7c0f"
    if score >= 65:
        return "#ca8a04"
    if score >= 50:
        return "#ea580c"
    return "#b91c1c"


def render_html(result: ScanResult, verbose: bool = False) -> str:
    """Informe autocontenido en HTML, sin dependencias externas."""
    mostrados = [f for f in result.by_severity() if verbose or f.severity not in _RUIDO]

    bloques = []
    for f in mostrados:
        color = _HTML_COLORS[f.severity]
        partes = [
            f'<div class="finding" style="border-left-color:{color}">',
            f'<span class="sev" style="background:{color}">{escape(f.severity.label)}</span>',
            f"<h3>{escape(f.title)}</h3>",
        ]
        if f.description:
            partes.append(f"<p>{escape(f.description)}</p>")
        if f.evidence:
            partes.append(f"<pre>{escape(f.evidence)}</pre>")
        if f.remediation:
            partes.append(f'<p class="fix"><b>Solución:</b> {escape(f.remediation)}</p>')
        if f.references:
            enlaces = " · ".join(
                f'<a href="{escape(r)}" rel="noopener noreferrer" target="_blank">{escape(r)}</a>'
                for r in f.references
            )
            partes.append(f'<p class="refs">{enlaces}</p>')
        partes.append("</div>")
        bloques.append("\n".join(partes))

    meta = " · ".join(f"{escape(k)}: {escape(v)}" for k, v in result.metadata.items())
    error = f'<div class="error">{escape(result.error)}</div>' if result.error else ""
    cuerpo = "\n".join(bloques) or "<p>Sin hallazgos que reportar.</p>"
    generado = result.started_at.strftime("%Y-%m-%d %H:%M UTC")
    color_nota = _grade_color(result.score)

    return f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Atalaya · {escape(result.target)}</title>
<style>{_HTML_STYLES}</style>
</head>
<body>
<header>
  <h1>{escape(result.module_name)}</h1>
  <div class="target">{escape(result.target)}</div>
  <div class="meta">{meta}</div>
  <div>
    <span class="grade" style="background:{color_nota}">{escape(result.grade)}</span>
    <span class="score">{result.score}/100</span>
  </div>
</header>
{error}
{cuerpo}
<footer>Generado por Atalaya · {generado} · {result.duration_seconds}s</footer>
</body>
</html>"""
