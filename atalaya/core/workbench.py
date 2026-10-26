"""Informes offline con navegación, filtros y los mismos estados del modelo de resultados."""

from __future__ import annotations

from html import escape
from importlib.resources import files
from urllib.parse import urlsplit

from .finding import EvaluationStatus, ScanResult, Severity


def _asset(name):
    return files("atalaya.services.static").joinpath(name).read_text(encoding="utf-8")


def _finding_html(finding, module_id, index):
    severity = finding.severity.value
    body = f"<p>{escape(finding.description)}</p>" if finding.description else ""
    if finding.evidence:
        body += f"<pre>{escape(finding.evidence)}</pre>"
    if finding.remediation:
        body += (
            '<div class="remediation"><b>Cómo corregirlo</b>'
            f"<p>{escape(finding.remediation)}</p></div>"
        )
    links = [r for r in finding.references if urlsplit(r).scheme in {"http", "https"}]
    if links:
        body += (
            '<p class="references">'
            + " · ".join(
                f'<a href="{escape(r, quote=True)}" rel="noopener noreferrer" '
                f'target="_blank">Referencia {i + 1}</a>'
                for i, r in enumerate(links)
            )
            + "</p>"
        )
    kind = f'<span class="kind">{escape(finding.kind.label)}</span>' if finding.kind else ""
    opened = " open" if finding.severity.weight >= Severity.MEDIUM.weight else ""
    return (
        f'<details class="finding" data-severity="{severity}" data-module="{escape(module_id)}"'
        f' id="finding-{index}"{opened}>'
        f'<summary><span class="severity {severity}">{finding.severity.label}</span>'
        f'<span class="finding-title">{escape(finding.title)}</span>{kind}</summary>'
        f'<div class="finding-body">{body}</div></details>'
    )


def render_workbench(
    results: list[ScanResult],
    target: str,
    title: str,
    comparison: dict | None = None,
    run_id: str = "",
    verbose: bool = True,
) -> str:
    sections, navigation, options = [], [], []
    total_findings = 0
    for index, result in enumerate(results):
        c = result.coverage()
        shown = [
            f
            for f in result.by_severity()
            if verbose or f.severity not in {Severity.INFO, Severity.OK}
        ]
        count = sum(f.severity not in {Severity.INFO, Severity.OK} for f in result.findings)
        navigation.append(
            f'<a href="#module-{index}"><span>{escape(result.module_name)}</span><b>{count}</b></a>'
        )
        options.append(
            f'<option value="{escape(result.module_id)}">{escape(result.module_name)}</option>'
        )
        complete = result.status is EvaluationStatus.COMPLETE
        score = (
            f'<strong class="grade">{result.grade}</strong><span>{result.score}/100</span>'
            if complete
            else (
                "<strong>Sin nota</strong><span>"
                + (
                    f"como máximo {result.score_upper_bound}/100"
                    if result.score_upper_bound is not None
                    else "no se llegó a comprobar nada"
                )
                + "</span>"
            )
        )
        pending = [check for check in result.checks if check.status.value != "done"]
        pending_html = ""
        if pending:
            pending_html = (
                '<details class="coverage-detail"><summary>'
                "Ver comprobaciones omitidas o sin determinar</summary><ul>"
                + "".join(
                    f"<li><b>{escape(check.name)}</b> · {check.status.label}"
                    f"{': ' + escape(check.detail) if check.detail else ''}</li>"
                    for check in pending
                )
                + "</ul></details>"
            )
        cards = []
        for finding in shown:
            cards.append(_finding_html(finding, result.module_id, total_findings))
            total_findings += 1
        error = f'<p class="error">{escape(result.error)}</p>' if result.error else ""
        metadata = (
            '<dl class="module-metadata">'
            + "".join(
                f"<div><dt>{escape(key)}</dt><dd>{escape(value)}</dd></div>"
                for key, value in result.metadata.items()
            )
            + "</dl>"
            if result.metadata
            else ""
        )
        sections.append(
            f'<section class="module" id="module-{index}"><header class="module-header">'
            f'<div><p class="module-id">{escape(result.module_id)}</p>'
            f"<h2>{escape(result.module_name)}</h2>"
            f'<p class="module-target">{escape(result.target)}</p></div>'
            f'<div class="module-score">{score}</div></header>'
            f'<div class="module-state {result.status.value}">{result.status.label} · '
            f"Cobertura: {c['done']} de {c['total']} comprobaciones concluidas · "
            f"{result.duration_seconds:g} s</div>"
            + error
            + metadata
            + pending_html
            + "".join(cards)
            + ('<p class="empty-module">Sin hallazgos que reportar.</p>' if not cards else "")
            + "</section>"
        )
    all_checks = [check for r in results for check in r.checks]
    done = sum(check.status.value == "done" for check in all_checks)
    high = sum(
        f.severity in {Severity.HIGH, Severity.CRITICAL} for r in results for f in r.findings
    )
    issues = sum(f.severity.weight > 0 for r in results for f in r.findings)
    status = (
        "Análisis completo"
        if results and all(r.status is EvaluationStatus.COMPLETE for r in results)
        else "Análisis incompleto"
    )
    if results and all(r.status is EvaluationStatus.NOT_EVALUATED for r in results):
        status = "No evaluado"
    comparison_html = ""
    if comparison:
        labels = {
            "new": "Nuevos",
            "resolved": "Resueltos",
            "changed": "Cambiados",
            "unverified": "Sin verificar",
            "unchanged": "Sin cambios",
        }
        items = []
        for key, values in comparison.items():
            rows = "".join(
                f"<li>{escape(v['module_id'])} · {escape(v['finding']['title'])}</li>"
                for v in values
            )
            items.append(
                f"<details><summary>{labels[key]} <b>{len(values)}</b></summary>"
                f"<ul>{rows}</ul></details>"
            )
        comparison_html = (
            '<section class="evolution"><h2>Evolución desde la última auditoría</h2><div>'
            + "".join(items)
            + "</div></section>"
        )
    date = results[0].started_at.strftime("%d/%m/%Y · %H:%M UTC") if results else ""
    return f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Atalaya · {escape(target)}</title>
<style>{_asset("report.css")}</style>
</head>
<body>
<a class="skip" href="#content">Ir al informe</a>
<aside class="sidebar">
<a class="brand" href="#content">ATALAYA<span>Consola de seguridad</span>
</a>
<p class="nav-label">MÓDULOS DEL INFORME</p>
<nav aria-label="Módulos">{"".join(navigation)}</nav>
<div class="rail-note">Informe autocontenido<br>Sin consultas externas</div>
</aside>
<main id="content">
<div class="topbar">
<span>Informe de seguridad · {date}</span>
<div>
<button id="theme" type="button">Cambiar tema</button>
<button id="print" type="button">Imprimir / PDF</button>
</div>
</div>
<header class="report-heading">
<p class="eyebrow">ATALAYA / RESULTADOS</p>
<h1>{escape(title)}</h1>
<p class="target">{escape(target)}</p>
<p class="run-id">{escape(run_id)}</p>
<span class="state">{status}</span>
</header>
<section class="metrics" aria-label="Resumen">
<article>
<span>Hallazgos a revisar</span>
<strong>{issues}</strong>
</article>
<article>
<span>Altos y críticos</span>
<strong>{high}</strong>
</article>
<article>
<span>Comprobaciones concluidas</span>
<strong>{done}<small>/{len(all_checks)}</small>
</strong>
</article>
<article>
<span>Módulos ejecutados</span>
<strong>{len(results)}</strong>
</article>
</section>
<p class="scope-note">La nota describe lo comprobado.
Un análisis incompleto no recibe nota final.</p>
{comparison_html}
<form class="filters" role="search">
<label>Buscar<input id="search" type="search" placeholder="Título, evidencia o solución…">
</label>
<label>Gravedad<select id="severity">
<option value="">Todas</option>
<option value="critical">Crítico</option>
<option value="high">Alto</option>
<option value="medium">Medio</option>
<option value="low">Bajo</option>
<option value="info">Informativo</option>
<option value="ok">Correcto</option>
</select>
</label>
<label>Módulo<select id="module">
<option value="">Todos los módulos</option>{"".join(options)}</select>
</label>
<span id="visible-count" role="status">{total_findings} resultados</span>
</form>
<p id="filter-empty" hidden>No hay resultados con estos filtros.</p>
{"".join(sections)}<footer>Atalaya · Informe local ·
Las comprobaciones sin determinar requieren revisión.</footer>
</main>
<script>{_asset("report.js")}</script>
</body>
</html>"""
