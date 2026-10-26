"""Rastreo HTML sin JavaScript ni envío de formularios, limitado al origen y ruta base."""

from __future__ import annotations

import time
from collections import deque
from html.parser import HTMLParser
from urllib.parse import parse_qs, unquote, urljoin, urlsplit, urlunsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .. import __version__
from ..core.finding import Finding, ScanOutput, Severity
from ..core.module import Category, Coverage, ScanModule
from .web_paths import WebPathsInput


class CrawlInput(BaseModel):
    model_config = ConfigDict(allow_inf_nan=False)
    url: str = Field(description="URL base; se respeta el origen y su prefijo de ruta.")
    max_pages: int = Field(default=25, ge=1, le=100, description="Máximo de peticiones HTTP.")
    max_depth: int = Field(default=2, ge=0, le=5, description="Profundidad máxima de enlaces.")
    timeout: float = Field(default=5, gt=0, le=30, description="Presupuesto por petición.")
    rate: float = Field(default=2, gt=0, le=10, description="Máximo de peticiones por segundo.")
    total_timeout: float = Field(default=60, gt=0, le=600, description="Duración máxima total.")

    @field_validator("url")
    @classmethod
    def valid_url(cls, value):
        return WebPathsInput(url=value).url


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.forms = []
        self.current = None

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if len(self.links) < 1000:
            link = values.get("href") if tag in {"a", "link"} else values.get("src")
            if link:
                self.links.append((tag, link))
        if tag == "form" and len(self.forms) < 50:
            self.current = {
                "action": values.get("action") or "",
                "method": (values.get("method") or "GET").upper(),
                "fields": set(),
            }
            self.forms.append(self.current)
        if (
            tag in {"input", "select", "textarea"}
            and self.current
            and values.get("name")
            and len(self.current["fields"]) < 100
        ):
            self.current["fields"].add(values["name"][:100])

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None


def scoped_url(base: str, current: str, link: str) -> str | None:
    if any(ord(c) < 32 for c in link) or "\\" in link:
        return None
    try:
        target = urlsplit(urljoin(current, link))
        scope = urlsplit(base)
        if target.scheme not in {"http", "https"} or target.username or target.password:
            return None
        if (
            target.scheme,
            target.hostname,
            target.port or (443 if target.scheme == "https" else 80),
        ) != (scope.scheme, scope.hostname, scope.port or (443 if scope.scheme == "https" else 80)):
            return None
        path = unquote(target.path)
        if any(p in {".", ".."} for p in path.split("/")) or not path.startswith(scope.path):
            return None
        if any(
            p.lower() in {"logout", "delete", "remove", "unsubscribe", "reset"}
            for p in path.split("/")
        ):
            return None
        return urlunsplit((target.scheme, target.netloc, target.path or "/", "", ""))
    except ValueError:
        return None


class WebCrawlModule(ScanModule):
    id = "web-crawl"
    name = "Rastreador de superficie web"
    description = "Descubre páginas, recursos, parámetros y formularios sin enviarlos."
    category = Category.WEB
    InputModel = CrawlInput
    show_info = True

    def run(self, inputs: CrawlInput) -> ScanOutput:
        cov, findings = Coverage(), []
        pending = deque([(inputs.url, 0)])
        queued = {inputs.url}
        deadline = time.monotonic() + inputs.total_timeout
        next_request = 0.0
        requests = 0
        with httpx.Client(
            follow_redirects=False,
            trust_env=False,
            headers={"User-Agent": f"Atalaya/{__version__}", "Accept-Encoding": "identity"},
        ) as client:
            while pending and requests < inputs.max_pages and time.monotonic() < deadline:
                delay = max(0, next_request - time.monotonic())
                if time.monotonic() + delay >= deadline:
                    break
                if delay:
                    time.sleep(delay)
                url, depth = pending.popleft()
                next_request = time.monotonic() + 1 / inputs.rate
                requests += 1
                try:
                    body = bytearray()
                    with client.stream(
                        "GET",
                        url,
                        timeout=min(inputs.timeout, max(0.001, deadline - time.monotonic())),
                    ) as response:
                        for chunk in response.iter_bytes(chunk_size=4096):
                            body.extend(chunk[: 131072 - len(body)])
                            if len(body) >= 131072 or time.monotonic() >= deadline:
                                break
                        status = response.status_code
                        content_type = response.headers.get("content-type", "").lower()
                        location = response.headers.get("location")
                    if status >= 500 or status == 429:
                        cov.undetermined(url, url, f"HTTP {status}")
                        if status in {429, 503}:
                            pending.appendleft((url, depth))
                            break
                        continue
                    cov.done(url, url, f"HTTP {status}")
                    findings.append(
                        Finding(
                            severity=Severity.INFO,
                            rule_id="crawl.page",
                            location=url,
                            title=f"Recurso web: {url}",
                            evidence=f"HTTP {status}; profundidad {depth}",
                        )
                    )
                    links = []
                    if location and 300 <= status < 400:
                        links.append(("a", location))
                    if "text/html" in content_type and status == 200:
                        parser = PageParser()
                        parser.feed(body.decode(response.encoding or "utf-8", errors="replace"))
                        links.extend(parser.links)
                        if len(body) >= 131072:
                            cov.undetermined(
                                f"body:{url}", "Lectura HTML", "Muestra limitada a 128 KiB"
                            )
                        for index, form in enumerate(parser.forms):
                            action = scoped_url(inputs.url, url, form["action"])
                            if action:
                                findings.append(
                                    Finding(
                                        severity=Severity.INFO,
                                        rule_id="crawl.form",
                                        location=f"{url}#form-{index}",
                                        title=f"Formulario {form['method']}: {action}",
                                        evidence="Campos: " + ", ".join(sorted(form["fields"])),
                                        description="Solo nombres de campos; sin valores "
                                        "ni envío del formulario.",
                                    )
                                )
                    for tag, link in links:
                        normalized = scoped_url(inputs.url, url, link)
                        if not normalized:
                            continue
                        params = sorted(
                            parse_qs(urlsplit(urljoin(url, link)).query, keep_blank_values=True)
                        )
                        if params:
                            findings.append(
                                Finding(
                                    severity=Severity.INFO,
                                    rule_id="crawl.parameters",
                                    location=normalized,
                                    title=f"Parámetros descubiertos: {normalized}",
                                    evidence=", ".join(p[:100] for p in params[:50]),
                                )
                            )
                        if tag in {"script", "iframe"}:
                            findings.append(
                                Finding(
                                    severity=Severity.INFO,
                                    rule_id="crawl.endpoint",
                                    location=normalized,
                                    title=f"Referencia {tag}: {normalized}",
                                    description="Referencia HTML descubierta; no se ejecuta "
                                    "ni interpreta JavaScript.",
                                )
                            )
                        if tag == "a" and depth < inputs.max_depth and normalized not in queued:
                            if len(queued) < 500:
                                queued.add(normalized)
                                pending.append((normalized, depth + 1))
                            else:
                                cov.undetermined(
                                    "frontier", "Enlaces pendientes", "Cola limitada a 500 URLs"
                                )
                except httpx.HTTPError as exc:
                    cov.undetermined(url, url, type(exc).__name__)
        if pending:
            cov.undetermined(
                "budget", "Rastreo pendiente", f"{len(pending)} URL(s) fuera del presupuesto"
            )
        if not cov.checks:
            cov.undetermined("crawl", "Rastreo web", "No se pudo iniciar ninguna petición")
        # Una misma URL puede estar enlazada varias veces con valores de query diferentes.
        unique = {(f.rule_id, f.location, f.evidence): f for f in findings}
        return cov.output(
            list(unique.values()),
            {
                "Alcance": inputs.url,
                "Máximo de páginas": str(inputs.max_pages),
                "Profundidad máxima": str(inputs.max_depth),
                "Frecuencia": f"{inputs.rate:g} req/s",
            },
        )
