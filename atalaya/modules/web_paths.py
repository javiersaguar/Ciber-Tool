"""Descubrimiento acotado de rutas web, sin seguir redirecciones ni guardar cuerpos."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit, urlunsplit
from uuid import uuid4

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .. import __version__
from ..core.finding import Finding, ScanOutput, Severity
from ..core.module import Category, Coverage, ScanModule

DEFAULT_PATHS = (
    "robots.txt",
    "sitemap.xml",
    "admin/",
    "login",
    "api/",
    "docs/",
    "swagger/",
    "swagger.json",
    "openapi.json",
    ".git/HEAD",
    ".env",
    "backup.zip",
)
MAX_BODY = 32768


def clean_path(value: str) -> str:
    value = unquote(value.strip()).lstrip("/")
    if not value or len(value) > 512 or any(c in value for c in "\\?#:%"):
        raise ValueError("Las rutas deben ser relativas y no contener URL, query ni fragmento.")
    if any(p in {".", ".."} for p in value.split("/")) or any(ord(c) < 32 for c in value):
        raise ValueError("Las rutas no pueden contener traversal ni caracteres de control.")
    return quote(value, safe="/-._~")


class WebPathsInput(BaseModel):
    model_config = ConfigDict(allow_inf_nan=False)

    url: str = Field(description="URL base HTTP/HTTPS; sin esquema se asume HTTPS.")
    wordlist: Path | None = Field(default=None, description="Archivo UTF-8, una ruta por línea.")
    timeout: float = Field(default=5, gt=0, le=30, description="Espera máxima por petición.")
    concurrency: int = Field(default=4, ge=1, le=16, description="Peticiones simultáneas máximas.")
    rate: float = Field(default=5, gt=0, le=20, description="Máximo de peticiones por segundo.")
    total_timeout: float = Field(default=60, gt=0, le=600, description="Duración máxima total.")

    @field_validator("url")
    @classmethod
    def valid_url(cls, value: str) -> str:
        parsed = urlsplit(value if "://" in value else "https://" + value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Indica una URL HTTP o HTTPS válida.")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("La URL base no debe incluir credenciales, query ni fragmento.")
        _ = parsed.port  # Validar también el puerto.
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/") + "/", "", ""))


@dataclass
class Probe:
    path: str
    status: int
    body: bytes
    location: str

    def fingerprint(self) -> tuple:
        # Normalizar páginas 404 que reflejan la ruta solicitada.
        body = self.body.replace(self.path.encode(), b"<path>")
        location = self.location.replace(self.path, "<path>")
        return self.status, location, hashlib.sha256(body).digest()


class WebPathsModule(ScanModule):
    id = "web-paths"
    name = "Descubridor de rutas web"
    description = "Busca rutas web y exposiciones de configuración con un diccionario acotado."
    category = Category.WEB
    InputModel = WebPathsInput
    show_info = True

    def run(self, inputs: WebPathsInput) -> ScanOutput:
        paths = list(DEFAULT_PATHS)
        if inputs.wordlist:
            with inputs.wordlist.open("rb") as source:
                raw = source.read(65537)
            if len(raw) > 65536:
                raise ValueError("El diccionario no puede superar 64 KiB.")
            paths = [
                clean_path(s)
                for s in raw.decode("utf-8-sig").splitlines()
                if s.strip() and not s.lstrip().startswith("#")
            ]
        paths = list(dict.fromkeys(paths))
        if not 1 <= len(paths) <= 256:
            raise ValueError("El diccionario debe contener entre 1 y 256 rutas únicas.")
        return asyncio.run(self._scan(inputs, paths))

    async def _request(self, client: httpx.AsyncClient, url: str, path: str) -> Probe:
        async with client.stream("GET", url + path) as response:
            body = bytearray()
            async for chunk in response.aiter_bytes(chunk_size=4096):
                body.extend(chunk[: MAX_BODY - len(body)])
                if len(body) >= MAX_BODY:
                    break
            return Probe(
                path, response.status_code, bytes(body), response.headers.get("location", "")
            )

    async def _scan(self, inputs: WebPathsInput, paths: list[str]) -> ScanOutput:
        responses: list[Probe] = []
        controls: list[Probe] = []
        failed = 0
        blocked = False
        lock = asyncio.Lock()
        next_request = 0.0

        async def request(path):
            nonlocal next_request, blocked
            async with lock:
                loop = asyncio.get_running_loop()
                await asyncio.sleep(max(0, next_request - loop.time()))
                if blocked:
                    return None
                next_request = loop.time() + 1 / inputs.rate
            response = await asyncio.wait_for(
                self._request(client, inputs.url, path), inputs.timeout
            )
            if response.status in {429, 503}:
                blocked = True
            return response

        async def execute():
            nonlocal failed
            for _ in range(2):
                control = await request("atalaya-not-found-" + uuid4().hex)
                if control is None or blocked:
                    return
                controls.append(control)
            pending = iter(paths)

            async def worker():
                nonlocal failed
                for path in pending:
                    if blocked:
                        break
                    try:
                        response = await request(path)
                        if response is not None:
                            responses.append(response)
                    except (httpx.HTTPError, asyncio.TimeoutError):
                        failed += 1

            await asyncio.gather(*(worker() for _ in range(min(inputs.concurrency, len(paths)))))

        async with httpx.AsyncClient(
            timeout=inputs.timeout,
            follow_redirects=False,
            trust_env=False,
            limits=httpx.Limits(max_connections=inputs.concurrency),
            headers={"User-Agent": f"Atalaya/{__version__}", "Accept-Encoding": "identity"},
        ) as client:
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(execute(), inputs.total_timeout)
        if not responses and not blocked:
            raise RuntimeError("No se pudo completar ninguna petición de descubrimiento.")
        baselines = {c.fingerprint() for c in controls}
        findings = []
        omitted = 0
        for response in sorted(responses, key=lambda r: r.path):
            if response.status in {404, 410} or response.fingerprint() in baselines:
                omitted += 1
                continue
            if response.status not in {200, 201, 204, 301, 302, 303, 307, 308, 401, 403}:
                continue
            findings.append(self._finding(response))
        findings.append(
            Finding(
                severity=Severity.INFO,
                title="Alcance del descubrimiento web",
                description="Las respuestas de rutas son candidatos para revisión manual. "
                "No se siguen redirecciones ni se incluyen cuerpos o cookies en el informe.",
                evidence=f"Rutas: {len(paths)}; respuestas: {len(responses)}; errores: {failed}; "
                f"no probadas: {len(paths) - len(responses) - failed}; "
                f"404/similares omitidas: {omitted}; controles: {len(controls)}; "
                f"interrumpido por 429/503: {blocked}",
            )
        )
        cov = Coverage()
        received = {r.path: r for r in responses}
        for path in paths:
            response = received.get(path)
            if response is None or response.status >= 500 or response.status == 429:
                cov.undetermined(
                    path, f"Ruta /{path}", "Sin respuesta concluyente o límite alcanzado"
                )
            else:
                cov.done(path, f"Ruta /{path}", f"HTTP {response.status}")
        if len(controls) != 2:
            cov.undetermined("wildcard", "Control de páginas comodín", "Control incompleto")
        else:
            cov.done("wildcard", "Control de páginas comodín")
        return cov.output(findings)

    def _finding(self, response: Probe) -> Finding:
        severity = Severity.INFO
        title = f"Ruta candidata: /{response.path} (HTTP {response.status})"
        remediation = "Verifica su finalidad y exige autenticación si el recurso es privado."
        if response.status == 200:
            if response.path.endswith(".git/HEAD") and re.match(
                rb"ref: refs/heads/[^\r\n]+\s*$|[a-f0-9]{40}\s*$", response.body
            ):
                severity = Severity.HIGH
                title = "Metadatos Git accesibles por HTTP"
                remediation = "Bloquea el acceso web al directorio .git y retíralo del despliegue."
            elif (
                response.path.endswith(".env")
                and len(re.findall(rb"(?m)^[A-Za-z_][A-Za-z0-9_]*\s*=\s*[^\r\n]+", response.body))
                >= 2
                and b"<html" not in response.body.lower()
            ):
                severity = Severity.HIGH
                title = "Posible archivo de entorno expuesto"
                remediation = "Retira el archivo del acceso público y revisa/rota sus credenciales."
        return Finding(
            severity=severity,
            rule_id="web.exposed-config" if severity is Severity.HIGH else "web.path",
            location=response.path,
            title=title,
            description="Detectado por estado y firma de contenido; confirma el resultado."
            if severity is Severity.HIGH
            else "La respuesta no demuestra una vulnerabilidad ni garantiza que la ruta exista.",
            evidence=f"Ruta relativa: /{response.path}; HTTP {response.status}; "
            f"muestra leída: {len(response.body)} bytes (máximo {MAX_BODY})",
            remediation=remediation,
        )
