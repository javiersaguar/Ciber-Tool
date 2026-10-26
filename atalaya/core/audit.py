"""Auditorías compuestas y comparación por identidad, sin mezclar sus puntuaciones."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, Field

from .finding import EvaluationStatus, Finding, ScanResult, Severity

AUDIT_MODULES = {
    "http-headers",
    "tls",
    "tcp-ports",
    "services",
    "subdomains",
    "web-paths",
    "web-crawl",
}
DEFAULT_AUDIT = "http-headers,tls,tcp-ports,services,web-paths,web-crawl"


class AuditRun(BaseModel):
    schema_version: int = 1
    id: str = Field(default_factory=lambda: uuid4().hex)
    target: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    configuration: dict = Field(default_factory=dict)
    results: list[ScanResult] = Field(default_factory=list)
    comparison: dict[str, list[dict]] = Field(default_factory=dict)
    previous_id: str | None = None

    @property
    def status(self) -> EvaluationStatus:
        if not self.results or all(
            r.status is EvaluationStatus.NOT_EVALUATED for r in self.results
        ):
            return EvaluationStatus.NOT_EVALUATED
        if any(r.status is not EvaluationStatus.COMPLETE for r in self.results):
            return EvaluationStatus.INCOMPLETE
        return EvaluationStatus.COMPLETE


def finding_identity(module_id: str, finding: Finding) -> str:
    parts = [module_id, finding.rule_id or finding.title, finding.location or ""]
    return hashlib.sha256(json.dumps(parts, ensure_ascii=True).encode()).hexdigest()[:24]


def observations(run: AuditRun) -> dict[str, dict]:
    # Conservar los positivos anteriores que una ejecución incompleta no pudo verificar.
    result = {v["id"]: v for v in run.comparison.get("unverified", [])}
    for module in run.results:
        for finding in module.findings:
            if finding.severity is Severity.OK:
                continue
            identity = finding_identity(module.module_id, finding)
            result[identity] = {
                "id": identity,
                "module_id": module.module_id,
                "finding": finding.model_dump(mode="json"),
            }
    return result


def compare_runs(previous: AuditRun, current: AuditRun) -> dict[str, list[dict]]:
    if previous.target != current.target or previous.configuration != current.configuration:
        raise ValueError("Solo se comparan auditorías del mismo objetivo y configuración.")
    old, new = observations(previous), observations(current)
    complete = {r.module_id for r in current.results if r.status is EvaluationStatus.COMPLETE}
    diff = {k: [] for k in ("new", "resolved", "changed", "unverified", "unchanged")}
    for key, value in new.items():
        if key not in old:
            diff["new"].append(value)
        else:
            before, after = old[key]["finding"], value["finding"]
            changed = any(before.get(k) != after.get(k) for k in ("severity", "kind", "attributes"))
            diff["changed" if changed else "unchanged"].append(value)
    for key in old.keys() - new.keys():
        value = old[key]
        diff["resolved" if value["module_id"] in complete else "unverified"].append(value)
    return diff


class HistoryStore:
    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self.path = self.directory / "history.sqlite3"

    def _connect(self):
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not self.path.exists():
            # Crear con permisos privados desde el primer byte en sistemas POSIX.
            import os

            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                pass  # Otra auditoría pudo crear la base entre exists() y open().
            else:
                os.close(fd)
        db = sqlite3.connect(self.path, timeout=5)
        db.execute(
            "CREATE TABLE IF NOT EXISTS audits (id TEXT PRIMARY KEY, target TEXT, "
            "configuration TEXT, started_at TEXT, payload TEXT)"
        )
        return db

    @staticmethod
    def _configuration(run):
        return json.dumps(run.configuration, sort_keys=True, ensure_ascii=True)

    def save(self, run: AuditRun) -> None:
        db = self._connect()
        try:
            with db:
                db.execute(
                    "INSERT INTO audits VALUES (?, ?, ?, ?, ?)",
                    (
                        run.id,
                        run.target,
                        self._configuration(run),
                        run.started_at.isoformat(),
                        run.model_dump_json(),
                    ),
                )
        finally:
            db.close()

    def latest(self, run: AuditRun) -> AuditRun | None:
        if not self.path.exists():
            return None
        db = self._connect()
        try:
            row = db.execute(
                "SELECT payload FROM audits WHERE target=? AND configuration=? "
                "ORDER BY started_at DESC, rowid DESC LIMIT 1",
                (run.target, self._configuration(run)),
            ).fetchone()
            return AuditRun.model_validate_json(row[0]) if row else None
        finally:
            db.close()

    def list(self, limit: int = 20) -> list[AuditRun]:
        if not self.path.exists():
            return []
        db = self._connect()
        try:
            rows = db.execute(
                "SELECT payload FROM audits ORDER BY started_at DESC, rowid DESC LIMIT ?",
                (max(1, min(limit, 100)),),
            ).fetchall()
            return [AuditRun.model_validate_json(row[0]) for row in rows]
        finally:
            db.close()

    def get(self, identifier: str) -> AuditRun:
        if not self.path.exists():
            raise ValueError("El historial está vacío.")
        db = self._connect()
        try:
            row = db.execute("SELECT payload FROM audits WHERE id=?", (identifier,)).fetchone()
            if not row:
                raise ValueError("No existe una auditoría con ese identificador.")
            return AuditRun.model_validate_json(row[0])
        finally:
            db.close()


def run_audit(
    target: str,
    modules: str = DEFAULT_AUDIT,
    ports: str = "22,80,443,8080,8443",
    timeout: float = 3,
    on_module: Callable[[str], None] | None = None,
) -> AuditRun:
    from urllib.parse import urlsplit

    from ..modules.web_paths import WebPathsInput
    from .registry import get_registry

    url = WebPathsInput(url=target).url
    parsed = urlsplit(url)
    names = list(dict.fromkeys(s.strip() for s in modules.split(",") if s.strip()))
    if not names or set(names) - AUDIT_MODULES:
        raise ValueError("Módulos válidos: " + ", ".join(sorted(AUDIT_MODULES)))
    if parsed.scheme == "http" and "tls" in names:
        names.remove("tls")  # No tratar el puerto HTTP explícito como si hablara TLS.
    if not names:
        raise ValueError("No hay módulos aplicables al objetivo; TLS requiere HTTPS.")
    plan = []
    for name in names:
        module = get_registry().get(name)
        values = {"timeout": timeout}
        if name in {"tcp-ports", "services"}:
            values.update(host=parsed.hostname, ports=ports)
            if name == "services" and parsed.port:
                field = "tls_ports" if parsed.scheme == "https" else "http_ports"
                values[field] = str(parsed.port)
        elif name == "tls":
            values.update(host=parsed.hostname, port=parsed.port or 443)
        elif name == "subdomains":
            values.update(domain=parsed.hostname)
        else:
            values.update(url=url)
        plan.append((module, module.parse_inputs(**values)))
    run = AuditRun(
        target=url,
        configuration={
            "modules": [module.id for module, _ in plan],
            "inputs": {module.id: inputs.model_dump(mode="json") for module, inputs in plan},
        },
    )
    for module, inputs in plan:
        if on_module:
            on_module(module.name)
        run.results.append(module.scan(inputs))
    return run


def audit_json(run: AuditRun) -> str:
    from .report import render_json

    data = run.model_dump(mode="json")
    data["status"] = run.status.value
    data["results"] = [json.loads(render_json(r)) for r in run.results]
    return json.dumps(data, indent=2, ensure_ascii=False)
