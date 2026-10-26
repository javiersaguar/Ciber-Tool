"""Modelo de datos común a todos los módulos.

Cualquier módulo de Atalaya produce `Finding`, como resultado o como evento.
Eso es lo que permite tener un único renderizador de informes, una única API y
una única interfaz web para herramientas que por dentro no se parecen en nada.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Gravedad de un hallazgo, de mayor a menor."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    OK = "ok"

    @property
    def weight(self) -> int:
        """Peso para ordenar y para calcular la nota. `OK` e `INFO` no penalizan."""
        return _WEIGHTS[self]

    @property
    def label(self) -> str:
        return _LABELS[self]

    @property
    def color(self) -> str:
        """Color de `rich` asociado, usado por el renderizador de terminal."""
        return _COLORS[self]


_WEIGHTS = {
    Severity.CRITICAL: 50,
    Severity.HIGH: 25,
    Severity.MEDIUM: 10,
    Severity.LOW: 3,
    Severity.INFO: 0,
    Severity.OK: 0,
}

_LABELS = {
    Severity.CRITICAL: "CRÍTICO",
    Severity.HIGH: "ALTO",
    Severity.MEDIUM: "MEDIO",
    Severity.LOW: "BAJO",
    Severity.INFO: "INFO",
    Severity.OK: "OK",
}

_COLORS = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
    Severity.OK: "green",
}


class FindingKind(str, Enum):
    """Qué clase de problema es, aparte de cuánto pesa.

    La gravedad dice cuánto importa; el tipo dice cuánto se ha demostrado. No es
    lo mismo una cabecera de defensa en profundidad que falta que un certificado
    caducado o una clave filtrada, aunque ambos puedan pesar lo mismo en la nota.
    """

    VULNERABILITY = "vulnerability"
    HARDENING = "hardening"

    @property
    def label(self) -> str:
        return _KIND_LABELS[self]


_KIND_LABELS = {
    FindingKind.VULNERABILITY: "Vulnerabilidad demostrada",
    FindingKind.HARDENING: "Configuración mejorable",
}


class Finding(BaseModel):
    """Un hallazgo concreto: qué pasa, qué lo demuestra y cómo se arregla."""

    severity: Severity
    title: str
    rule_id: str | None = None
    location: str | None = None
    attributes: dict[str, str] = Field(default_factory=dict)
    kind: FindingKind | None = Field(
        default=None,
        description="Vulnerabilidad demostrada o configuración mejorable; None si no aplica.",
    )
    description: str = ""
    evidence: str | None = Field(
        default=None,
        description="El dato crudo que respalda el hallazgo (cabecera, campo del cert...).",
    )
    remediation: str | None = Field(default=None, description="Qué hacer para corregirlo.")
    references: list[str] = Field(default_factory=list)

    def __str__(self) -> str:  # pragma: no cover - conveniencia al depurar
        return f"[{self.severity.label}] {self.title}"


class CheckStatus(str, Enum):
    """Hasta dónde llegó una comprobación concreta."""

    DONE = "done"
    SKIPPED = "skipped"
    UNDETERMINED = "undetermined"

    @property
    def label(self) -> str:
        return _CHECK_LABELS[self]


_CHECK_LABELS = {
    CheckStatus.DONE: "comprobada",
    CheckStatus.SKIPPED: "omitida",
    CheckStatus.UNDETERMINED: "sin determinar",
}


class Check(BaseModel):
    """Una comprobación del módulo y si llegó a una conclusión.

    `SKIPPED` es una omisión pedida (por ejemplo, desactivar la prueba de
    protocolos); `UNDETERMINED` es que se intentó y no se pudo concluir nada,
    como un timeout. Solo lo segundo impide dar nota.
    """

    id: str
    name: str
    status: CheckStatus = CheckStatus.DONE
    detail: str | None = None


class ScanOutput(BaseModel):
    """Lo que puede devolver `run` cuando además informa de su cobertura."""

    findings: list[Finding] = Field(default_factory=list)
    checks: list[Check] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)


class EvaluationStatus(str, Enum):
    """Si el resultado permite dar una nota o no."""

    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    NOT_EVALUATED = "not_evaluated"

    @property
    def label(self) -> str:
        return _STATUS_LABELS[self]


_STATUS_LABELS = {
    EvaluationStatus.COMPLETE: "Análisis completo",
    EvaluationStatus.INCOMPLETE: "Análisis incompleto",
    EvaluationStatus.NOT_EVALUATED: "No evaluado",
}


class ScanResult(BaseModel):
    """Resultado completo de ejecutar un módulo sobre un objetivo."""

    module_id: str
    module_name: str
    target: str
    findings: list[Finding] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    duration_seconds: float = 0.0
    error: str | None = Field(
        default=None,
        description="Si el módulo no pudo completarse, el motivo. Los findings serán parciales.",
    )
    metadata: dict[str, str] = Field(
        default_factory=dict,
        description="Datos del objetivo que no son hallazgos (IP resuelta, servidor, etc.).",
    )
    checks: list[Check] = Field(
        default_factory=list,
        description="Cobertura: qué comprobaciones concluyeron y cuáles quedaron pendientes.",
    )

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def status(self) -> EvaluationStatus:
        """Completo solo si no hubo error y ninguna comprobación quedó sin determinar.

        Sin esta distinción, un módulo que falla antes de emitir hallazgos
        sacaba 100/100 y A+ junto al mensaje de error.
        """
        hechas = [c for c in self.checks if c.status is CheckStatus.DONE]
        if self.error and not self.findings:
            return EvaluationStatus.NOT_EVALUATED
        if self.checks and not hechas and not self.findings:
            return EvaluationStatus.NOT_EVALUATED
        if self.error or self.pending_checks:
            return EvaluationStatus.INCOMPLETE
        return EvaluationStatus.COMPLETE

    @property
    def pending_checks(self) -> list[Check]:
        return [c for c in self.checks if c.status is CheckStatus.UNDETERMINED]

    def coverage(self) -> dict[str, int]:
        """Recuento de comprobaciones por estado, más el total."""
        resumen = {s.value: 0 for s in CheckStatus}
        for check in self.checks:
            resumen[check.status.value] += 1
        resumen["total"] = len(self.checks)
        return resumen

    def by_severity(self) -> list[Finding]:
        """Los hallazgos ordenados de más grave a menos."""
        order = list(Severity)
        return sorted(self.findings, key=lambda f: order.index(f.severity))

    def count(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.severity is severity)

    @property
    def score_upper_bound(self) -> int | None:
        """Lo que se ha podido calcular con lo comprobado: 100 menos el peso de cada hallazgo.

        En un análisis incompleto es un techo, no la nota: lo que quedó por
        comprobar solo podría restar. Si no se evaluó nada, no hay cifra.
        """
        if self.status is EvaluationStatus.NOT_EVALUATED:
            return None
        penalty = sum(f.severity.weight for f in self.findings)
        return max(0, 100 - penalty)

    @property
    def score(self) -> int | None:
        """Puntuación de 0 a 100, solo si el análisis está completo."""
        if self.status is not EvaluationStatus.COMPLETE:
            return None
        return self.score_upper_bound

    @property
    def grade(self) -> str | None:
        """Nota de A+ a F derivada de la puntuación; None si el análisis no está completo."""
        score = self.score
        if score is None:
            return None
        for threshold, grade in _GRADES:
            if score >= threshold:
                return grade
        return "F"


_GRADES = [
    (100, "A+"),
    (90, "A"),
    (80, "B"),
    (65, "C"),
    (50, "D"),
    (30, "E"),
]
