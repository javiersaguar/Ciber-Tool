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


class Finding(BaseModel):
    """Un hallazgo concreto: qué pasa, qué lo demuestra y cómo se arregla."""

    severity: Severity
    title: str
    description: str = ""
    evidence: str | None = Field(
        default=None,
        description="El dato crudo que respalda el hallazgo (cabecera, campo del cert...).",
    )
    remediation: str | None = Field(default=None, description="Qué hacer para corregirlo.")
    references: list[str] = Field(default_factory=list)

    def __str__(self) -> str:  # pragma: no cover - conveniencia al depurar
        return f"[{self.severity.label}] {self.title}"


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

    @property
    def ok(self) -> bool:
        return self.error is None

    def by_severity(self) -> list[Finding]:
        """Los hallazgos ordenados de más grave a menos."""
        order = list(Severity)
        return sorted(self.findings, key=lambda f: order.index(f.severity))

    def count(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.severity is severity)

    @property
    def score(self) -> int:
        """Puntuación de 0 a 100. Se parte de 100 y cada hallazgo resta su peso."""
        penalty = sum(f.severity.weight for f in self.findings)
        return max(0, 100 - penalty)

    @property
    def grade(self) -> str:
        """Nota de A+ a F derivada de la puntuación."""
        score = self.score
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
