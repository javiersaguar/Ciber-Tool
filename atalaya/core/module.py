"""Metadatos compartidos y contrato de análisis puntual de Atalaya.

Un módulo declara qué necesita (`InputModel`, un modelo de pydantic) y qué hace
(`run`, que devuelve hallazgos). De ese `InputModel` salen automáticamente los
argumentos de la CLI, la validación de la API y el formulario de la web, así que
añadir una herramienta nueva no obliga a tocar ninguna de las tres.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from enum import Enum
from typing import ClassVar

from pydantic import BaseModel

from .finding import Check, CheckStatus, Finding, ScanOutput, ScanResult


class Category(str, Enum):
    """Familia a la que pertenece el módulo. Solo sirve para agrupar en la interfaz."""

    WEB = "web"
    CRYPTO = "crypto"
    RECON = "recon"
    INTEL = "intel"
    CODE = "code"


class ModuleDescriptor(ABC):
    """Identidad y esquema comunes; no impone un ciclo de ejecución."""

    id: ClassVar[str]
    name: ClassVar[str]
    description: ClassVar[str]
    category: ClassVar[Category]
    InputModel: ClassVar[type[BaseModel]]
    show_info: ClassVar[bool] = False

    def parse_inputs(self, **kwargs) -> BaseModel:
        return self.InputModel(**kwargs)

    @classmethod
    def input_schema(cls) -> dict:
        return cls.InputModel.model_json_schema()

    @classmethod
    def info(cls) -> dict:
        return {
            "id": cls.id,
            "name": cls.name,
            "description": cls.description,
            "category": cls.category.value,
            "input_schema": cls.input_schema(),
        }


class Coverage:
    """Lleva la cuenta de qué comprobaciones concluyeron, para el `ScanOutput`.

    `run` envuelve cada comprobación y, si una revienta, queda marcada como sin
    determinar en lugar de tumbar el análisis entero o, peor, de desaparecer
    del informe como si hubiera salido bien.
    """

    def __init__(self) -> None:
        self.checks: list[Check] = []

    def run(self, check_id: str, name: str, fn: Callable[[], list[Finding]]) -> list[Finding]:
        try:
            findings = fn()
        except Exception as exc:  # noqa: BLE001 - se refleja como comprobación pendiente
            self.undetermined(check_id, name, f"{type(exc).__name__}: {exc}")
            return []
        self.done(check_id, name)
        return findings

    def done(self, check_id: str, name: str, detail: str | None = None) -> None:
        self.checks.append(Check(id=check_id, name=name, status=CheckStatus.DONE, detail=detail))

    def skipped(self, check_id: str, name: str, detail: str | None = None) -> None:
        self.checks.append(Check(id=check_id, name=name, status=CheckStatus.SKIPPED, detail=detail))

    def undetermined(self, check_id: str, name: str, detail: str | None = None) -> None:
        self.checks.append(
            Check(id=check_id, name=name, status=CheckStatus.UNDETERMINED, detail=detail)
        )

    def output(self, findings: list[Finding], metadata: dict[str, str] | None = None) -> ScanOutput:
        return ScanOutput(findings=findings, checks=self.checks, metadata=metadata or {})


class ScanModule(ModuleDescriptor):
    """Base de todo módulo de análisis puntual (ejecuta, informa y termina).

    Los servicios de larga duración tienen su propia base hermana, ServiceModule.
    """

    @abstractmethod
    def run(self, inputs: BaseModel) -> list[Finding] | ScanOutput:
        """Analiza el objetivo y devuelve los hallazgos.

        Puede devolver la lista sin más o un `ScanOutput` que además diga qué
        comprobaciones concluyeron (ver `Coverage`). Puede lanzar excepciones:
        `scan` las captura y las refleja en el `ScanResult`, de modo que un
        módulo que falla no tumba una ejecución que abarque varios, y el
        resultado queda como no evaluado en vez de con nota perfecta.
        """

    def target_of(self, inputs: BaseModel) -> str:
        """Descripción corta del objetivo, para los informes.

        Por defecto usa el primer campo del `InputModel`, que por convención es
        el objetivo. Un módulo puede sobrescribirlo si necesita algo más claro.
        """
        first = next(iter(type(inputs).model_fields))
        return str(getattr(inputs, first))

    def scan(self, inputs: BaseModel) -> ScanResult:
        """Ejecuta `run` midiendo el tiempo y capturando errores."""
        result = ScanResult(
            module_id=self.id,
            module_name=self.name,
            target=self.target_of(inputs),
        )
        start = time.perf_counter()
        try:
            salida = self.run(inputs)
            if isinstance(salida, ScanOutput):
                result.findings = salida.findings
                result.checks = salida.checks
                result.metadata = salida.metadata
            else:
                result.findings = salida
        except Exception as exc:  # noqa: BLE001 - un módulo roto no debe tumbar el resto
            result.error = f"{type(exc).__name__}: {exc}"
        result.duration_seconds = round(time.perf_counter() - start, 3)
        return result
