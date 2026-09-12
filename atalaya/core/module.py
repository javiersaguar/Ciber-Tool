"""Metadatos compartidos y contrato de análisis puntual de Atalaya.

Un módulo declara qué necesita (`InputModel`, un modelo de pydantic) y qué hace
(`run`, que devuelve hallazgos). De ese `InputModel` salen automáticamente los
argumentos de la CLI, la validación de la API y el formulario de la web, así que
añadir una herramienta nueva no obliga a tocar ninguna de las tres.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from enum import Enum
from typing import ClassVar

from pydantic import BaseModel

from .finding import Finding, ScanResult


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


class ScanModule(ModuleDescriptor):
    """Base de todo módulo de análisis puntual (ejecuta, informa y termina).

    Los servicios de larga duración tienen su propia base hermana, ServiceModule.
    """

    @abstractmethod
    def run(self, inputs: BaseModel) -> list[Finding]:
        """Analiza el objetivo y devuelve los hallazgos.

        Puede lanzar excepciones: `scan` las captura y las refleja en el
        `ScanResult`, de modo que un módulo que falla no tumba una ejecución
        que abarque varios.
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
            result.findings = self.run(inputs)
        except Exception as exc:  # noqa: BLE001 - un módulo roto no debe tumbar el resto
            result.error = f"{type(exc).__name__}: {exc}"
        result.duration_seconds = round(time.perf_counter() - start, 3)
        return result
