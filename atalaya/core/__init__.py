"""Núcleo compartido: modelo de hallazgos, contrato de módulo, registro e informes."""

from .finding import Finding, ScanResult, Severity
from .module import Category, ScanModule
from .registry import ModuleRegistry, get_registry

__all__ = [
    "Category",
    "Finding",
    "ModuleRegistry",
    "ScanModule",
    "ScanResult",
    "Severity",
    "get_registry",
]
