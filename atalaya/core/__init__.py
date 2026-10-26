"""Núcleo compartido: modelo de hallazgos, contrato de módulo, registro e informes."""

from .finding import (
    Check,
    CheckStatus,
    EvaluationStatus,
    Finding,
    FindingKind,
    ScanOutput,
    ScanResult,
    Severity,
)
from .module import Category, Coverage, ScanModule
from .registry import ModuleRegistry, get_registry
from .service import ServiceContext, ServiceEvent, ServiceModule

__all__ = [
    "Category",
    "Check",
    "CheckStatus",
    "Coverage",
    "EvaluationStatus",
    "Finding",
    "FindingKind",
    "ModuleRegistry",
    "ScanModule",
    "ScanOutput",
    "ScanResult",
    "Severity",
    "ServiceContext",
    "ServiceEvent",
    "ServiceModule",
    "get_registry",
]
