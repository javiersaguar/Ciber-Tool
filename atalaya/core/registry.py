"""Descubrimiento automático de módulos.

Recorre el paquete `atalaya.modules`, importa lo que encuentre y registra toda
subclase concreta de `ScanModule` o `ServiceModule`. Añadir una herramienta es crear un archivo
ahí dentro: no hay lista que mantener ni imports que recordar.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from functools import lru_cache

from .module import Category, ScanModule
from .service import ServiceModule

Module = ScanModule | ServiceModule


class ModuleRegistry:
    """Colección de módulos disponibles, indexada por id."""

    def __init__(self) -> None:
        self._modules: dict[str, Module] = {}

    def register(self, module: Module) -> None:
        if module.id in self._modules:
            raise ValueError(
                f"Ya hay un módulo registrado con id '{module.id}' "
                f"({type(self._modules[module.id]).__name__})"
            )
        self._modules[module.id] = module

    def get(self, module_id: str) -> Module:
        try:
            return self._modules[module_id]
        except KeyError:
            disponibles = ", ".join(sorted(self._modules)) or "ninguno"
            raise KeyError(
                f"No existe el módulo '{module_id}'. Disponibles: {disponibles}"
            ) from None

    def all(self) -> list[Module]:
        return sorted(self._modules.values(), key=lambda m: (m.category.value, m.id))

    def by_category(self) -> dict[Category, list[Module]]:
        agrupados: dict[Category, list[Module]] = {}
        for module in self.all():
            agrupados.setdefault(module.category, []).append(module)
        return agrupados

    def ids(self) -> list[str]:
        return sorted(self._modules)

    def __len__(self) -> int:
        return len(self._modules)

    def __contains__(self, module_id: object) -> bool:
        return module_id in self._modules


def _is_concrete_module(obj: object) -> bool:
    """Una subclase de cualquiera de los dos contratos, con id propio.

    Descarta la propia base, las clases abstractas intermedias y las clases
    importadas de rebote en otro módulo (cada una se registra desde su archivo).
    """
    return (
        inspect.isclass(obj)
        and issubclass(obj, (ScanModule, ServiceModule))
        and obj not in (ScanModule, ServiceModule)
        and not inspect.isabstract(obj)
        and "id" in obj.__dict__
    )


@lru_cache(maxsize=1)
def get_registry() -> ModuleRegistry:
    """Registro global, construido una sola vez por proceso."""
    from atalaya import modules as modules_pkg

    registry = ModuleRegistry()
    for info in pkgutil.iter_modules(modules_pkg.__path__):
        if info.name.startswith("_"):
            continue
        imported = importlib.import_module(f"{modules_pkg.__name__}.{info.name}")
        for _, obj in inspect.getmembers(imported, _is_concrete_module):
            # Solo registramos las clases definidas en este archivo, no las
            # que estén ahí por un import.
            if obj.__module__ == imported.__name__:
                registry.register(obj())
    return registry
