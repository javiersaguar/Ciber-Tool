"""Detección de credenciales filtradas en un repositorio.

Tres modos, según lo que se quiera mirar:

- **árbol de trabajo** (por defecto): los archivos tal y como están ahora.
- **`--staged`**: solo las líneas añadidas en el índice, que es lo que necesita
  un hook de pre-commit para no dejar pasar un secreto nuevo.
- **`--history`**: las líneas añadidas a lo largo del historial, porque borrar
  un secreto en un commit posterior no lo saca del repositorio.

Dentro de un repositorio git, la lista de archivos sale de `git ls-files`, así
que se respeta el `.gitignore` sin tener que interpretarlo.
"""

from __future__ import annotations

import fnmatch
import subprocess
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, Field

from ..core.finding import Finding, Severity
from ..core.module import Category, ScanModule
from ._secret_rules import (
    ENTROPIA_ALTA,
    ENTROPIA_SOSPECHOSA,
    REGLAS,
    Regla,
    entropia,
    es_marcador,
    redacta,
)

# Directorios que nunca contienen código propio y sí muchísimos ficheros.
DIRECTORIOS_IGNORADOS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        "dist",
        "build",
        "target",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "vendor",
        "site-packages",
        ".next",
        ".nuxt",
        "coverage",
        "htmlcov",
        ".idea",
        ".vscode",
    }
)

# Extensiones sin texto útil que buscar.
EXTENSIONES_IGNORADAS = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".ico",
        ".webp",
        ".svg",
        ".pdf",
        ".zip",
        ".gz",
        ".tar",
        ".bz2",
        ".xz",
        ".7z",
        ".rar",
        ".mp3",
        ".mp4",
        ".avi",
        ".mov",
        ".wav",
        ".ogg",
        ".webm",
        ".ttf",
        ".otf",
        ".woff",
        ".woff2",
        ".eot",
        ".pyc",
        ".pyo",
        ".so",
        ".dll",
        ".dylib",
        ".exe",
        ".bin",
        ".o",
        ".a",
        ".lock",
        ".pack",
        ".idx",
        ".whl",
        ".jar",
        ".class",
    }
)

# Rutas donde un valor con pinta de secreto suele ser un ejemplo. Solo rebaja
# las reglas contextuales: una clave de AWS con formato válido sigue siendo
# crítica aunque esté en un test.
INDICIOS_DE_EJEMPLO = ("test", "spec", "fixture", "mock", "example", "sample", "doc", "demo")

# Comentario con el que marcar una línea como revisada y segura, al estilo de las
# directivas que usan los linters. Hace falta para las credenciales de ejemplo de
# los tests y de la documentación, que son legítimas y no deben ensuciar cada
# análisis.
MARCA_IGNORAR = "atalaya:ignore"

_DEGRADACION = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.LOW,
}

# Marca con la que se separan los commits al recorrer el historial.
#
# En un diff unificado, las líneas de contenido siempre empiezan por '+', '-' o
# espacio, y las de cabecera por 'diff', 'index', '@@' o '---'. Así que una línea
# que empiece por este centinela solo puede ser la que pone `git log --format`.
# (Un NUL sería aún más seguro, pero no se puede pasar en los argumentos.)
_MARCA_COMMIT = "~~atalaya~~"

_LIMITE_EVIDENCIA = 120


class SecretsInput(BaseModel):
    """Entradas del módulo."""

    path: str = Field(description="Ruta del repositorio o carpeta a analizar.")
    staged: bool = Field(
        default=False,
        description="Analizar solo las líneas añadidas en el índice (para un hook de pre-commit).",
    )
    history: bool = Field(
        default=False,
        description="Analizar las líneas añadidas en el historial de commits.",
    )
    max_commits: int = Field(default=200, ge=1, description="Commits a recorrer con --history.")
    min_entropy: float = Field(
        default=ENTROPIA_SOSPECHOSA,
        ge=0,
        description="Entropía mínima para aceptar un valor de las reglas contextuales.",
    )
    max_file_size: int = Field(
        default=1_000_000, gt=0, description="Tamaño máximo de archivo a leer, en bytes."
    )
    exclude: str = Field(
        default="",
        description=(
            "Patrones glob separados por comas que no se analizan, por ejemplo 'tests/*,docs/*'."
        ),
    )


@dataclass
class Fuente:
    """Un trozo de texto que analizar, con la etiqueta que lo ubica."""

    etiqueta: str
    contenido: str
    # Ruta del archivo, sin el commit que la etiqueta lleva delante en el modo
    # historial. Es contra esto contra lo que casan los patrones de exclusión.
    ruta: str = ""
    # Número de la primera línea, para que los diffs señalen la línea real.
    primera_linea: int = 1
    # Números de línea reales, cuando el contenido no es contiguo (diffs).
    lineas: list[int] | None = None

    def __post_init__(self) -> None:
        if not self.ruta:
            self.ruta = self.etiqueta


@dataclass(frozen=True)
class Coincidencia:
    regla: Regla
    secreto: str
    etiqueta: str
    linea: int
    severidad: Severity
    entropia_valor: float
    # El valor contiene un marcador tipo 'EXAMPLE'. En una regla de formato
    # conocido no se descarta, pero sí se rebaja y se avisa.
    parece_ejemplo: bool = False


class SecretsModule(ScanModule):
    id = "secrets"
    name = "Detector de secretos"
    description = (
        "Busca credenciales filtradas (claves de API, tokens, claves privadas) en los "
        "archivos de un repositorio, en el índice o en el historial de commits."
    )
    category = Category.CODE
    InputModel = SecretsInput

    def target_of(self, inputs: SecretsInput) -> str:  # type: ignore[override]
        modo = "índice" if inputs.staged else ("historial" if inputs.history else "árbol")
        return f"{Path(inputs.path).resolve()} ({modo})"

    def run(self, inputs: SecretsInput) -> list[Finding]:  # type: ignore[override]
        raiz = Path(inputs.path).resolve()
        if not raiz.exists():
            raise FileNotFoundError(f"No existe la ruta: {raiz}")

        if inputs.staged and inputs.history:
            raise ValueError("--staged y --history se excluyen: elige uno.")

        if inputs.staged:
            fuentes = self._fuentes_indice(raiz)
        elif inputs.history:
            fuentes = self._fuentes_historial(raiz, inputs.max_commits)
        else:
            fuentes = self._fuentes_arbol(raiz, inputs.max_file_size)

        fuentes = self._sin_excluidas(fuentes, inputs.exclude)

        coincidencias: list[Coincidencia] = []
        revisadas = 0
        for fuente in fuentes:
            revisadas += 1
            coincidencias += self._analiza(fuente, inputs.min_entropy)

        return self._a_hallazgos(coincidencias, revisadas, inputs)

    # -- obtención del texto a analizar -----------------------------------

    def _git(self, raiz: Path, *args: str) -> str:
        """Ejecuta git en la raíz y devuelve su salida."""
        proceso = subprocess.run(
            ["git", *args],
            cwd=raiz,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if proceso.returncode != 0:
            raise RuntimeError(
                f"git {' '.join(args)} falló: {proceso.stderr.strip() or 'sin detalle'}"
            )
        return proceso.stdout

    def _es_repo(self, raiz: Path) -> bool:
        try:
            return self._git(raiz, "rev-parse", "--is-inside-work-tree").strip() == "true"
        except (RuntimeError, FileNotFoundError, OSError):
            return False

    def _fuentes_arbol(self, raiz: Path, max_size: int) -> list[Fuente]:
        fuentes = []
        for archivo in self._archivos(raiz):
            texto = self._lee(archivo, max_size)
            if texto is not None:
                relativa = self._relativa(archivo, raiz)
                fuentes.append(Fuente(etiqueta=relativa, contenido=texto, ruta=relativa))
        return fuentes

    def _archivos(self, raiz: Path) -> list[Path]:
        """Archivos a analizar, respetando .gitignore cuando hay repositorio."""
        if raiz.is_file():
            return [raiz]

        if self._es_repo(raiz):
            # -c: los que están en el índice. -o --exclude-standard: los no
            # seguidos que git tampoco ignora. Así se respeta el .gitignore
            # sin tener que interpretarlo.
            salida = self._git(raiz, "ls-files", "-co", "--exclude-standard")
            rutas = [raiz / linea for linea in salida.splitlines() if linea]
            return [r for r in rutas if r.is_file() and not self._descartable(r)]

        return [
            ruta
            for ruta in raiz.rglob("*")
            if ruta.is_file()
            and not self._descartable(ruta)
            and not any(parte in DIRECTORIOS_IGNORADOS for parte in ruta.parts)
        ]

    def _descartable(self, ruta: Path) -> bool:
        return ruta.suffix.lower() in EXTENSIONES_IGNORADAS

    def _lee(self, ruta: Path, max_size: int) -> str | None:
        """Devuelve el texto del archivo, o None si es binario o demasiado grande."""
        try:
            if ruta.stat().st_size > max_size:
                return None
            crudo = ruta.read_bytes()
        except OSError:
            return None
        # Un NUL en la cabecera es la señal clásica de contenido binario.
        if b"\x00" in crudo[:8192]:
            return None
        return crudo.decode("utf-8", errors="replace")

    def _relativa(self, ruta: Path, raiz: Path) -> str:
        try:
            return ruta.relative_to(raiz).as_posix()
        except ValueError:
            return ruta.as_posix()

    def _fuentes_indice(self, raiz: Path) -> list[Fuente]:
        """Solo lo que se va a commitear: las líneas añadidas en el índice."""
        if not self._es_repo(raiz):
            raise RuntimeError("--staged necesita un repositorio git.")
        diff = self._git(raiz, "diff", "--cached", "--unified=0", "--no-color")
        return self._fuentes_de_diff(diff)

    def _fuentes_historial(self, raiz: Path, max_commits: int) -> list[Fuente]:
        """Las líneas añadidas en cada commit.

        Se mira lo añadido, no el estado final, porque un secreto borrado en un
        commit posterior sigue estando en el historial y sigue siendo accesible.
        """
        if not self._es_repo(raiz):
            raise RuntimeError("--history necesita un repositorio git.")
        diff = self._git(
            raiz,
            "log",
            "-p",
            "--unified=0",
            "--no-color",
            "--all",
            f"--max-count={max_commits}",
            "--date=short",
            f"--format={_MARCA_COMMIT}%h %ad %s",
        )
        return self._fuentes_de_diff(diff)

    def _fuentes_de_diff(self, diff: str) -> list[Fuente]:
        """Extrae de un diff unificado las líneas añadidas, con su archivo y número.

        Solo interesan las añadidas: las eliminadas ya no están, y las de
        contexto se reportarían una vez por cada commit que las roce.
        """
        fuentes: list[Fuente] = []
        archivo: str | None = None
        commit = ""
        numero = 0
        acumulado: list[str] = []
        numeros: list[int] = []

        def vuelca() -> None:
            nonlocal acumulado, numeros
            if archivo and acumulado:
                etiqueta = f"{commit} {archivo}" if commit else archivo
                fuentes.append(
                    Fuente(
                        etiqueta=etiqueta.strip(),
                        contenido="\n".join(acumulado),
                        ruta=archivo,
                        lineas=numeros,
                    )
                )
            acumulado, numeros = [], []

        for linea in diff.splitlines():
            if linea.startswith(_MARCA_COMMIT):
                vuelca()
                archivo = None
                commit = linea[len(_MARCA_COMMIT) :].strip()
            elif linea.startswith("+++ "):
                vuelca()
                ruta = linea[4:].strip()
                # /dev/null aparece cuando el archivo se borra en ese commit.
                archivo = None if ruta == "/dev/null" else ruta.removeprefix("b/")
            elif linea.startswith("@@"):
                numero = self._linea_de_hunk(linea)
            elif linea.startswith("+") and not linea.startswith("+++"):
                acumulado.append(linea[1:])
                numeros.append(numero)
                numero += 1

        vuelca()
        return fuentes

    def _linea_de_hunk(self, cabecera: str) -> int:
        """Saca el número de la primera línea nueva de un '@@ -a,b +c,d @@'."""
        try:
            nuevo = cabecera.split("+", 1)[1].split(maxsplit=1)[0]
            return int(nuevo.split(",")[0])
        except (IndexError, ValueError):
            return 0

    # -- análisis ---------------------------------------------------------

    def _analiza(self, fuente: Fuente, min_entropia: float) -> list[Coincidencia]:
        coincidencias: list[Coincidencia] = []
        es_ejemplo = self._parece_ejemplo(fuente.etiqueta)

        for indice, linea in enumerate(fuente.contenido.splitlines()):
            if MARCA_IGNORAR in linea:
                continue
            numero = (
                fuente.lineas[indice]
                if fuente.lineas and indice < len(fuente.lineas)
                else fuente.primera_linea + indice
            )
            for regla in REGLAS:
                for m in regla.pattern.finditer(linea):
                    secreto = m.group(regla.group) or ""
                    if not secreto:
                        continue

                    marcador = es_marcador(secreto)
                    # En una regla contextual, un marcador descarta: el valor no
                    # era un secreto. En una de formato conocido no se descarta,
                    # porque una credencial real puede contener 'abcdef' por azar
                    # y perderla en silencio sería mucho peor que un falso positivo.
                    if marcador and regla.requiere_entropia:
                        continue

                    entropia_valor = entropia(secreto)
                    if regla.requiere_entropia and entropia_valor < min_entropia:
                        continue

                    coincidencias.append(
                        Coincidencia(
                            regla=regla,
                            secreto=secreto,
                            etiqueta=fuente.etiqueta,
                            linea=numero,
                            severidad=self._severidad(regla, entropia_valor, es_ejemplo, marcador),
                            entropia_valor=entropia_valor,
                            parece_ejemplo=marcador,
                        )
                    )
        return coincidencias

    def _sin_excluidas(self, fuentes: list[Fuente], exclude: str) -> list[Fuente]:
        """Descarta las fuentes cuya ruta case con alguno de los patrones."""
        patrones = [p.strip() for p in exclude.split(",") if p.strip()]
        if not patrones:
            return fuentes
        return [
            f for f in fuentes if not any(fnmatch.fnmatch(f.ruta, patron) for patron in patrones)
        ]

    def _parece_ejemplo(self, etiqueta: str) -> bool:
        bajo = etiqueta.lower()
        return any(indicio in bajo for indicio in INDICIOS_DE_EJEMPLO)

    def _severidad(
        self, regla: Regla, entropia_valor: float, es_ejemplo: bool, marcador: bool
    ) -> Severity:
        severidad = regla.severity

        # Un valor con formato de credencial pero que contiene 'EXAMPLE' casi
        # seguro sale de documentación. Se reporta, pero sin gritar.
        if marcador:
            severidad = _DEGRADACION[_DEGRADACION[severidad]]

        # Las contextuales se gradúan: cuanto más aleatorio el valor, más
        # probable que sea un secreto de verdad y no una cadena cualquiera.
        if regla.requiere_entropia and entropia_valor < ENTROPIA_ALTA:
            severidad = _DEGRADACION[severidad]

        # En tests y ejemplos se rebaja lo contextual, pero no lo que tiene
        # formato de credencial real: esa es real esté donde esté.
        if es_ejemplo and regla.requiere_entropia:
            severidad = _DEGRADACION[severidad]

        return severidad

    # -- salida -----------------------------------------------------------

    def _a_hallazgos(
        self, coincidencias: list[Coincidencia], revisadas: int, inputs: SecretsInput
    ) -> list[Finding]:
        if not coincidencias:
            return [
                Finding(
                    severity=Severity.OK,
                    title="No se han encontrado credenciales",
                    description=f"Se han analizado {revisadas} fuente(s) de texto.",
                )
            ]

        # El mismo secreto puede aparecer en varios sitios; se agrupa para no
        # repetir el mismo hallazgo una y otra vez.
        agrupadas: dict[tuple[str, str], list[Coincidencia]] = {}
        for c in coincidencias:
            agrupadas.setdefault((c.regla.id, c.secreto), []).append(c)

        hallazgos = []
        for grupo in agrupadas.values():
            hallazgos.append(self._hallazgo(grupo))

        orden = list(Severity)
        hallazgos.sort(key=lambda f: orden.index(f.severity))
        return hallazgos

    def _hallazgo(self, grupo: list[Coincidencia]) -> Finding:
        primera = grupo[0]
        # Dentro de un grupo la severidad puede variar (mismo valor en un test y
        # en producción); manda la más alta.
        orden = list(Severity)
        severidad = min((c.severidad for c in grupo), key=orden.index)

        ubicaciones = [f"{c.etiqueta}:{c.linea}" for c in grupo[:5]]
        if len(grupo) > 5:
            ubicaciones.append(f"y {len(grupo) - 5} más")

        mostrado = redacta(primera.secreto) if primera.regla.redactar else primera.secreto
        evidencia = f"{mostrado}  ·  {', '.join(ubicaciones)}"
        if len(evidencia) > _LIMITE_EVIDENCIA:
            evidencia = evidencia[:_LIMITE_EVIDENCIA] + "…"

        descripcion = primera.regla.description
        if primera.parece_ejemplo:
            descripcion += (
                " El valor contiene un marcador de ejemplo, así que probablemente venga"
                " de documentación; se reporta rebajado por si acaso."
            )
        if primera.regla.requiere_entropia:
            descripcion += f" Entropía del valor: {primera.entropia_valor:.1f} bits/carácter."

        return Finding(
            severity=severidad,
            title=primera.regla.name,
            description=descripcion,
            evidence=evidencia,
            remediation=primera.regla.remediation,
            references=primera.regla.references,
        )
