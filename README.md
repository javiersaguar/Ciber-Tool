# Atalaya

Caja de herramientas modular de seguridad defensiva. Un solo comando, un informe
con el mismo formato para todas las herramientas, y una arquitectura en la que
añadir un análisis nuevo es crear un archivo.

```
$ atalaya http-headers github.com

╭──────────────────────────────────────────────╮
│ Auditor de cabeceras HTTP                    │
│ https://github.com/                          │
│                                              │
│  A   90/100                                  │
╰──────────────────────────────────────────────╯

    BAJO  Falta Permissions-Policy
          Sin ella, cualquier iframe de la página puede pedir cámara,
          micrófono o geolocalización en nombre de tu sitio.
          Solución: Permissions-Policy: camera=(), microphone=(), geolocation=()
```

## Por qué modular

Cada herramienta de seguridad suele ser un script aislado con su propia salida,
sus propios argumentos y su propio criterio. Atalaya define **un contrato** que
cumplen todas:

- Declaran qué necesitan con un modelo de **pydantic** (`InputModel`).
- Devuelven siempre lo mismo: una lista de **`Finding`** con gravedad, evidencia
  y solución.

De ahí sale todo lo demás de forma automática: los argumentos de la CLI, la
validación de la API, el formulario de la web y los tres formatos de informe.

## Módulos

| ID | Categoría | Qué hace |
|---|---|---|
| `http-headers` | web | Audita HSTS, CSP, X-Frame-Options, cookies, fugas de versión y CORS. |
| `tls` | crypto | Valida el certificado, su caducidad, fuerza de clave y firma, versiones de TLS y cifrados aceptados. |
| `secrets` | code | Busca credenciales filtradas en los archivos, en el índice o en el historial de commits. |

En camino: detector de phishing en URLs con aprendizaje automático, y honeypot
SSH con panel de ataques.

## Instalación

```bash
git clone https://github.com/javiersaguar/Ciber-Tool
cd Ciber-Tool
python -m venv .venv && .venv/Scripts/activate   # Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"
```

## Uso

```bash
atalaya list                              # módulos disponibles
atalaya http-headers ejemplo.com          # auditoría de cabeceras
atalaya tls ejemplo.com --port 443        # certificado y configuración TLS
atalaya tls ejemplo.com --detallado       # incluye también lo que está bien
atalaya secrets .                         # busca credenciales en este repositorio
```

Si el ejecutable no estuviera disponible, todo funciona igual con `python -m atalaya`.

Informes en otros formatos:

```bash
atalaya http-headers ejemplo.com --formato json
atalaya tls ejemplo.com --formato html --salida informe.html
```

### Buscar secretos

El módulo `secrets` tiene tres modos, según lo que interese mirar:

```bash
atalaya secrets .              # los archivos tal y como están ahora
atalaya secrets . --staged     # solo lo que se va a commitear
atalaya secrets . --history    # las líneas añadidas a lo largo del historial
```

El modo `--history` es el que más sorprende: **borrar un secreto en un commit
posterior no lo saca del repositorio**, así que sigue ahí para cualquiera que
clone. Si aparece algo, no basta con borrarlo: hay que revocar la credencial.

Dentro de un repositorio git se respeta el `.gitignore`, porque la lista de
archivos sale de `git ls-files`.

**Cómo se decide la gravedad.** Hay dos familias de reglas. Las de formato
conocido (`AKIA…`, `ghp_…`, `sk_live_…`) casi no dan falsos positivos y van en
crítico. Las contextuales buscan asignaciones tipo `api_key = "…"` y exigen
además que el valor tenga entropía alta, porque el nombre de la variable no
basta: `password = "changeme"` no es un secreto.

**Falsos positivos.** Dos formas de silenciarlos:

```bash
atalaya secrets . --exclude "tests/*,docs/*"   # por ruta
```

```python
TOKEN_DE_EJEMPLO = "ghp_0000000000000000000000000000000000"  # atalaya:ignore
```

Los valores que son claramente huecos (`your_api_key_here`, `${TOKEN}`,
`changeme`) ya se descartan solos. Con una salvedad deliberada: si el valor
tiene formato de credencial real pero contiene algo como `EXAMPLE`, **no se
descarta**, solo se rebaja de gravedad. Perder una clave auténtica que por azar
contuviera esa palabra sería mucho peor que un falso positivo.

### Como hook de pre-commit

Para que no se te escape un secreto en un commit, en `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/javiersaguar/Ciber-Tool
    rev: v0.2.0
    hooks:
      - id: atalaya-secrets
```

Analiza solo las líneas añadidas al índice, así que un secreto que ya estuviera
en el historial no te bloquea todos los commits a partir de ahora.

### Uso en integración continua

El código de salida permite cortar un pipeline cuando aparece algo grave:

| Código | Significado |
|---|---|
| `0` | Sin hallazgos por encima del umbral |
| `1` | El análisis no pudo completarse |
| `2` | Hay hallazgos en el umbral o por encima |

```bash
atalaya http-headers https://mi-web.com --fallar-en medium
```

## Cómo se puntúa

Se parte de 100 puntos y cada hallazgo resta según su gravedad: crítico 50,
alto 25, medio 10, bajo 3. Los hallazgos informativos no penalizan.

| Nota | Puntos |
|---|---|
| A+ | 100 |
| A | 90–99 |
| B | 80–89 |
| C | 65–79 |
| D | 50–64 |
| E | 30–49 |
| F | < 30 |

## Añadir un módulo

Crea un archivo en `atalaya/modules/`. No hay que registrarlo en ningún sitio:
el descubrimiento es automático y el módulo aparece en la CLI, en la API y en la web.

```python
from pydantic import BaseModel, Field

from ..core.finding import Finding, Severity
from ..core.module import Category, ScanModule


class MiInput(BaseModel):
    objetivo: str = Field(description="Lo que se va a analizar.")
    profundo: bool = Field(default=False, description="Análisis exhaustivo.")


class MiModulo(ScanModule):
    id = "mi-modulo"
    name = "Mi módulo"
    description = "Qué hace, en una línea."
    category = Category.RECON
    InputModel = MiInput

    def run(self, inputs: MiInput) -> list[Finding]:
        return [
            Finding(
                severity=Severity.MEDIUM,
                title="He encontrado algo",
                description="Por qué importa.",
                evidence="El dato que lo demuestra.",
                remediation="Cómo se arregla.",
            )
        ]
```

Y ya está disponible:

```bash
atalaya mi-modulo objetivo.com --profundo
```

## Arquitectura

```
atalaya/
├── core/
│   ├── finding.py     Severity, Finding, ScanResult (puntuación y nota)
│   ├── module.py      ScanModule: el contrato
│   ├── registry.py    descubrimiento automático de módulos
│   └── report.py      renderizado a terminal, JSON y HTML
├── modules/           una herramienta por archivo
│   └── _secret_rules.py   catálogo de reglas (el guion bajo lo excluye del registro)
└── cli.py             subcomandos generados desde el registro
```

## Aviso

Atalaya analiza objetivos desde fuera, sin explotar nada y sin modificar nada,
pero **úsalo solo sobre sistemas de tu propiedad o para los que tengas permiso
por escrito**. Escanear infraestructura ajena sin autorización es ilegal en la
mayoría de las jurisdicciones.

## Licencia

MIT
