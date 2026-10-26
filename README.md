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
│ Cobertura: 12 de 12 comprobaciones concluidas│
╰──────────────────────────────────────────────╯

    BAJO  Falta Permissions-Policy  · Configuración mejorable
          Sin ella, cualquier iframe de la página puede pedir cámara,
          micrófono o geolocalización en nombre de tu sitio.
          Solución: Permissions-Policy: camera=(), microphone=(), geolocation=()
```

## Por qué modular

Cada herramienta de seguridad suele ser un script aislado con su propia salida,
sus propios argumentos y su propio criterio. Atalaya define dos contratos hermanos:

- Declaran qué necesitan con un modelo de **pydantic** (`InputModel`).
- Los análisis `ScanModule` devuelven una lista de **`Finding`** y terminan.
- Los servicios `ServiceModule` emiten eventos y hallazgos mientras están activos;
  los informes se obtienen de una ventana temporal.

De ahí sale todo lo demás de forma automática: los argumentos de la CLI, la
validación de la API, el formulario de la web y los tres formatos de informe.

## Módulos

| ID | Categoría | Qué hace |
|---|---|---|
| `http-headers` | web | Audita HSTS, CSP, X-Frame-Options, cookies, fugas de versión y CORS. |
| `tls` | crypto | Valida el certificado, su caducidad, fuerza de clave y firma, versiones de TLS y cifrados aceptados. |
| `secrets` | code | Busca credenciales filtradas en los archivos, en el índice o en el historial de commits. |
| `ssh-honeypot` | intel | Servicio SSH que siempre deniega acceso, con panel privado y alertas de fuerza bruta. |

En camino: detector de phishing en URLs con aprendizaje automático.

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
atalaya ssh-honeypot                       # SSH en 127.0.0.1:2222; panel en 127.0.0.1:8080
```

Si el ejecutable no estuviera disponible, todo funciona igual con `python -m atalaya`.

Informes en otros formatos:

```bash
atalaya http-headers ejemplo.com --formato json
atalaya tls ejemplo.com --formato html --salida informe.html
```

### Honeypot SSH

`atalaya ssh-honeypot` se mantiene activo hasta Ctrl+C o SIGTERM. El panel requiere
el token de `.atalaya-honeypot/dashboard.token`; muestra intentos en directo,
ranking por HMAC, mapa con una base City `.mmdb` local y evolución temporal.
Todas las autenticaciones se rechazan y no hay canales ni reenvíos.

```bash
atalaya ssh-honeypot --duration 60 --formato json --salida ventana.json
atalaya ssh-honeypot --host 0.0.0.0 --port 2222 --geoip-db /ruta/GeoLite2-City.mmdb
```

Las contraseñas y usuarios se almacenan como seudónimos diarios, nunca como
credenciales recuperables. Consulta [las decisiones de diseño](docs/service-design.md)
y [la guía para Windows y VPS Linux](docs/honeypot-operations.md) antes de exponerlo.

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
| `0` | Análisis completo y sin hallazgos por encima del umbral |
| `1` | El análisis no pudo completarse |
| `2` | Hay hallazgos en el umbral o por encima |
| `3` | Sin hallazgos por encima del umbral, pero alguna comprobación quedó sin determinar |

El `3` existe para que un CI no lea como «revisado y limpio» un análisis en el
que, por ejemplo, la prueba de TLS 1.0 dio timeout. `--fallar-en nunca` solo
desactiva el `2`.

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

**Solo hay nota si el análisis está completo.** Cada módulo informa de su
cobertura: qué comprobaciones concluyeron, cuáles se omitieron a petición
(`--no-check-protocols`, `--no-probe-cors`) y cuáles no se pudieron determinar
(un timeout, una conexión cortada, un OpenSSL local que no puede ofrecer TLS 1.0).

| Estado | Cuándo | Qué se muestra |
|---|---|---|
| Completo | Sin errores y todo concluido u omitido a propósito | Nota y puntos |
| Análisis incompleto | Alguna comprobación sin determinar, o un error con hallazgos parciales | Sin nota; los puntos como techo («como máximo 87/100») y la lista de lo pendiente |
| No evaluado | El módulo falló antes de comprobar nada | Sin nota ni puntos |

Así un dominio que no resuelve ya no sale con 100/100 y A+ junto al error. En
el JSON van `status`, `score` y `grade` (nulos si no hay nota),
`score_upper_bound` y `coverage`.

**Gravedad y tipo son cosas distintas.** Además de la gravedad, cada hallazgo
dice si es una *vulnerabilidad demostrada* (un certificado caducado, TLS 1.0
aceptado, un CORS que refleja cualquier origen con credenciales, una clave
filtrada) o una *configuración mejorable* (una cabecera de defensa en
profundidad que falta).

### Cómo se interpretan las cabeceras

Las cabeceras se leen según su gramática, no buscando texto:

- **CSP**: se separa en políticas y directivas. `'unsafe-inline'` solo cuenta en
  `script-src`/`default-src` y si no lo neutraliza un nonce o hash; con
  `'strict-dynamic'` se ignora la lista de hosts; `https:`, `data:` o
  `https://*` cuentan como comodín. Si hay varias políticas, una debilidad solo
  cuenta si la tienen todas.
- **frame-ancestors**: se mira qué orígenes permite. `*` o `https:` no protegen,
  y como el navegador ignora X-Frame-Options cuando la directiva existe, un
  `X-Frame-Options: DENY` no lo compensa.
- **Cookies**: se separa el par nombre=valor de los atributos, así que una
  cookie llamada `secure_session` no pasa por tener `Secure`. Se revisan
  también `SameSite=None` sin `Secure` y los prefijos `__Host-`/`__Secure-`.
  **El valor nunca llega al informe**: la evidencia queda como
  `session=[OCULTO]; Secure; HttpOnly`.
- **CORS**: además de leer las cabeceras, se repite la petición con un `Origin`
  inventado (`https://atalaya-sonda.invalid`) para ver si el servidor lo refleja.

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

`run` también puede devolver un `ScanOutput` con la cobertura. `Coverage`
envuelve cada comprobación y, si una revienta, la marca como sin determinar
en vez de tumbar el análisis:

```python
from ..core.module import Coverage

    def run(self, inputs: MiInput):
        cov = Coverage()
        findings = cov.run("algo", "Comprobación de algo", lambda: self._check_algo(inputs))
        if not inputs.profundo:
            cov.skipped("profundo", "Análisis exhaustivo", "Desactivado")
        return cov.output(findings)
```

Y ya está disponible:

```bash
atalaya mi-modulo objetivo.com --profundo
```

## Arquitectura

```
atalaya/
├── core/
│   ├── finding.py     Severity, Finding, ScanResult (estado, cobertura y nota)
│   ├── module.py      metadatos compartidos, ScanModule y Coverage
│   ├── service.py     ServiceModule, eventos y snapshots de ventana
│   ├── registry.py    descubrimiento automático de módulos
│   └── report.py      renderizado a terminal, JSON y HTML
├── modules/           una herramienta por archivo
│   └── _secret_rules.py   catálogo de reglas (el guion bajo lo excluye del registro)
├── services/          SSH, persistencia y panel privado autocontenido
└── cli.py             subcomandos generados desde el registro
```

## Aviso

Los módulos de análisis inspeccionan objetivos desde fuera, sin explotarlos;
el honeypot escucha y almacena eventos en el equipo del operador.
**Úsalo solo sobre sistemas de tu propiedad o para los que tengas permiso
por escrito**. Escanear infraestructura ajena sin autorización es ilegal en la
mayoría de las jurisdicciones.

## Licencia

MIT
