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
| `tcp-ports` | recon | Reconocimiento activo de puertos TCP abiertos en un único host (IPv4/IPv6). |
| `web-paths` | web | Descubre rutas web y posibles archivos de entorno o metadatos Git expuestos. |
| `subdomains` | recon | Resuelve candidatos DNS A/AAAA, con controles de wildcard y cobertura por nombre. |
| `services` | recon | Identifica protocolos por respuestas reales y separa la confianza del protocolo de la versión anunciada. |
| `web-crawl` | web | Rastrea HTML dentro del origen y ruta base; descubre formularios, parámetros y referencias sin enviarlos. |

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
atalaya tcp-ports 127.0.0.1 --ports "22,80,443,8000-8010"
atalaya web-paths http://127.0.0.1:8000
atalaya subdomains mi-dominio.example
atalaya services 127.0.0.1 --ports "22,80,443"
atalaya web-crawl http://127.0.0.1:8000 --max-pages 25
atalaya audit https://mi-dominio.example --formato html --salida auditoria.html
atalaya history list
```

Si el ejecutable no estuviera disponible, todo funciona igual con `python -m atalaya`.

Informes en otros formatos:

```bash
atalaya http-headers ejemplo.com --formato json
atalaya tls ejemplo.com --formato html --salida informe.html
```

### Auditoría conjunta e historial

`atalaya audit` ejecuta HTTP, TLS, puertos TCP, identificación de servicios,
descubrimiento de rutas y rastreo HTML. El progreso va a stderr y el JSON a stdout.
Cada módulo conserva sus hallazgos, estado y cobertura; no se mezclan las notas
de módulos distintos para inventar una puntuación global.

```bash
atalaya audit https://mi-dominio.example --formato html --salida auditoria.html
atalaya audit https://mi-dominio.example --modules "http-headers,tls,subdomains"
atalaya audit http://127.0.0.1:8000 --modules "services,web-paths,web-crawl" --ports "8000" --no-save
atalaya history list --json
atalaya history show ID --formato html --salida auditoria.html
atalaya history compare ID_ANTERIOR ID_ACTUAL --formato json
```

Por defecto se guardan las auditorías en `.atalaya/history/history.sqlite3`,
excluido de Git. `--history-dir` cambia la ubicación y `--no-save` evita guardar
y comparar esa ejecución. No se envía el historial a ningún servicio externo.
Cada ejecución se compara automáticamente con la última del mismo objetivo y
la misma configuración. Cambiar módulos, puertos o presupuestos crea una serie
distinta. Los identificadores completos se consultan con `history list`.

La evolución distingue hallazgos **nuevos, cambiados, resueltos, sin verificar y
sin cambios**. Un hallazgo ausente solo se marca resuelto si su módulo terminó
completamente. Si la ejecución fue parcial, queda sin verificar y se conserva
como referencia para las siguientes comparaciones. Los cambios en evidencia
volátil no generan hallazgos nuevos; las observaciones estructuradas, como una
versión anunciada distinta, sí aparecen como cambios.

Con una URL HTTP se omite TLS; no se presupone que su puerto hable HTTPS.
Los módulos de red analizan el host declarado. Los subdominios descubiertos no
se escanean automáticamente y DNS se añade explícitamente con `--modules`.
Los códigos de salida siguen la prioridad error (1), hallazgos por encima del
umbral (2), cobertura incompleta (3) y ejecución completa sin esos hallazgos (0).

### Subdominios, servicios y superficie web

```bash
atalaya subdomains mi-dominio.example --wordlist nombres.txt --concurrency 4
atalaya services mi-servidor.example --ports "22,25,80,443,8443"
atalaya services 127.0.0.1 --ports "9000" --http-ports "9000"
atalaya services mi-servidor.example --ports "9443" --tls-ports "9443"
atalaya web-crawl https://mi-web.example/app/ --max-pages 25 --max-depth 2 --rate 2
```

`subdomains` consulta A y AAAA usando los resolutores del sistema y dnspython,
con tiempos acotados. Lleva 20 prefijos habituales y admite un diccionario UTF-8
de hasta 256 prefijos y 64 KiB. Dos nombres aleatorios sirven como control de
wildcard. Si hay wildcard o el control no concluye, los positivos son candidatos
y quedan sin determinar. Un registro resuelto no prueba propiedad del activo.

`services` admite hasta 128 puertos. Lee como máximo 4 KiB de respuesta y reconoce
SSH, HTTP(S), SMTP, FTP, POP3 e IMAP. En los puertos HTTP declarados envía una
petición HEAD; en los demás espera un saludo. `--tls-ports` negocia TLS para
identificar el servicio, **sin evaluar la confianza del certificado**: para eso
está `tls`. Los protocolos se confirman por su respuesta, nunca por el número
de puerto. La versión es la anunciada por el servidor, no una confirmación de
vulnerabilidades. Un servicio silencioso o desconocido queda sin determinar.

`web-crawl` usa GET sin credenciales y sin ejecutar JavaScript. Se limita al mismo
esquema, host, puerto y prefijo de ruta. Sigue enlaces HTML hasta la profundidad
pedida; admite hasta 100 peticiones y lee como máximo 128 KiB por respuesta.
Las redirecciones se revisan antes de seguirlas. No envía formularios ni conserva
sus valores o los valores de query; recoge nombres de campos y parámetros.
Las referencias a scripts e iframes se incluyen en el inventario sin ejecutarlas. Ignora rutas
con segmentos como logout, delete o reset. Ante HTTP 429/503 detiene el rastreo.
Los límites agotados y errores pendientes impiden dar una nota final.

### Informes y observatorio

Los informes HTML son autocontenidos y funcionan sin conexión. Incluyen resumen,
navegación por módulos, búsqueda en títulos/evidencias/soluciones, filtros de
gravedad y módulo, tema claro/oscuro y vista de impresión/PDF. Los resultados de
reconocimiento se muestran también en terminal, aunque sean informativos.

El observatorio SSH conserva el token solo en memoria y ofrece búsqueda en los
últimos intentos, filtro de gravedad, pausa de la vista y tema claro/oscuro.
Pausar no detiene el servicio ni la persistencia; al reanudar se muestra el
último snapshot. La exportación corresponde al snapshot que se está viendo.

### Reconocimiento activo: puertos TCP y rutas web

Estos dos módulos sirven como punto de partida para un pentest autorizado:
identifican servicios alcanzables y recursos web que merecen revisión.
No requieren Nmap, permisos de administrador ni dependencias nuevas.

```bash
atalaya tcp-ports mi-servidor.example --ports "1-1024" --concurrency 16 --timeout 2
atalaya tcp-ports ::1 --ports "22,443" --formato json --salida puertos.json
atalaya web-paths https://mi-web.example --formato html --salida rutas.html
atalaya web-paths https://mi-web.example/app/ --wordlist rutas.txt --rate 3 --total-timeout 120
```

`tcp-ports` realiza conexiones TCP completas a 30 puertos habituales por defecto.
Acepta listas y rangos, hasta 4096 puertos y 64 conexiones simultáneas; no acepta
CIDR ni múltiples hosts. Resuelve el nombre una vez y analiza **solo la primera IP
resuelta**, indicada en el resumen. Puedes pasar una IP explícita para revisar
otras direcciones. Distingue conexiones abiertas, rechazos e intentos
indeterminados/no completados. Los nombres de servicio son orientativos por
número de puerto, sin identificar versiones ni confirmar protocolos. Un puerto
abierto se informa como `info`: no demuestra una vulnerabilidad.

`web-paths` prueba 12 rutas habituales: paneles, documentación de API, `robots.txt`,
`.git/HEAD`, `.env` y `backup.zip`. Puedes sustituirlas con un archivo UTF-8
de una ruta relativa por línea (líneas vacías y comentarios `#` se omiten).
Las rutas se añaden a la URL base; se rechazan traversal, URLs, queries y fragmentos.
El diccionario admite hasta 256 rutas únicas y 64 KiB.

Se envían dos peticiones iniciales a rutas aleatorias inexistentes para filtrar
respuestas comodín y errores 404 que devuelven HTTP 200. El filtro compara estado,
redirección y huella del cuerpo, normalizando la ruta reflejada; páginas dinámicas
pueden requerir revisión manual. Los HTTP 200/3xx/401/403 restantes se muestran
como **candidatos**, sin asumir que exista una vulnerabilidad. Solo se eleva a
`high` una respuesta 200 con firma de Git HEAD o de un posible archivo `.env`.
No se descargan otros objetos Git ni se prueban las credenciales detectadas.

Por defecto hay como máximo 4 peticiones simultáneas, 5 inicios de petición por
segundo y 60 segundos de ejecución. Ambos módulos aceptan `--total-timeout`.
Al agotarse el tiempo conservan los resultados completados y resumen lo pendiente.
El descubridor se detiene ante HTTP 429/503 (pueden terminar peticiones ya iniciadas),
verifica TLS, no usa proxies del entorno y **no sigue redirecciones**.
Lee como máximo 32 KiB por respuesta; los cuerpos, cookies y destinos de
redirección no se incorporan al informe. El resumen expone el alcance y los errores:
una nota A+ no certifica ausencia de vulnerabilidades ni cobertura completa.

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
