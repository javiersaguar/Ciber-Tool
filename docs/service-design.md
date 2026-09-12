# Servicios y honeypot SSH

## Dos contratos, una identidad

`ModuleDescriptor` reúne id, nombre, descripción, categoría, `InputModel`,
validación, JSON Schema y ficha. Sus dos hijas son **hermanas**:

| Contrato | Ejecución | Resultado |
|---|---|---|
| `ScanModule` | `run(inputs)` síncrono; `scan` mide y captura errores | `list[Finding]` → `ScanResult` cerrado |
| `ServiceModule` | `async run(inputs, context)` hasta `context.stop` | `ServiceEvent` durante la ejecución; snapshots de `ScanResult` |

No se simula un escaneo que nunca devuelve. El registro usa el mismo `pkgutil`
y el mismo espacio de ids para ambas bases; descarta clases abstractas e imports
indirectos como antes. `atalaya list` distingue el tipo; los parámetros siguen
saliendo del modelo. La CLI elige el adaptador por contrato. Los tres escáneres,
su método `scan`, los renderizadores y la semántica de sus opciones permanecen
compatibles. `run` es invocable en ambos contratos, pero no intercambiable.

## Eventos e informes finitos

Cada ejecución tiene su propio `ServiceContext`: parada, disponibilidad, bus y
ventana. Un `ServiceEvent` lleva tipo, fecha UTC, datos y un `Finding` opcional.
El bus es en vivo, sin replay: máximo 16 suscriptores de 128 eventos; si uno se
retrasa pierde los más antiguos y el informe registra la pérdida. Los hallazgos
tienen límite de 1.000 y caducan por ventana. Un snapshot es una copia independiente.

El honeypot registra primero en SQLite, en un worker único, y después emite.
Detecta por defecto **400 contraseñas distintas por IP en 120 segundos**, con un
único hallazgo HIGH por IP durante la ventana de informe (300 s por defecto).
Las alertas vigentes se restauran al reiniciar. El reloj es UTC del VPS: requiere
sincronización; no es una prueba forense de tiempos ni de identidad del atacante.

`/api/report` y la descarga del panel exportan la ventana actual. Al llegar a
`--duration`, Ctrl+C o SIGTERM se cierran sockets, se drena la cola y se emite
un informe con los formatos existentes. Códigos: 0 normal, 1 error, 2 hallazgos
que alcanzan `--fallar-en`. **Un proceso vivo no tiene código de salida**: para
automatización periódica se toma un snapshot. La nota representa actividad de
esa ventana, no seguridad del VPS. A+ sin observaciones no certifica nada; un
honeypot que atrae ataques no está por ello mal configurado.

## Credenciales: decisión deliberada

No se persiste texto claro, cifrado reversible, fragmentos ni longitudes de
contraseñas. Tampoco usuarios en claro: pueden identificar a víctimas. Se
guardan HMAC-SHA-256 separados por dominio para usuario, contraseña y pareja,
con clave aleatoria local de 256 bits y derivación diaria UTC. El ranking muestra
identificadores (12 hex en pantalla; 64 en el API), frecuencia y día. Se renuncia
deliberadamente a un ranking de contraseñas legibles: no hace falta convertir el
señuelo en otra colección de credenciales filtradas.

Un SHA-256 sin clave sería comprobable mediante diccionarios. Un hash lento con
sal distinta por registro impediría agrupar y daría al bot una palanca de coste
computacional. El HMAC permite agrupar sin conservar valores recuperables, pero
**no anonimiza**: filtrar también `hmac.key` permite ataques de diccionario. La
rotación diaria limita la correlación accidental; no ofrece secreto hacia atrás
si se roba la clave maestra. La detección reinicia su ventana a medianoche para
no contar dos veces una clave que cambie de seudónimo.

Se retienen IP real del socket, UTC, versión declarada del cliente (no confiable),
UUID del evento y huella HMAC diaria de IP + usuario + contraseña + cliente. Esta
huella agrupa intentos iguales, **no es HASSH ni atribuye al bot una identidad**.
La IP y los seudónimos son datos sensibles. Clave, token y clave de host se guardan
en archivos separados de la base. Retención por defecto: 24 h o 50.000 intentos,
lo que llegue antes. El purgado funciona también sin tráfico y al arrancar;
estando apagado no puede ejecutarse. Los informes exportados tienen su propia
vida útil, fuera del control del servicio.

Python y AsyncSSH necesitan temporalmente la contraseña para procesar SSH; no
se promete borrado seguro de RAM. No activar trazas de paquetes, volcados de
memoria ni copias indiscriminadas del directorio. SQLite usa `secure_delete` y
journal DELETE; eso no garantiza borrado físico en SSD, snapshots o backups.

## Límites y compromisos de red

Admisión TCP antes del banner/KEX: 64 conexiones, 3/IP, 20 altas/s globales y
5/IP/s. Por conexión: 15 s totales, 6 contraseñas, demora de 250 ms, 128 KiB de
entrada y 64 KiB de salida. Usuario/contraseña limitados a 256/1.024 caracteres.
Una cola de persistencia de 1.024 eventos se llena con descarte contado y cierre
de la conexión; un fallo de disco detiene el servicio. SQLite limita sus páginas
a 256 MiB (página estándar de 4 KiB); su journal necesita margen adicional.

Se usa la API pública [`run_server`](https://asyncssh.readthedocs.io/en/stable/api.html#asyncssh.run_server)
de AsyncSSH sobre un **socketpair fijo local**. Dos copias acotadas controlan los
bytes antes del parser, incluso si el bot declara paquetes enormes. No aceptan
destinos del cliente. Se paga ese coste de sockets/copias por evitar depender de
atributos internos del parser. TCP evita reflexión UDP; los presupuestos limitan
respuestas y renegociaciones, pero no garantizan resistir un DDoS volumétrico.

Siempre se exige autenticación y siempre falla. Se desactivan los demás métodos,
PTY, agente, X11 y compresión; todos los handlers de sesión, TCP, UNIX, TUN/TAP y
listeners devuelven `False`. No hay shell, ejecutor, SFTP, resolución inversa ni
conexiones a destinos de red. El panel sólo admite loopback, token Bearer,
Host/Origin exactos, CSP y texto DOM seguro. Sus cuatro SSE como máximo envían
snapshots cada segundo; no son una cola de todos los eventos.

El mapa usa una base City `.mmdb` del operador, sin APIs ni teselas externas.
Sin base o sin ubicación muestra ese estado, sin inventar puntos. Una IP puede
ser NAT, proxy o máquina comprometida; [la geolocalización es aproximada](https://support.maxmind.com/knowledge-base/articles/maxmind-geolocation-accuracy).
Se acepta menor cobertura de bots antiguos al conservar criptografía moderna.
Muchos IPs, rotación IPv6 o fallos de librería exigen aislamiento del VPS y
controles del sistema; véase [despliegue](honeypot-operations.md).
