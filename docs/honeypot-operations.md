# Ejecutar y desplegar el honeypot

## Prueba local en Windows 11

Desde el repositorio:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m atalaya list
.\.venv\Scripts\python.exe -m atalaya ssh-honeypot
```

Escucha SSH en `127.0.0.1:2222`, panel en `http://127.0.0.1:8080`.
Lee el token y pégalo en el formulario del panel:

```powershell
Get-Content .atalaya-honeypot\dashboard.token
```

En otra terminal, una prueba manual pide contraseña y siempre termina denegada:

```powershell
ssh -p 2222 -o PreferredAuthentications=password -o PubkeyAuthentication=no prueba@127.0.0.1
```

Usa credenciales inventadas para las pruebas. Para bajar el umbral de alerta:
`--alert-threshold 3`. Para una ejecución finita con informe:

```powershell
.\.venv\Scripts\python.exe -m atalaya ssh-honeypot --duration 60 --formato json --salida ventana.json
```

La CLI conserva `app(windows_expand_args=False)` y el escritor UTF-8; el anuncio
del servicio y su panel va a stderr para mantener stdout como JSON válido.
La interfaz muestra sólo datos retenidos: 50 últimos eventos, 15 parejas más
repetidas, 100 IPs más activas y 60 minutos de evolución. Al perder conexión
borra los datos visibles y permite reconectar con el token. No guarda el token
en URL, cookies ni almacenamiento del navegador.

## VPS Linux sin root para Python

Usa una cuenta dedicada y el puerto **2222**; el modelo rechaza puertos menores
de 1024. No concedas capabilities al intérprete Python. Si necesitas que los
bots lleguen al 22, un administrador puede configurar una redirección **en el
firewall** de la IP/interfaz exclusiva del señuelo, `22 → 2222`, que conserve
la IP de origen. Antes debe separar el SSH administrativo en otra IP/puerto o
red privada. No aplicar una regla global que intercepte el acceso administrativo.
El puerto 2222 público es la alternativa que no requiere esa redirección.

1. Instala el repositorio y venv en `/opt/atalaya` para la cuenta del servicio.
2. Crea la cuenta `atalaya-honeypot`, sin login ni pertenencia a grupos sensibles.
3. Ajusta y coloca [la unidad incluida](../deploy/atalaya-honeypot.service) en
   `/etc/systemd/system/`; `StateDirectory` crea `/var/lib/atalaya-honeypot`.
4. El administrador habilita el puerto del señuelo en el firewall. Mantiene
   8080 cerrado al exterior y aplica límites de SYN/conexiones en el proveedor.
5. Revisa la unidad con `systemd-analyze verify`, y después arranca con
   `systemctl enable --now atalaya-honeypot`. Parar con `systemctl stop` emite
   `/var/lib/atalaya-honeypot/last-window.json`. Un corte de corriente/SIGKILL
   puede perder eventos pendientes (máximo cola + lote en curso).

El ejemplo aplica usuario dedicado, capacidades vacías, filesystem protegido,
límites de CPU/RAM/descriptores y **deniega `connect()`** por seccomp. El servicio
Linux sólo acepta conexiones y usa `socketpair`; no necesita iniciar ninguna
conexión, ni siquiera al panel. Esta barrera debe probarse en la distribución
del VPS. Como defensa adicional, usa una red aislada con salida nueva bloqueada
y retorno de conexiones establecidas permitido; sin rutas hacia redes internas,
metadatos cloud ni credenciales del proveedor en el proceso.

Accede al panel desde Windows mediante **el SSH administrativo**, nunca mediante
el honeypot. Conserva el mismo puerto local/remoto por la validación de Host:

```powershell
ssh -N -L 127.0.0.1:8080:127.0.0.1:8080 administrador@IP-ADMINISTRATIVA
```

Abre `http://127.0.0.1:8080`, y obtén `dashboard.token` por el canal administrativo.
El HTTP es sólo loopback dentro del túnel cifrado. No configurar un proxy público
para el panel; no hay modo de escucha público. Para IPv6 usa una instancia con
`--host ::`; la escucha es sólo IPv6. Para dos instancias, separa directorios y
puertos de panel.

## Mapa, claves y operación

- Obtén legalmente una base GeoLite2/GeoIP2 **City** `.mmdb`, manténla actualizada
  fuera del proceso y arranca con `--geoip-db /ruta/GeoLite2-City.mmdb`. La app
  no descarga bases ni incluye datos de terceros. Muestra radio de precisión
  al señalar un punto; IPs privadas o sin registro quedan sin ubicación.
- En POSIX el directorio debe ser 0700 y los archivos 0600. En Windows los
  directorios nuevos pierden herencia y conceden acceso sólo a la cuenta actual;
  para un directorio preexistente el operador debe restringir su ACL. `chmod`
  en Windows no sustituye la ACL. No guardar estado en un recurso compartido.
- `hmac.key`, `dashboard.token` y `ssh_host_key` son distintos; no publicar ni
  copiar junto con la base. Se excluyen por `.gitignore`. Una segunda instancia
  con el mismo directorio falla por un bloqueo del SO.
- Para rotar el token, para el servicio, elimina sólo `dashboard.token` y
  reinicia. Para reiniciar la correlación de credenciales utiliza un nuevo
  directorio privado; gestiona la eliminación del anterior según la retención
  de tus backups. Rotar el host key cambia la huella SSH que ven los clientes.
- Un error muestra un tipo/motivo seguro, sin el texto de excepciones que pueda
  incluir datos del atacante. Comprueba puertos ocupados, ACL, `.mmdb`, integridad
  de claves y espacio en disco. Los descartes y rechazos se cuentan en panel e
  informe; los contadores de transporte reinician con el proceso.
- Un snapshot consulta los hallazgos vigentes; los informes exportados no se
  purgan automáticamente. La nota puede subir al caducar una alerta. El ejemplo
  systemd considera 2 una parada válida para evitar reinicios por hallazgos.

## Validación

```powershell
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m pytest
```

CI queda configurada para Python 3.10, 3.11 y 3.12 en Linux y Windows.
Validación local: Windows con Python 3.10 y 3.12, **260 pasan y 1 se omite**
(SIGTERM exclusivo de Linux); Linux/WSL con Python 3.14, **261 pasan**. Ruff,
formato y sintaxis JavaScript limpios; wheel construido con los recursos del panel.
La sintaxis de systemd se verificó sustituyendo únicamente la ruta del ejecutable
por el venv local de pruebas; la unidad no se ha instalado en ningún VPS.

Las pruebas nuevas usan SSH
y HTTP reales en loopback, SQLite temporal y credenciales ficticias. No atacan
equipos externos. La copia inicial del repositorio tenía **202 tests**, no 242;
se mantienen íntegros, sin modificar los archivos existentes de pruebas.
