"""Auditoría de cabeceras HTTP de seguridad.

Pide una URL y evalúa las cabeceras de respuesta: HSTS, CSP, protección contra
clickjacking y sniffing de MIME, política de referente, CORS, atributos de las
cookies y fugas de información del servidor.

Cada cabecera se interpreta según su gramática (directivas, listas separadas
por comas, atributos de cookie) en lugar de buscar subcadenas: buscar
`frame-ancestors` o `secure` en el texto daba por buenas políticas que no
protegían nada.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import NamedTuple

import httpx
from pydantic import BaseModel, Field

from .. import __version__
from ..core.finding import Finding, FindingKind, ScanOutput, Severity
from ..core.module import Category, Coverage, ScanModule

# Seis meses, el mínimo que pide hstspreload.org para entrar en la lista.
HSTS_MIN_MAX_AGE = 15_768_000

# Origen inventado para la sonda de CORS. `.invalid` está reservado (RFC 2606),
# así que nunca puede ser un origen legítimo que el servidor tenga en su lista.
ORIGEN_SONDA = "https://atalaya-sonda.invalid"

_MAX_EVIDENCIA = 300

HARDENING = FindingKind.HARDENING
VULNERABILIDAD = FindingKind.VULNERABILITY


def _recorta(valor: str) -> str:
    valor = valor.strip()
    if len(valor) <= _MAX_EVIDENCIA:
        return valor
    return valor[:_MAX_EVIDENCIA] + "…"


# -- gramáticas de las cabeceras ---------------------------------------------

Politica = dict[str, list[str]]


def parse_csp(valor: str) -> list[Politica]:
    """Una cabecera CSP como lista de políticas `{directiva: [fuentes]}`.

    Varias cabeceras CSP llegan unidas por comas y el navegador aplica todas a
    la vez. Dentro de una política, si una directiva se repite solo cuenta la
    primera aparición, como manda la especificación.
    """
    politicas: list[Politica] = []
    for texto in valor.split(","):
        directivas: Politica = {}
        for trozo in texto.split(";"):
            tokens = trozo.split()
            if not tokens:
                continue
            nombre = tokens[0].lower()
            directivas.setdefault(nombre, tokens[1:])
        if directivas:
            politicas.append(directivas)
    return politicas


def _fuentes_de_scripts(politica: Politica) -> list[str] | None:
    """Las fuentes que gobiernan los scripts: script-src o, si falta, default-src."""
    if "script-src" in politica:
        return politica["script-src"]
    return politica.get("default-src")


_ESQUEMAS_ABIERTOS = {"http:", "https:", "data:", "blob:", "*"}
_PREFIJOS_HASH = ("'nonce-", "'sha256-", "'sha384-", "'sha512-")


def _es_comodin(fuente: str) -> bool:
    """`*`, un esquema suelto (`https:`) o un host comodín (`https://*`) admiten cualquier origen.

    `*.cdn.com` no lo es: restringe a los subdominios de cdn.com.
    """
    fuente = fuente.lower()
    if fuente in _ESQUEMAS_ABIERTOS:
        return True
    host = fuente.split("://", 1)[1] if "://" in fuente else fuente
    host = host.split("/", 1)[0]
    return host == "*" or host.startswith("*:")


def _debilidades_scripts(fuentes: list[str]) -> dict[str, str]:
    """Qué debilidades tiene una lista de fuentes de script, con la fuente que la causa.

    Respeta cómo el navegador neutraliza algunas: 'unsafe-inline' se ignora si
    hay nonce o hash, y 'strict-dynamic' ignora la lista de hosts y esquemas.
    """
    bajas = [f.lower() for f in fuentes]
    con_nonce = any(f.startswith(_PREFIJOS_HASH) for f in bajas)
    dinamica = "'strict-dynamic'" in bajas
    debilidades: dict[str, str] = {}
    if "'unsafe-inline'" in bajas and not con_nonce:
        debilidades["unsafe-inline"] = "'unsafe-inline'"
    if "'unsafe-eval'" in bajas:
        debilidades["unsafe-eval"] = "'unsafe-eval'"
    if not dinamica:
        comodin = next((f for f in fuentes if _es_comodin(f)), None)
        if comodin:
            debilidades["comodin"] = comodin
    return debilidades


def _valores_lista(valor: str) -> list[str]:
    """Separa una cabecera de lista (`a, b`), que es como llegan las repetidas."""
    return [v.strip() for v in valor.split(",") if v.strip()]


class Cookie(NamedTuple):
    nombre: str
    valor: str
    atributos: dict[str, str | None]
    """Atributos en minúsculas; si alguno se repite, gana el último (RFC 6265)."""
    crudos: list[tuple[str, str | None]]
    """Los atributos tal y como venían, en orden, para reconstruir la evidencia."""


def parse_cookie(cruda: str) -> Cookie:
    """Interpreta un Set-Cookie: el par nombre=valor y después sus atributos.

    Separarlo así es lo que evita que una cookie llamada `secure_session`, o
    con un valor que contenga `httponly`, pase por tener esos atributos.
    """
    par, *resto = cruda.split(";")
    nombre, igual, valor = par.partition("=")
    if not igual:  # RFC 6265bis: sin '=', todo es el valor y el nombre va vacío
        nombre, valor = "", par
    atributos: dict[str, str | None] = {}
    crudos: list[tuple[str, str | None]] = []
    for trozo in resto:
        clave, igual, v = trozo.partition("=")
        clave = clave.strip()
        if not clave:
            continue
        v_limpio = v.strip() if igual else None
        atributos[clave.lower()] = v_limpio
        crudos.append((clave, v_limpio))
    return Cookie(nombre.strip(), valor.strip(), atributos, crudos)


# Atributos cuyo valor se puede enseñar en un informe; el resto se oculta por si acaso.
_ATRIBUTOS_PUBLICOS = {
    "expires",
    "max-age",
    "domain",
    "path",
    "samesite",
    "priority",
    "secure",
    "httponly",
    "partitioned",
}

OCULTO = "[OCULTO]"


def cookie_redactada(cookie: Cookie) -> str:
    """La cookie lista para un informe: atributos visibles y el valor sustituido.

    El informe se exporta y se comparte, y el valor de una cookie de sesión
    es una credencial: con él se suplanta al usuario.
    """
    partes = [f"{cookie.nombre}={OCULTO if cookie.valor else ''}"]
    for clave, valor in cookie.crudos:
        if valor is None:
            partes.append(clave)
        elif clave.lower() in _ATRIBUTOS_PUBLICOS:
            partes.append(f"{clave}={valor}")
        else:
            partes.append(f"{clave}={OCULTO}")
    return "; ".join(partes)


def _cookie_se_borra(cookie: Cookie) -> bool:
    """Las cookies vacías o ya caducadas solo sirven para borrar otra; no guardan nada."""
    if not cookie.valor:
        return True
    max_age = cookie.atributos.get("max-age")
    if max_age is not None and re.fullmatch(r"-?\d+", max_age) and int(max_age) <= 0:
        return True
    expires = cookie.atributos.get("expires")
    if expires and max_age is None:
        try:
            fecha = parsedate_to_datetime(expires)
        except (TypeError, ValueError):
            return False
        if fecha.tzinfo is None:
            fecha = fecha.replace(tzinfo=timezone.utc)
        return fecha < datetime.now(timezone.utc)
    return False


_REFERRER_VALIDAS = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
}


# -- módulo ------------------------------------------------------------------


class HttpHeadersInput(BaseModel):
    """Entradas del módulo. De aquí salen los argumentos de la CLI y el formulario web."""

    url: str = Field(description="URL a auditar. Si omites el esquema se asume https://")
    timeout: float = Field(default=10.0, gt=0, description="Segundos de espera por petición.")
    follow_redirects: bool = Field(
        default=True, description="Seguir redirecciones hasta la respuesta final."
    )
    probe_cors: bool = Field(
        default=True,
        description=(
            "Repetir la petición con un Origin ajeno para ver si el servidor lo refleja en CORS."
        ),
    )
    # Las cabeceras HTTP no admiten caracteres fuera de ASCII, así que el valor
    # por defecto va sin tildes a propósito.
    user_agent: str = Field(
        default=f"Atalaya/{__version__} (+https://github.com/javiersaguar/Ciber-Tool)",
        description="Cabecera User-Agent a enviar (solo ASCII).",
    )


class HttpHeadersModule(ScanModule):
    id = "http-headers"
    name = "Auditor de cabeceras HTTP"
    description = (
        "Evalúa las cabeceras de seguridad de una respuesta HTTP (HSTS, CSP, "
        "X-Frame-Options, cookies...) y emite una nota de A+ a F."
    )
    category = Category.WEB
    InputModel = HttpHeadersInput

    def run(self, inputs: HttpHeadersInput) -> ScanOutput:  # type: ignore[override]
        url = inputs.url if "://" in inputs.url else f"https://{inputs.url}"
        cov = Coverage()
        findings: list[Finding] = []

        with httpx.Client(
            timeout=inputs.timeout,
            follow_redirects=inputs.follow_redirects,
            headers={"User-Agent": inputs.user_agent},
        ) as client:
            # Si la petición principal falla no hay nada que evaluar: la
            # excepción sube y el resultado queda como no evaluado.
            response = client.get(url)

            headers = {k.lower(): v for k, v in response.headers.items()}
            es_https = response.url.scheme == "https"

            # Cada comprobación va aislada: si una revienta, queda como pendiente
            # en la cobertura y el resto del análisis sigue.
            de_cabeceras = [
                ("csp", "Content-Security-Policy", self._check_csp),
                ("clickjacking", "Protección contra clickjacking", self._check_frame_options),
                ("nosniff", "X-Content-Type-Options", self._check_content_type_options),
                ("referrer", "Referrer-Policy", self._check_referrer_policy),
                ("permissions", "Permissions-Policy", self._check_permissions_policy),
                ("cors", "Cabeceras CORS", self._check_cors),
                ("xss-legacy", "X-XSS-Protection", self._check_legacy_xss),
                ("info-leak", "Versiones expuestas", self._check_info_leak),
            ]
            findings += cov.run(
                "https", "Uso de HTTPS", lambda: self._check_https(response, es_https)
            )
            findings += cov.run(
                "hsts", "Strict-Transport-Security", lambda: self._check_hsts(headers, es_https)
            )
            for check_id, nombre, check in de_cabeceras:
                findings += cov.run(check_id, nombre, lambda check=check: check(headers))
            findings += cov.run(
                "cookies",
                "Atributos de las cookies",
                lambda: self._check_cookies(response, es_https),
            )

            if inputs.probe_cors:
                findings += self._sonda_cors(client, str(response.url), cov)
            else:
                cov.skipped(
                    "cors-reflejo", "Reflejo de Origin en CORS", "Desactivada (--no-probe-cors)"
                )

        return cov.output(findings)

    # -- comprobaciones ---------------------------------------------------

    def _check_https(self, response: httpx.Response, es_https: bool) -> list[Finding]:
        if not es_https:
            return [
                Finding(
                    severity=Severity.HIGH,
                    kind=VULNERABILIDAD,
                    title="El sitio no sirve por HTTPS",
                    description=(
                        "Todo el tráfico viaja en claro: es legible y modificable por "
                        "cualquiera en la ruta de red."
                    ),
                    evidence=f"URL final: {response.url}",
                    remediation=(
                        "Instala un certificado TLS y redirige todo el tráfico HTTP a HTTPS."
                    ),
                    references=["https://letsencrypt.org/"],
                )
            ]

        redirigido = str(response.url) != str(response.request.url)
        if redirigido and response.history:
            origen = str(response.history[0].url)
            if origen.startswith("http://"):
                return [
                    Finding(
                        severity=Severity.OK,
                        title="HTTP redirige correctamente a HTTPS",
                        evidence=f"{origen} → {response.url}",
                    )
                ]
        return [Finding(severity=Severity.OK, title="El sitio se sirve por HTTPS")]

    def _check_hsts(self, headers: dict[str, str], es_https: bool) -> list[Finding]:
        if not es_https:
            return []  # HSTS se ignora sobre HTTP; ya se ha reportado la falta de TLS.

        crudo = headers.get("strict-transport-security", "").strip()
        if not crudo:
            return [
                Finding(
                    severity=Severity.HIGH,
                    kind=HARDENING,
                    title="Falta Strict-Transport-Security (HSTS)",
                    description=(
                        "Sin HSTS, la primera visita de cada usuario puede ser degradada "
                        "a HTTP por un atacante en la red (ataque de SSL stripping)."
                    ),
                    remediation=(
                        "Añade: Strict-Transport-Security: max-age=31536000; includeSubDomains"
                    ),
                    references=[
                        "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"
                    ],
                )
            ]

        # Con la cabecera repetida, el navegador solo atiende a la primera (RFC 6797).
        valor = crudo.split(",", 1)[0]
        directivas: dict[str, str] = {}
        duplicada = False
        for trozo in valor.split(";"):
            nombre, _, v = trozo.strip().partition("=")
            nombre = nombre.strip().lower()
            if not nombre:
                continue
            if nombre in directivas:
                duplicada = True
            directivas[nombre] = v.strip().strip('"')

        max_age_txt = directivas.get("max-age", "")
        if duplicada or not max_age_txt.isdigit():
            return [
                Finding(
                    severity=Severity.HIGH,
                    kind=HARDENING,
                    title="Cabecera HSTS no válida",
                    description=(
                        "Sin un max-age numérico, o con directivas repetidas, el navegador "
                        "descarta la cabecera entera: es como no tener HSTS."
                    ),
                    evidence=_recorta(crudo),
                    remediation=(
                        "Usa: Strict-Transport-Security: max-age=31536000; includeSubDomains"
                    ),
                )
            ]

        findings: list[Finding] = []
        max_age = int(max_age_txt)
        if max_age == 0:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    kind=HARDENING,
                    title="HSTS presente pero desactivado (max-age=0)",
                    description="Un max-age de 0 le dice al navegador que olvide la política.",
                    evidence=_recorta(crudo),
                    remediation="Sube max-age a 31536000 (un año).",
                )
            )
        elif max_age < HSTS_MIN_MAX_AGE:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    kind=HARDENING,
                    title="El max-age de HSTS es demasiado corto",
                    description=(
                        f"Son {max_age} segundos ({max_age // 86400} días). Por debajo de "
                        "seis meses la protección se pierde entre visitas espaciadas."
                    ),
                    evidence=_recorta(crudo),
                    remediation="Usa al menos max-age=15768000; lo habitual es 31536000.",
                )
            )
        else:
            findings.append(
                Finding(
                    severity=Severity.OK,
                    title="HSTS configurado con un max-age adecuado",
                    evidence=_recorta(crudo),
                )
            )

        if max_age and "includesubdomains" not in directivas:
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    kind=HARDENING,
                    title="HSTS no cubre los subdominios",
                    description=(
                        "Sin includeSubDomains, un subdominio servido por HTTP sigue "
                        "siendo un punto de entrada para robar cookies de sesión."
                    ),
                    evidence=_recorta(crudo),
                    remediation="Añade includeSubDomains si controlas todos los subdominios.",
                )
            )
        return findings

    def _check_csp(self, headers: dict[str, str]) -> list[Finding]:
        valor = headers.get("content-security-policy", "")
        solo_informe = headers.get("content-security-policy-report-only")
        politicas = parse_csp(valor)

        if not politicas:
            if solo_informe:
                return [
                    Finding(
                        severity=Severity.MEDIUM,
                        kind=HARDENING,
                        title="La CSP está solo en modo informe",
                        description=(
                            "Content-Security-Policy-Report-Only registra violaciones "
                            "pero no bloquea nada, así que hoy no protege."
                        ),
                        evidence=_recorta(solo_informe),
                        remediation=(
                            "Cuando el informe esté limpio, pasa la política a "
                            "Content-Security-Policy."
                        ),
                    )
                ]
            return [
                Finding(
                    severity=Severity.HIGH,
                    kind=HARDENING,
                    title="Falta Content-Security-Policy",
                    description=(
                        "La CSP es la defensa más eficaz contra XSS: sin ella, cualquier "
                        "script inyectado en la página se ejecuta sin restricción."
                    ),
                    remediation=(
                        "Empieza por default-src 'self'; object-src 'none'; base-uri 'self' "
                        "y ve afinando con el modo report-only."
                    ),
                    references=["https://developer.mozilla.org/docs/Web/HTTP/CSP"],
                )
            ]

        findings: list[Finding] = []

        # El navegador aplica todas las políticas: un script solo carga si lo
        # permiten todas. Una debilidad cuenta solo si la tienen todas las que
        # restringen scripts; las que no los restringen no añaden nada.
        listas = [f for f in (_fuentes_de_scripts(p) for p in politicas) if f is not None]
        if not listas:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    kind=HARDENING,
                    title="La CSP no define default-src ni script-src",
                    description="Sin ninguna de las dos, la carga de scripts queda sin restringir.",
                    evidence=_recorta(valor),
                    remediation="Añade al menos default-src 'self'.",
                )
            )
        else:
            por_lista = [_debilidades_scripts(f) for f in listas]
            comunes = set.intersection(*(set(d) for d in por_lista))
            fuente_scripts = " ".join(listas[0])

            if "unsafe-inline" in comunes:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        kind=HARDENING,
                        title="La CSP permite scripts en línea ('unsafe-inline')",
                        description=(
                            "Sin nonce ni hash que lo neutralice, permitir scripts en línea "
                            "anula buena parte de la protección contra XSS que aporta la CSP."
                        ),
                        evidence=_recorta(f"script-src/default-src: {fuente_scripts}"),
                        remediation="Sustitúyelo por nonces ('nonce-...') o hashes por script.",
                    )
                )
            if "unsafe-eval" in comunes:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        kind=HARDENING,
                        title="La CSP permite 'unsafe-eval'",
                        description=(
                            "Habilita eval() y equivalentes, una vía clásica de ejecución "
                            "de código."
                        ),
                        evidence=_recorta(f"script-src/default-src: {fuente_scripts}"),
                        remediation=(
                            "Elimina las dependencias que necesiten eval y quita la directiva."
                        ),
                    )
                )
            if "comodin" in comunes:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        kind=HARDENING,
                        title="La CSP admite scripts de cualquier origen",
                        description=(
                            f"La fuente {por_lista[0]['comodin']} en script-src/default-src "
                            "deja cargar scripts de cualquier sitio, así que la política no "
                            "frena un XSS."
                        ),
                        evidence=_recorta(f"script-src/default-src: {fuente_scripts}"),
                        remediation=(
                            "Enumera los orígenes concretos o usa nonces con 'strict-dynamic'."
                        ),
                    )
                )

        if not any("object-src" in p or "default-src" in p for p in politicas):
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    kind=HARDENING,
                    title="La CSP no restringe object-src",
                    description=(
                        "Sin object-src ni default-src, <object> y <embed> pueden cargar "
                        "contenido activo de cualquier origen."
                    ),
                    remediation="Añade object-src 'none'.",
                )
            )

        # base-uri no hereda de default-src: hay que declararlo aparte.
        if not any("base-uri" in p for p in politicas):
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    kind=HARDENING,
                    title="La CSP no define base-uri",
                    description=(
                        "Sin base-uri, un atacante que logre inyectar una etiqueta <base> "
                        "puede redirigir las rutas relativas de la página."
                    ),
                    remediation="Añade base-uri 'self'.",
                )
            )

        if not findings:
            findings.append(
                Finding(
                    severity=Severity.OK,
                    title="CSP presente y sin patrones peligrosos evidentes",
                    evidence=_recorta(valor),
                )
            )
        return findings

    def _check_frame_options(self, headers: dict[str, str]) -> list[Finding]:
        xfo = headers.get("x-frame-options", "").strip()
        politicas = parse_csp(headers.get("content-security-policy", ""))
        ancestros = [p["frame-ancestors"] for p in politicas if "frame-ancestors" in p]

        # Con frame-ancestors en la CSP, el navegador ignora X-Frame-Options:
        # manda la CSP aunque sea más permisiva.
        if ancestros:
            restrictivas = [a for a in ancestros if not any(_es_comodin(f) for f in a)]
            if not restrictivas:
                abierta = " ".join(ancestros[0]) or "(vacía)"
                return [
                    Finding(
                        severity=Severity.MEDIUM,
                        kind=HARDENING,
                        title="frame-ancestors permite incrustar la página en cualquier sitio",
                        description=(
                            "La directiva existe pero admite cualquier origen, así que no "
                            "protege contra clickjacking. Y como está presente, el navegador "
                            "ignora X-Frame-Options aunque lo hayas puesto."
                        ),
                        evidence=_recorta(f"frame-ancestors {abierta}"),
                        remediation=(
                            "Usa frame-ancestors 'none', 'self' o la lista concreta de "
                            "orígenes que deban poder incrustarla."
                        ),
                        references=["https://owasp.org/www-community/attacks/Clickjacking"],
                    )
                ]
            # Varias políticas se suman: basta con que una restrinja.
            fuentes = min(restrictivas, key=len)
            bajas = [f.lower() for f in fuentes]
            if not fuentes or bajas == ["'none'"]:
                titulo = "Protegido contra clickjacking: frame-ancestors 'none'"
            elif bajas == ["'self'"]:
                titulo = "Protegido contra clickjacking: solo el propio origen puede incrustarla"
            else:
                titulo = "Protegido contra clickjacking: frame-ancestors limita los orígenes"
            # Una directiva sin fuentes equivale a 'none'.
            mostradas = " ".join(fuentes) or "'none'"
            return [
                Finding(
                    severity=Severity.OK,
                    title=titulo,
                    evidence=_recorta(f"frame-ancestors {mostradas}"),
                )
            ]

        if not xfo:
            return [
                Finding(
                    severity=Severity.MEDIUM,
                    kind=HARDENING,
                    title="Sin protección contra clickjacking",
                    description=(
                        "No hay X-Frame-Options ni frame-ancestors en la CSP: la página "
                        "puede incrustarse en un iframe ajeno para engañar al usuario."
                    ),
                    remediation="Añade Content-Security-Policy: frame-ancestors 'none' (o 'self').",
                    references=["https://owasp.org/www-community/attacks/Clickjacking"],
                )
            ]

        valores = {v.upper() for v in _valores_lista(xfo)}
        if len(valores) != 1 or not valores <= {"DENY", "SAMEORIGIN"}:
            motivo = (
                "Hay valores contradictorios (cabecera repetida) y el navegador la descarta."
                if len(valores) > 1
                else "Los navegadores solo reconocen DENY y SAMEORIGIN; ALLOW-FROM "
                "está obsoleto y se ignora."
            )
            return [
                Finding(
                    severity=Severity.MEDIUM,
                    kind=HARDENING,
                    title="Valor de X-Frame-Options no válido",
                    description=motivo,
                    evidence=f"X-Frame-Options: {xfo}",
                    remediation="Usa frame-ancestors en la CSP, que sí admite listas de orígenes.",
                )
            ]
        return [
            Finding(
                severity=Severity.OK,
                title="X-Frame-Options configurado",
                evidence=f"X-Frame-Options: {xfo}",
            )
        ]

    def _check_content_type_options(self, headers: dict[str, str]) -> list[Finding]:
        crudo = headers.get("x-content-type-options", "").strip()
        valores = _valores_lista(crudo)
        # El navegador solo mira el primer valor (Fetch, «determine nosniff»).
        if valores and valores[0].lower() == "nosniff":
            return [Finding(severity=Severity.OK, title="X-Content-Type-Options: nosniff")]
        return [
            Finding(
                severity=Severity.MEDIUM,
                kind=HARDENING,
                title="Falta X-Content-Type-Options: nosniff",
                description=(
                    "Sin esta cabecera el navegador puede adivinar el tipo de un recurso "
                    "e interpretar como script algo que se subió como imagen o texto."
                ),
                evidence=f"X-Content-Type-Options: {crudo}" if crudo else None,
                remediation="Añade: X-Content-Type-Options: nosniff",
            )
        ]

    def _check_referrer_policy(self, headers: dict[str, str]) -> list[Finding]:
        crudo = headers.get("referrer-policy", "").strip()
        if not crudo:
            return [
                Finding(
                    severity=Severity.LOW,
                    kind=HARDENING,
                    title="Falta Referrer-Policy",
                    description=(
                        "Sin política explícita, la URL completa puede filtrarse a sitios "
                        "de terceros, incluidos tokens o identificadores que lleve."
                    ),
                    remediation="Añade: Referrer-Policy: strict-origin-when-cross-origin",
                )
            ]

        # Es una lista: el navegador se queda con el último valor que reconoce.
        validas = [v.lower() for v in _valores_lista(crudo) if v.lower() in _REFERRER_VALIDAS]
        if not validas:
            return [
                Finding(
                    severity=Severity.LOW,
                    kind=HARDENING,
                    title="Referrer-Policy no válida",
                    description=(
                        "Ningún valor es reconocible, así que el navegador aplica su "
                        "política por defecto."
                    ),
                    evidence=f"Referrer-Policy: {crudo}",
                    remediation="Usa: Referrer-Policy: strict-origin-when-cross-origin",
                )
            ]
        efectiva = validas[-1]
        if efectiva in {"unsafe-url", "no-referrer-when-downgrade"}:
            return [
                Finding(
                    severity=Severity.MEDIUM,
                    kind=HARDENING,
                    title="Referrer-Policy permisiva",
                    description="Envía la URL completa a terceros, con lo que eso arrastre.",
                    evidence=f"Referrer-Policy: {crudo}",
                    remediation="Cambia a strict-origin-when-cross-origin o no-referrer.",
                )
            ]
        return [
            Finding(
                severity=Severity.OK,
                title="Referrer-Policy configurada",
                evidence=f"Referrer-Policy: {crudo}",
            )
        ]

    def _check_permissions_policy(self, headers: dict[str, str]) -> list[Finding]:
        if headers.get("permissions-policy") or headers.get("feature-policy"):
            return [Finding(severity=Severity.OK, title="Permissions-Policy configurada")]
        return [
            Finding(
                severity=Severity.LOW,
                kind=HARDENING,
                title="Falta Permissions-Policy",
                description=(
                    "Sin ella, cualquier iframe de la página puede pedir cámara, micrófono "
                    "o geolocalización en nombre de tu sitio."
                ),
                remediation="Añade: Permissions-Policy: camera=(), microphone=(), geolocation=()",
            )
        ]

    def _check_cors(self, headers: dict[str, str]) -> list[Finding]:
        """Lo que dicen las cabeceras CORS de la respuesta normal, sin Origin."""
        origen = headers.get("access-control-allow-origin", "").strip()
        credenciales = headers.get("access-control-allow-credentials", "").strip().lower()

        if origen == "*" and credenciales == "true":
            return [
                Finding(
                    severity=Severity.LOW,
                    kind=HARDENING,
                    title="CORS combina comodín y credenciales",
                    description=(
                        "Los navegadores rechazan Allow-Origin: * junto a Allow-Credentials: "
                        "true, así que esto no expone nada por sí solo; pero es señal de una "
                        "configuración descuidada. La sonda de CORS comprueba si el servidor "
                        "refleja orígenes ajenos, que es lo que sí sería explotable."
                    ),
                    evidence=(
                        "Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true"
                    ),
                    remediation="Enumera los orígenes concretos permitidos en lugar del comodín.",
                )
            ]
        if origen == "*":
            return [
                Finding(
                    severity=Severity.LOW,
                    kind=HARDENING,
                    title="CORS abierto a cualquier origen",
                    description="Correcto si el contenido es público; revísalo si no lo es.",
                    evidence="Access-Control-Allow-Origin: *",
                )
            ]
        return []

    def _sonda_cors(self, client: httpx.Client, url: str, cov: Coverage) -> list[Finding]:
        """Repite la petición con un Origin inventado y mira si el servidor lo devuelve."""
        nombre = "Reflejo de Origin en CORS"
        try:
            respuesta = client.get(url, headers={"Origin": ORIGEN_SONDA})
        except httpx.HTTPError as exc:
            cov.undetermined(
                "cors-reflejo", nombre, f"La petición de sonda falló: {type(exc).__name__}"
            )
            return []
        cov.done("cors-reflejo", nombre)
        return self._check_cors_reflejo({k.lower(): v for k, v in respuesta.headers.items()})

    def _check_cors_reflejo(self, headers: dict[str, str]) -> list[Finding]:
        origen = headers.get("access-control-allow-origin", "").strip()
        credenciales = headers.get("access-control-allow-credentials", "").strip().lower()
        if origen != ORIGEN_SONDA:
            return []
        evidencia = f"Origin: {ORIGEN_SONDA} → Access-Control-Allow-Origin: {origen}"
        if credenciales == "true":
            return [
                Finding(
                    severity=Severity.HIGH,
                    kind=VULNERABILIDAD,
                    title="CORS acepta cualquier origen con credenciales",
                    description=(
                        "El servidor devolvió como permitido un origen inventado y además "
                        "admite credenciales: cualquier web puede leer, con la sesión del "
                        "usuario, las respuestas de este sitio."
                    ),
                    evidence=f"{evidencia}; Access-Control-Allow-Credentials: true",
                    remediation=(
                        "Compara el Origin con una lista cerrada antes de devolverlo; no "
                        "copies la cabecera de la petición."
                    ),
                    references=["https://portswigger.net/web-security/cors"],
                )
            ]
        return [
            Finding(
                severity=Severity.LOW,
                kind=HARDENING,
                title="CORS refleja cualquier origen",
                description=(
                    "El servidor devuelve el Origin que se le mande. Sin credenciales "
                    "equivale a un comodín; si algún día se añaden, pasa a ser explotable."
                ),
                evidence=evidencia,
                remediation="Compara el Origin con una lista cerrada antes de devolverlo.",
            )
        ]

    def _check_legacy_xss(self, headers: dict[str, str]) -> list[Finding]:
        valor = headers.get("x-xss-protection", "").strip()
        if valor and not valor.startswith("0"):
            return [
                Finding(
                    severity=Severity.LOW,
                    kind=HARDENING,
                    title="X-XSS-Protection activada (obsoleta)",
                    description=(
                        "El filtro XSS de los navegadores antiguos llegó a introducir "
                        "vulnerabilidades propias y hoy está retirado."
                    ),
                    evidence=f"X-XSS-Protection: {valor}",
                    remediation="Ponla a 0 o elimínala, y confía la defensa a la CSP.",
                )
            ]
        return []

    def _check_cookies(self, response: httpx.Response, es_https: bool) -> list[Finding]:
        cookies = [parse_cookie(c) for c in response.headers.get_list("set-cookie")]
        cookies = [c for c in cookies if not _cookie_se_borra(c)]
        if not cookies:
            return []

        findings: list[Finding] = []
        for cookie in cookies:
            findings += self._check_cookie(cookie, es_https)

        if not findings:
            findings.append(
                Finding(
                    severity=Severity.OK,
                    title=f"Las {len(cookies)} cookies emitidas tienen atributos correctos",
                )
            )
        return findings

    def _check_cookie(self, cookie: Cookie, es_https: bool) -> list[Finding]:
        nombre = cookie.nombre or "(sin nombre)"
        atributos = cookie.atributos
        evidencia = _recorta(cookie_redactada(cookie))
        secure = "secure" in atributos
        samesite = (atributos.get("samesite") or "").lower() if "samesite" in atributos else None
        findings: list[Finding] = []

        if es_https and not secure:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    kind=HARDENING,
                    title=f"La cookie «{nombre}» no lleva Secure",
                    description="Puede enviarse por HTTP en claro y ser interceptada.",
                    evidence=evidencia,
                    remediation="Añade el atributo Secure.",
                )
            )

        # Los prefijos son promesas que el navegador verifica: si no se cumplen,
        # descarta la cookie, así que suele ser un fallo funcional además de uno
        # de seguridad.
        if cookie.nombre.startswith("__Host-") and (
            not secure or "domain" in atributos or atributos.get("path") != "/"
        ):
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    kind=HARDENING,
                    title=f"La cookie «{nombre}» no cumple el prefijo __Host-",
                    description=(
                        "__Host- exige Secure, Path=/ y ningún Domain. Si falta algo, el "
                        "navegador rechaza la cookie."
                    ),
                    evidence=evidencia,
                    remediation="Añade Secure y Path=/, y quita Domain.",
                )
            )
        elif cookie.nombre.startswith("__Secure-") and not secure:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    kind=HARDENING,
                    title=f"La cookie «{nombre}» no cumple el prefijo __Secure-",
                    description="__Secure- exige Secure; sin él, el navegador rechaza la cookie.",
                    evidence=evidencia,
                    remediation="Añade el atributo Secure.",
                )
            )

        if "httponly" not in atributos:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    kind=HARDENING,
                    title=f"La cookie «{nombre}» no lleva HttpOnly",
                    description=(
                        "Es accesible desde JavaScript, así que un XSS podría robarla. "
                        "Si la cookie no la necesita el front, debería ser HttpOnly."
                    ),
                    evidence=evidencia,
                    remediation="Añade el atributo HttpOnly.",
                )
            )

        if samesite is None:
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    kind=HARDENING,
                    title=f"La cookie «{nombre}» no define SameSite",
                    description=(
                        "El valor por defecto de los navegadores modernos (Lax) ayuda, "
                        "pero conviene declararlo de forma explícita."
                    ),
                    evidence=evidencia,
                    remediation="Añade SameSite=Lax o SameSite=Strict.",
                )
            )
        elif samesite not in {"strict", "lax", "none"}:
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    kind=HARDENING,
                    title=f"La cookie «{nombre}» tiene un SameSite no válido",
                    description=(
                        "El navegador ignora el valor y aplica su comportamiento por defecto."
                    ),
                    evidence=evidencia,
                    remediation="Usa SameSite=Lax, Strict o None.",
                )
            )
        elif samesite == "none" and not secure:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    kind=HARDENING,
                    title=f"La cookie «{nombre}» usa SameSite=None sin Secure",
                    description=(
                        "Los navegadores rechazan SameSite=None si la cookie no es Secure, "
                        "y aunque la aceptaran viajaría en peticiones de cualquier sitio."
                    ),
                    evidence=evidencia,
                    remediation=(
                        "Añade Secure, o usa SameSite=Lax si no necesitas el envío cruzado."
                    ),
                )
            )
        return findings

    def _check_info_leak(self, headers: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for cabecera in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
            valor = headers.get(cabecera, "").strip()
            if valor and re.search(r"\d", valor):
                findings.append(
                    Finding(
                        severity=Severity.LOW,
                        kind=HARDENING,
                        title=f"La cabecera {cabecera} revela versiones",
                        description=(
                            "Publicar producto y versión facilita a un atacante buscar "
                            "exploits conocidos para esa versión exacta."
                        ),
                        evidence=f"{cabecera}: {valor}",
                        remediation="Suprime la cabecera o deja solo el nombre del producto.",
                    )
                )
        return findings
