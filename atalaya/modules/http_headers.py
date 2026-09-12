"""Auditoría de cabeceras HTTP de seguridad.

Pide una URL y evalúa las cabeceras de respuesta: HSTS, CSP, protección contra
clickjacking y sniffing de MIME, política de referente, atributos de las cookies
y fugas de información del servidor.
"""

from __future__ import annotations

import re

import httpx
from pydantic import BaseModel, Field

from ..core.finding import Finding, Severity
from ..core.module import Category, ScanModule

# Seis meses, el mínimo que pide hstspreload.org para entrar en la lista.
HSTS_MIN_MAX_AGE = 15_768_000

_MAX_EVIDENCIA = 300


def _recorta(valor: str) -> str:
    valor = valor.strip()
    if len(valor) <= _MAX_EVIDENCIA:
        return valor
    return valor[:_MAX_EVIDENCIA] + "…"


class HttpHeadersInput(BaseModel):
    """Entradas del módulo. De aquí salen los argumentos de la CLI y el formulario web."""

    url: str = Field(description="URL a auditar. Si omites el esquema se asume https://")
    timeout: float = Field(default=10.0, gt=0, description="Segundos de espera por petición.")
    follow_redirects: bool = Field(
        default=True, description="Seguir redirecciones hasta la respuesta final."
    )
    # Las cabeceras HTTP no admiten caracteres fuera de ASCII, así que el valor
    # por defecto va sin tildes a propósito.
    user_agent: str = Field(
        default="Atalaya/0.1 (+https://github.com/javiersaguar/atalaya)",
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

    def run(self, inputs: HttpHeadersInput) -> list[Finding]:  # type: ignore[override]
        url = inputs.url if "://" in inputs.url else f"https://{inputs.url}"

        with httpx.Client(
            timeout=inputs.timeout,
            follow_redirects=inputs.follow_redirects,
            headers={"User-Agent": inputs.user_agent},
        ) as client:
            response = client.get(url)

        headers = {k.lower(): v for k, v in response.headers.items()}
        es_https = response.url.scheme == "https"

        findings: list[Finding] = []
        findings += self._check_https(response, es_https)
        findings += self._check_hsts(headers, es_https)
        findings += self._check_csp(headers)
        findings += self._check_frame_options(headers)
        findings += self._check_content_type_options(headers)
        findings += self._check_referrer_policy(headers)
        findings += self._check_permissions_policy(headers)
        findings += self._check_cors(headers)
        findings += self._check_legacy_xss(headers)
        findings += self._check_cookies(response, es_https)
        findings += self._check_info_leak(headers)
        return findings

    # -- comprobaciones ---------------------------------------------------

    def _check_https(self, response: httpx.Response, es_https: bool) -> list[Finding]:
        if not es_https:
            return [
                Finding(
                    severity=Severity.HIGH,
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

        valor = headers.get("strict-transport-security")
        if not valor:
            return [
                Finding(
                    severity=Severity.HIGH,
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

        findings: list[Finding] = []
        match = re.search(r"max-age\s*=\s*(\d+)", valor, re.I)
        max_age = int(match.group(1)) if match else 0

        if max_age == 0:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title="HSTS presente pero desactivado (max-age=0)",
                    description="Un max-age de 0 le dice al navegador que olvide la política.",
                    evidence=_recorta(valor),
                    remediation="Sube max-age a 31536000 (un año).",
                )
            )
        elif max_age < HSTS_MIN_MAX_AGE:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title="El max-age de HSTS es demasiado corto",
                    description=(
                        f"Son {max_age} segundos ({max_age // 86400} días). Por debajo de "
                        "seis meses la protección se pierde entre visitas espaciadas."
                    ),
                    evidence=_recorta(valor),
                    remediation="Usa al menos max-age=15768000; lo habitual es 31536000.",
                )
            )
        else:
            findings.append(
                Finding(
                    severity=Severity.OK,
                    title="HSTS configurado con un max-age adecuado",
                    evidence=_recorta(valor),
                )
            )

        if "includesubdomains" not in valor.lower():
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    title="HSTS no cubre los subdominios",
                    description=(
                        "Sin includeSubDomains, un subdominio servido por HTTP sigue "
                        "siendo un punto de entrada para robar cookies de sesión."
                    ),
                    evidence=_recorta(valor),
                    remediation="Añade includeSubDomains si controlas todos los subdominios.",
                )
            )
        return findings

    def _check_csp(self, headers: dict[str, str]) -> list[Finding]:
        valor = headers.get("content-security-policy")
        solo_informe = headers.get("content-security-policy-report-only")

        if not valor:
            if solo_informe:
                return [
                    Finding(
                        severity=Severity.MEDIUM,
                        title="La CSP está solo en modo informe",
                        description=(
                            "Content-Security-Policy-Report-Only registra violaciones "
                            "pero no bloquea nada, así que hoy no protege."
                        ),
                        evidence=_recorta(solo_informe),
                        remediation=(
                            "Cuando el informe esté limpio, pasa la política a Content-Security- "
                            "Policy."
                        ),
                    )
                ]
            return [
                Finding(
                    severity=Severity.HIGH,
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
        politica = valor.lower()
        directivas = {
            d.split()[0]: d for d in (p.strip() for p in politica.split(";")) if d and d.split()
        }

        if "'unsafe-inline'" in politica:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title="La CSP permite 'unsafe-inline'",
                    description=(
                        "Permitir scripts en línea anula buena parte de la protección "
                        "contra XSS que aporta la CSP."
                    ),
                    evidence=_recorta(valor),
                    remediation="Sustitúyelo por nonces ('nonce-...') o hashes por script.",
                )
            )
        if "'unsafe-eval'" in politica:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title="La CSP permite 'unsafe-eval'",
                    description=(
                        "Habilita eval() y equivalentes, una vía clásica de ejecución de código."
                    ),
                    evidence=_recorta(valor),
                    remediation="Elimina las dependencias que necesiten eval y quita la directiva.",
                )
            )

        fuente = directivas.get("script-src") or directivas.get("default-src", "")
        if re.search(r"(^|\s)\*(\s|$)", fuente):
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title="La CSP admite scripts de cualquier origen",
                    description=(
                        "Un comodín en script-src/default-src deja la política sin efecto "
                        "práctico."
                    ),
                    evidence=_recorta(fuente),
                    remediation="Enumera los orígenes concretos que necesitas.",
                )
            )

        if "default-src" not in directivas and "script-src" not in directivas:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title="La CSP no define default-src ni script-src",
                    description="Sin ninguna de las dos, la carga de scripts queda sin restringir.",
                    evidence=_recorta(valor),
                    remediation="Añade al menos default-src 'self'.",
                )
            )

        if "base-uri" not in directivas:
            findings.append(
                Finding(
                    severity=Severity.LOW,
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
        csp = headers.get("content-security-policy", "").lower()
        tiene_ancestors = "frame-ancestors" in csp

        if tiene_ancestors:
            return [
                Finding(
                    severity=Severity.OK,
                    title="Protegido contra clickjacking vía CSP frame-ancestors",
                )
            ]
        if not xfo:
            return [
                Finding(
                    severity=Severity.MEDIUM,
                    title="Sin protección contra clickjacking",
                    description=(
                        "No hay X-Frame-Options ni frame-ancestors en la CSP: la página "
                        "puede incrustarse en un iframe ajeno para engañar al usuario."
                    ),
                    remediation="Añade Content-Security-Policy: frame-ancestors 'none' (o 'self').",
                    references=["https://owasp.org/www-community/attacks/Clickjacking"],
                )
            ]
        if xfo.upper() not in {"DENY", "SAMEORIGIN"}:
            return [
                Finding(
                    severity=Severity.MEDIUM,
                    title="Valor de X-Frame-Options no válido",
                    description=(
                        "Los navegadores solo reconocen DENY y SAMEORIGIN; ALLOW-FROM "
                        "está obsoleto y se ignora."
                    ),
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
        valor = headers.get("x-content-type-options", "").strip().lower()
        if valor == "nosniff":
            return [Finding(severity=Severity.OK, title="X-Content-Type-Options: nosniff")]
        return [
            Finding(
                severity=Severity.MEDIUM,
                title="Falta X-Content-Type-Options: nosniff",
                description=(
                    "Sin esta cabecera el navegador puede adivinar el tipo de un recurso "
                    "e interpretar como script algo que se subió como imagen o texto."
                ),
                evidence=f"X-Content-Type-Options: {valor}" if valor else None,
                remediation="Añade: X-Content-Type-Options: nosniff",
            )
        ]

    def _check_referrer_policy(self, headers: dict[str, str]) -> list[Finding]:
        valor = headers.get("referrer-policy", "").strip().lower()
        if not valor:
            return [
                Finding(
                    severity=Severity.LOW,
                    title="Falta Referrer-Policy",
                    description=(
                        "Sin política explícita, la URL completa puede filtrarse a sitios "
                        "de terceros, incluidos tokens o identificadores que lleve."
                    ),
                    remediation="Añade: Referrer-Policy: strict-origin-when-cross-origin",
                )
            ]
        if valor in {"unsafe-url", "no-referrer-when-downgrade"}:
            return [
                Finding(
                    severity=Severity.MEDIUM,
                    title="Referrer-Policy permisiva",
                    description="Envía la URL completa a terceros, con lo que eso arrastre.",
                    evidence=f"Referrer-Policy: {valor}",
                    remediation="Cambia a strict-origin-when-cross-origin o no-referrer.",
                )
            ]
        return [
            Finding(
                severity=Severity.OK,
                title="Referrer-Policy configurada",
                evidence=f"Referrer-Policy: {valor}",
            )
        ]

    def _check_permissions_policy(self, headers: dict[str, str]) -> list[Finding]:
        if headers.get("permissions-policy") or headers.get("feature-policy"):
            return [Finding(severity=Severity.OK, title="Permissions-Policy configurada")]
        return [
            Finding(
                severity=Severity.LOW,
                title="Falta Permissions-Policy",
                description=(
                    "Sin ella, cualquier iframe de la página puede pedir cámara, micrófono "
                    "o geolocalización en nombre de tu sitio."
                ),
                remediation="Añade: Permissions-Policy: camera=(), microphone=(), geolocation=()",
            )
        ]

    def _check_cors(self, headers: dict[str, str]) -> list[Finding]:
        origen = headers.get("access-control-allow-origin", "").strip()
        credenciales = headers.get("access-control-allow-credentials", "").strip().lower()

        if origen == "*" and credenciales == "true":
            return [
                Finding(
                    severity=Severity.HIGH,
                    title="CORS permisivo con credenciales",
                    description=(
                        "Combinar Allow-Origin: * con Allow-Credentials: true permitiría a "
                        "cualquier web leer respuestas autenticadas. Los navegadores "
                        "rechazan esa combinación, señal de una configuración descuidada."
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
                    title="CORS abierto a cualquier origen",
                    description="Correcto si el contenido es público; revísalo si no lo es.",
                    evidence="Access-Control-Allow-Origin: *",
                )
            ]
        return []

    def _check_legacy_xss(self, headers: dict[str, str]) -> list[Finding]:
        valor = headers.get("x-xss-protection", "").strip()
        if valor and not valor.startswith("0"):
            return [
                Finding(
                    severity=Severity.LOW,
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
        cookies = response.headers.get_list("set-cookie")
        if not cookies:
            return []

        findings: list[Finding] = []
        for cruda in cookies:
            nombre = cruda.split("=", 1)[0].strip()
            atributos = cruda.lower()

            if es_https and "secure" not in atributos:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        title=f"La cookie «{nombre}» no lleva Secure",
                        description="Puede enviarse por HTTP en claro y ser interceptada.",
                        evidence=_recorta(cruda),
                        remediation="Añade el atributo Secure.",
                    )
                )
            if "httponly" not in atributos:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        title=f"La cookie «{nombre}» no lleva HttpOnly",
                        description=(
                            "Es accesible desde JavaScript, así que un XSS podría robarla. "
                            "Si la cookie no la necesita el front, debería ser HttpOnly."
                        ),
                        evidence=_recorta(cruda),
                        remediation="Añade el atributo HttpOnly.",
                    )
                )
            if "samesite" not in atributos:
                findings.append(
                    Finding(
                        severity=Severity.LOW,
                        title=f"La cookie «{nombre}» no define SameSite",
                        description=(
                            "El valor por defecto de los navegadores modernos (Lax) ayuda, "
                            "pero conviene declararlo de forma explícita."
                        ),
                        evidence=_recorta(cruda),
                        remediation="Añade SameSite=Lax o SameSite=Strict.",
                    )
                )

        if not findings:
            findings.append(
                Finding(
                    severity=Severity.OK,
                    title=f"Las {len(cookies)} cookies emitidas tienen atributos correctos",
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
