"""Verificación de certificado y configuración TLS de un host.

Comprueba la validez y caducidad del certificado, la fuerza de la clave y del
algoritmo de firma, qué versiones del protocolo acepta el servidor y si el
cifrado negociado sigue siendo recomendable.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from pydantic import BaseModel, Field

from ..core.finding import Finding, Severity
from ..core.module import Category, ScanModule

# Umbrales de aviso por caducidad, en días.
CADUCIDAD_CRITICA = 7
CADUCIDAD_ALTA = 15
CADUCIDAD_MEDIA = 30

# Desde septiembre de 2020 los navegadores rechazan certificados TLS de servidor
# con una vigencia superior a 398 días.
VIGENCIA_MAXIMA_DIAS = 398

RSA_MINIMO_BITS = 2048
EC_MINIMO_BITS = 256

# Familias de cifrado que ya no deberían negociarse.
CIFRADOS_DEBILES = {
    "RC4": "RC4 tiene sesgos estadísticos explotables en el flujo de clave.",
    "3DES": "3DES es vulnerable a Sweet32 por su bloque de 64 bits.",
    "DES": "DES tiene una clave de 56 bits, rompible por fuerza bruta.",
    "NULL": "Un cifrado NULL no cifra nada: el tráfico viaja en claro.",
    "EXPORT": "Los cifrados de exportación usan claves deliberadamente débiles.",
    "MD5": "MD5 no ofrece garantías de integridad frente a colisiones.",
    "ANON": "Un intercambio anónimo no autentica al servidor.",
}

_VERSIONES = [
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3, Severity.OK),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2, Severity.OK),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1, Severity.HIGH),
    ("TLSv1.0", ssl.TLSVersion.TLSv1, Severity.HIGH),
]


class TlsInput(BaseModel):
    """Entradas del módulo."""

    host: str = Field(description="Dominio a analizar (se aceptan URLs completas).")
    port: int = Field(default=443, ge=1, le=65535, description="Puerto TLS.")
    timeout: float = Field(default=10.0, gt=0, description="Segundos de espera por conexión.")
    check_protocols: bool = Field(
        default=True,
        description=(
            "Probar qué versiones de TLS acepta el servidor (abre una conexión por versión)."
        ),
    )


def _limpia_host(valor: str) -> str:
    """Acepta 'https://ejemplo.com/algo' y devuelve 'ejemplo.com'."""
    host = valor.strip()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0].split("?", 1)[0]
    if host.startswith("[") and "]" in host:  # IPv6 entre corchetes
        return host[: host.index("]") + 1]
    if host.count(":") == 1:
        host = host.split(":", 1)[0]
    return host


def _naive_a_utc(momento: datetime) -> datetime:
    return momento if momento.tzinfo else momento.replace(tzinfo=timezone.utc)


def _no_after(cert: x509.Certificate) -> datetime:
    # `not_valid_after` quedó obsoleto en cryptography 42 a favor de la variante UTC.
    valor = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    return _naive_a_utc(valor)


def _no_before(cert: x509.Certificate) -> datetime:
    valor = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
    return _naive_a_utc(valor)


def _nombre_comun(nombre: x509.Name) -> str:
    atributos = nombre.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    if atributos:
        return str(atributos[0].value)
    return nombre.rfc4514_string()


class TlsModule(ScanModule):
    id = "tls"
    name = "Verificador de TLS y certificados"
    description = (
        "Analiza el certificado de un host (validez, caducidad, fuerza de clave y "
        "firma) y las versiones de TLS y cifrados que acepta."
    )
    category = Category.CRYPTO
    InputModel = TlsInput

    def target_of(self, inputs: TlsInput) -> str:  # type: ignore[override]
        return f"{_limpia_host(inputs.host)}:{inputs.port}"

    def run(self, inputs: TlsInput) -> list[Finding]:  # type: ignore[override]
        host = _limpia_host(inputs.host)
        findings: list[Finding] = []

        # Primero verificamos como lo haría un navegador, para detectar cadenas
        # rotas o nombres que no casan.
        error_verificacion = self._verificar(host, inputs.port, inputs.timeout)

        # Y después recogemos el certificado sin verificar, para poder analizarlo
        # incluso cuando la validación falla (que es justo cuando más interesa).
        der, protocolo, cifrado = self._recoger(host, inputs.port, inputs.timeout)
        cert = x509.load_der_x509_certificate(der)

        if error_verificacion:
            hallazgo = self._finding_verificacion(error_verificacion)
            if hallazgo is not None:
                findings.append(hallazgo)
        else:
            findings.append(
                Finding(
                    severity=Severity.OK,
                    title="El certificado valida correctamente",
                    description="Cadena de confianza completa y nombre del host coincidente.",
                )
            )

        findings += self._check_vigencia(cert)
        findings += self._check_autofirmado(cert, error_verificacion)
        findings += self._check_firma(cert)
        findings += self._check_clave(cert)
        findings += self._check_nombres(cert)
        findings += self._check_cifrado(protocolo, cifrado)

        if inputs.check_protocols:
            findings += self._check_protocolos(host, inputs.port, inputs.timeout)

        return findings

    # -- conexiones -------------------------------------------------------

    def _verificar(self, host: str, port: int, timeout: float) -> str | None:
        """Intenta un handshake verificado. Devuelve el motivo del fallo, o None."""
        contexto = ssl.create_default_context()
        try:
            with (
                socket.create_connection((host, port), timeout=timeout) as sock,
                contexto.wrap_socket(sock, server_hostname=host),
            ):
                return None
        except ssl.SSLCertVerificationError as exc:
            return exc.verify_message or str(exc)
        except ssl.SSLError as exc:
            return str(exc)

    def _recoger(self, host: str, port: int, timeout: float) -> tuple[bytes, str, tuple]:
        """Recoge el certificado sin validarlo, junto al protocolo y cifrado negociados."""
        contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        contexto.check_hostname = False
        contexto.verify_mode = ssl.CERT_NONE
        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            contexto.wrap_socket(sock, server_hostname=host) as tls,
        ):
            der = tls.getpeercert(binary_form=True)
            if not der:
                raise RuntimeError("El servidor no presentó ningún certificado.")
            return der, tls.version() or "desconocido", tls.cipher() or ()

    # -- comprobaciones ---------------------------------------------------

    def _finding_verificacion(self, error: str) -> Finding | None:
        """Traduce el error de validación a un hallazgo, o None si ya lo cubre otra comprobación."""
        bajo = error.lower()
        if "expired" in bajo:
            # `_check_vigencia` lo reporta con la fecha exacta y los días de desfase.
            return None
        if "hostname mismatch" in bajo or "doesn't match" in bajo:
            return Finding(
                severity=Severity.CRITICAL,
                title="El certificado no corresponde a este dominio",
                description=(
                    "El nombre del host no aparece entre los del certificado. Los "
                    "navegadores muestran un aviso a pantalla completa."
                ),
                evidence=error,
                remediation="Emite un certificado que incluya este dominio en sus SAN.",
            )
        if "self signed" in bajo or "self-signed" in bajo:
            return Finding(
                severity=Severity.HIGH,
                title="Certificado autofirmado o con cadena no confiable",
                description=(
                    "Ningún navegador confía en él por defecto, y un certificado "
                    "autofirmado no distingue al servidor legítimo de un impostor."
                ),
                evidence=error,
                remediation="Usa un certificado de una CA pública (Let's Encrypt es gratuito).",
            )
        return Finding(
            severity=Severity.HIGH,
            title="El certificado no supera la validación",
            evidence=error,
            remediation="Revisa la cadena de certificados que sirve el servidor.",
        )

    def _check_vigencia(self, cert: x509.Certificate) -> list[Finding]:
        ahora = datetime.now(timezone.utc)
        inicio, fin = _no_before(cert), _no_after(cert)
        findings: list[Finding] = []

        if ahora < inicio:
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    title="El certificado todavía no es válido",
                    description="Su periodo de validez empieza en el futuro.",
                    evidence=f"Válido desde: {inicio:%Y-%m-%d %H:%M UTC}",
                    remediation="Revisa la fecha del servidor y la emisión del certificado.",
                )
            )

        dias = (fin - ahora).days
        if dias < 0:
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    title=f"Certificado caducado hace {abs(dias)} días",
                    evidence=f"Caducó: {fin:%Y-%m-%d %H:%M UTC}",
                    remediation="Renuévalo ya y automatiza la renovación con certbot o similar.",
                )
            )
        elif dias <= CADUCIDAD_CRITICA:
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    title=f"El certificado caduca en {dias} días",
                    evidence=f"Caduca: {fin:%Y-%m-%d %H:%M UTC}",
                    remediation="Renueva de inmediato.",
                )
            )
        elif dias <= CADUCIDAD_ALTA:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title=f"El certificado caduca en {dias} días",
                    evidence=f"Caduca: {fin:%Y-%m-%d %H:%M UTC}",
                    remediation="Programa la renovación esta semana.",
                )
            )
        elif dias <= CADUCIDAD_MEDIA:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title=f"El certificado caduca en {dias} días",
                    evidence=f"Caduca: {fin:%Y-%m-%d %H:%M UTC}",
                    remediation="Conviene renovarlo antes de que entre en la última semana.",
                )
            )
        else:
            findings.append(
                Finding(
                    severity=Severity.OK,
                    title=f"El certificado es válido {dias} días más",
                    evidence=f"Caduca: {fin:%Y-%m-%d %H:%M UTC}",
                )
            )

        vigencia = (fin - inicio).days
        if vigencia > VIGENCIA_MAXIMA_DIAS:
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    title=f"Periodo de validez excesivo ({vigencia} días)",
                    description=(
                        f"Desde 2020 los navegadores rechazan certificados de servidor "
                        f"con más de {VIGENCIA_MAXIMA_DIAS} días de vigencia."
                    ),
                    evidence=f"{inicio:%Y-%m-%d} → {fin:%Y-%m-%d}",
                    remediation=(
                        "Emite certificados de vigencia corta y renuévalos automáticamente."
                    ),
                )
            )
        return findings

    def _check_autofirmado(
        self, cert: x509.Certificate, error_verificacion: str | None
    ) -> list[Finding]:
        # Si la validación ya falló, el motivo concreto se reportó allí.
        if error_verificacion or cert.issuer != cert.subject:
            return []
        return [
            Finding(
                severity=Severity.HIGH,
                title="El certificado está autofirmado",
                evidence=f"Emisor y sujeto coinciden: {_nombre_comun(cert.subject)}",
                remediation="Sustitúyelo por uno emitido por una CA reconocida.",
            )
        ]

    def _check_firma(self, cert: x509.Certificate) -> list[Finding]:
        algoritmo = (
            cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "desconocido"
        )
        nombre = algoritmo.lower()

        if nombre in {"md5", "md2"}:
            return [
                Finding(
                    severity=Severity.CRITICAL,
                    title=f"Certificado firmado con {algoritmo.upper()}",
                    description=(
                        "MD5 admite colisiones prácticas: se pueden falsificar certificados."
                    ),
                    evidence=f"Algoritmo de firma: {cert.signature_algorithm_oid._name}",
                    remediation="Reemite el certificado con SHA-256 o superior.",
                )
            ]
        if nombre == "sha1":
            return [
                Finding(
                    severity=Severity.CRITICAL,
                    title="Certificado firmado con SHA-1",
                    description=(
                        "SHA-1 tiene colisiones demostradas (SHAttered, 2017) y los "
                        "navegadores llevan años rechazándolo."
                    ),
                    evidence=f"Algoritmo de firma: {cert.signature_algorithm_oid._name}",
                    remediation="Reemite el certificado con SHA-256 o superior.",
                )
            ]
        return [
            Finding(
                severity=Severity.OK,
                title=f"Firma con {algoritmo.upper()}",
                evidence=f"Algoritmo de firma: {cert.signature_algorithm_oid._name}",
            )
        ]

    def _check_clave(self, cert: x509.Certificate) -> list[Finding]:
        clave = cert.public_key()

        if isinstance(clave, rsa.RSAPublicKey):
            bits = clave.key_size
            if bits < RSA_MINIMO_BITS:
                return [
                    Finding(
                        severity=Severity.HIGH if bits >= 1024 else Severity.CRITICAL,
                        title=f"Clave RSA débil ({bits} bits)",
                        description=f"El mínimo aceptado hoy son {RSA_MINIMO_BITS} bits.",
                        evidence=f"Clave pública: RSA {bits} bits",
                        remediation="Reemite el certificado con una clave RSA de 2048 bits o más.",
                    )
                ]
            return [Finding(severity=Severity.OK, title=f"Clave RSA de {bits} bits")]

        if isinstance(clave, ec.EllipticCurvePublicKey):
            bits = clave.curve.key_size
            if bits < EC_MINIMO_BITS:
                return [
                    Finding(
                        severity=Severity.HIGH,
                        title=f"Curva elíptica débil ({clave.curve.name}, {bits} bits)",
                        evidence=f"Clave pública: EC {clave.curve.name}",
                        remediation="Usa al menos P-256 (secp256r1).",
                    )
                ]
            return [
                Finding(
                    severity=Severity.OK,
                    title=f"Clave EC {clave.curve.name} ({bits} bits)",
                )
            ]

        if isinstance(clave, dsa.DSAPublicKey):
            return [
                Finding(
                    severity=Severity.HIGH,
                    title="Certificado con clave DSA",
                    description="DSA está en desuso y muchos clientes ya no lo aceptan.",
                    remediation="Migra a RSA de 2048 bits o a ECDSA P-256.",
                )
            ]

        return [Finding(severity=Severity.INFO, title=f"Tipo de clave: {type(clave).__name__}")]

    def _check_nombres(self, cert: x509.Certificate) -> list[Finding]:
        try:
            extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            nombres = extension.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            return [
                Finding(
                    severity=Severity.HIGH,
                    title="El certificado no tiene extensión SAN",
                    description=(
                        "Los navegadores modernos ignoran el Common Name y exigen SAN, "
                        "así que este certificado no será aceptado."
                    ),
                    remediation="Reemítelo incluyendo los dominios en subjectAltName.",
                )
            ]

        findings = [
            Finding(
                severity=Severity.INFO,
                title=f"El certificado cubre {len(nombres)} nombre(s)",
                evidence=", ".join(nombres[:12]) + ("…" if len(nombres) > 12 else ""),
            )
        ]
        if any(n.startswith("*.") for n in nombres):
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title="Es un certificado comodín",
                    description=(
                        "Una sola clave privada sirve para todos los subdominios: si se "
                        "filtra, quedan comprometidos todos a la vez."
                    ),
                    evidence=", ".join(n for n in nombres if n.startswith("*."))[:200],
                )
            )
        return findings

    def _check_cifrado(self, protocolo: str, cifrado: tuple) -> list[Finding]:
        if not cifrado:
            return []
        nombre, version_cifrado, bits = cifrado[0], cifrado[1], cifrado[2]
        findings: list[Finding] = []

        for patron, motivo in CIFRADOS_DEBILES.items():
            if patron in nombre.upper():
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        title=f"Cifrado débil negociado: {nombre}",
                        description=motivo,
                        evidence=f"{protocolo} · {nombre} · {bits} bits",
                        remediation=(
                            "Restringe la lista de cifrados del servidor a suites AEAD modernas."
                        ),
                    )
                )
                break

        if bits and bits < 128:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title=f"Clave de sesión corta ({bits} bits)",
                    evidence=f"{protocolo} · {nombre}",
                    remediation="Exige suites de al menos 128 bits.",
                )
            )

        if not findings:
            findings.append(
                Finding(
                    severity=Severity.OK,
                    title=f"Cifrado negociado: {nombre}",
                    evidence=f"{protocolo} · {version_cifrado} · {bits} bits",
                )
            )
        return findings

    def _check_protocolos(self, host: str, port: int, timeout: float) -> list[Finding]:
        soportadas: list[str] = []
        no_comprobables: list[str] = []
        findings: list[Finding] = []

        for etiqueta, version, gravedad in _VERSIONES:
            estado = self._soporta(host, port, timeout, version)
            if estado is None:
                no_comprobables.append(etiqueta)
                continue
            if not estado:
                continue

            soportadas.append(etiqueta)
            if gravedad is not Severity.OK:
                findings.append(
                    Finding(
                        severity=gravedad,
                        title=f"El servidor acepta {etiqueta}",
                        description=(
                            f"{etiqueta} está formalmente obsoleto (RFC 8996) y arrastra "
                            "debilidades conocidas como BEAST y POODLE."
                        ),
                        evidence=f"Handshake completado con {etiqueta}",
                        remediation="Configura el servidor para aceptar solo TLS 1.2 y 1.3.",
                        references=["https://datatracker.ietf.org/doc/html/rfc8996"],
                    )
                )

        modernas = {"TLSv1.2", "TLSv1.3"} & set(soportadas)
        if not modernas and not no_comprobables:
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    title="El servidor no acepta TLS 1.2 ni TLS 1.3",
                    remediation="Habilita TLS 1.2 como mínimo.",
                )
            )
        elif "TLSv1.3" not in soportadas and "TLSv1.3" not in no_comprobables:
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    title="El servidor no ofrece TLS 1.3",
                    description=(
                        "TLS 1.3 es más rápido y elimina por diseño las suites problemáticas."
                    ),
                    remediation="Actualiza el servidor y habilita TLS 1.3.",
                )
            )

        if soportadas:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title="Versiones de TLS aceptadas",
                    evidence=", ".join(soportadas),
                )
            )
        if no_comprobables:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title="Versiones que no se han podido probar",
                    description=(
                        "El OpenSSL de esta máquina tiene deshabilitadas estas versiones, "
                        "así que no se puede saber si el servidor las aceptaría."
                    ),
                    evidence=", ".join(no_comprobables),
                )
            )
        return findings

    def _soporta(
        self, host: str, port: int, timeout: float, version: ssl.TLSVersion
    ) -> bool | None:
        """True/False si el servidor acepta esa versión; None si no se puede probar aquí."""
        try:
            contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            contexto.check_hostname = False
            contexto.verify_mode = ssl.CERT_NONE
            contexto.minimum_version = version
            contexto.maximum_version = version
            if version < ssl.TLSVersion.TLSv1_2:
                # OpenSSL 3 exige bajar el nivel de seguridad para siquiera
                # ofrecer las suites de TLS 1.0/1.1.
                contexto.set_ciphers("ALL:@SECLEVEL=0")
        except (ssl.SSLError, ValueError):
            return None

        try:
            with (
                socket.create_connection((host, port), timeout=timeout) as sock,
                contexto.wrap_socket(sock, server_hostname=host),
            ):
                return True
        except (ssl.SSLError, OSError):
            return False
