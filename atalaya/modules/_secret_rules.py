"""Catálogo de reglas de detección de secretos.

Va en un archivo aparte (con guion bajo, que el registro ignora) porque es la
parte que más va a crecer: añadir un proveedor nuevo es añadir una `Regla` a
`REGLAS`, sin tocar el módulo.

Dos familias de reglas:

- **De formato conocido.** Buscan credenciales con una forma inconfundible
  (`AKIA...`, `ghp_...`). Casi no dan falsos positivos, así que van en crítico.
- **Contextuales.** Buscan una asignación con pinta de secreto (`api_key = "..."`)
  y exigen además entropía alta en el valor. Dan más falsos positivos, así que
  su gravedad depende de lo aleatorio que parezca el valor.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field

from ..core.finding import Severity

# Un valor con menos entropía que esto no se considera secreto aunque esté en
# una variable que se llame «password». Se calcula en bits por carácter.
ENTROPIA_SOSPECHOSA = 3.5
ENTROPIA_ALTA = 4.5

LONGITUD_MINIMA = 12


@dataclass(frozen=True)
class Regla:
    """Una forma de reconocer un secreto."""

    id: str
    name: str
    severity: Severity
    pattern: re.Pattern[str]
    description: str
    remediation: str
    # Grupo de la expresión regular que contiene el secreto en sí. El 0 es la
    # coincidencia entera; en las reglas contextuales interesa solo el valor.
    group: int = 0
    # Si es cierto, el valor capturado debe superar el umbral de entropía para
    # que el hallazgo se emita.
    requiere_entropia: bool = False
    # Si es falso, la evidencia se muestra tal cual. Se usa cuando lo que casa
    # es un marcador (la cabecera de una clave privada), no el secreto.
    redactar: bool = True
    references: list[str] = field(default_factory=list)


def _r(patron: str, banderas: int = 0) -> re.Pattern[str]:
    return re.compile(patron, banderas)


ROTAR = (
    "Revoca la credencial en el proveedor y emite una nueva: una vez publicada, "
    "se considera comprometida."
)

# -- Credenciales de formato inconfundible ---------------------------------

REGLAS_CONOCIDAS: list[Regla] = [
    Regla(
        id="aws-access-key-id",
        name="Clave de acceso de AWS",
        severity=Severity.CRITICAL,
        pattern=_r(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}\b"),
        description=(
            "Identificador de clave de acceso de AWS. Con su secreto da acceso a la cuenta."
        ),
        remediation="Desactiva la clave en IAM, crea otra y revisa CloudTrail por si se usó.",
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
        ],
    ),
    Regla(
        id="aws-secret-access-key",
        name="Secreto de acceso de AWS",
        severity=Severity.CRITICAL,
        pattern=_r(
            r"""aws_?secret_?access_?key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?""",
            re.IGNORECASE,
        ),
        group=1,
        description="La mitad secreta de una credencial de AWS.",
        remediation="Desactiva la clave en IAM, crea otra y revisa CloudTrail por si se usó.",
    ),
    Regla(
        id="private-key",
        name="Clave privada",
        severity=Severity.CRITICAL,
        pattern=_r(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
        ),
        description=(
            "Bloque de clave privada. Quien la tenga puede suplantar al servidor o al usuario."
        ),
        remediation="Genera un par de claves nuevo, despliégalo y revoca el antiguo.",
        redactar=False,
    ),
    Regla(
        id="github-token",
        name="Token de GitHub",
        severity=Severity.CRITICAL,
        pattern=_r(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,251}\b"),
        description="Token de acceso personal de GitHub.",
        remediation=ROTAR,
        references=["https://github.com/settings/tokens"],
    ),
    Regla(
        id="github-fine-grained",
        name="Token de GitHub de permisos específicos",
        severity=Severity.CRITICAL,
        pattern=_r(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
        description="Token de acceso personal de GitHub de nueva generación.",
        remediation=ROTAR,
    ),
    Regla(
        id="gitlab-token",
        name="Token de GitLab",
        severity=Severity.CRITICAL,
        pattern=_r(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
        description="Token de acceso personal de GitLab.",
        remediation=ROTAR,
    ),
    Regla(
        id="stripe-secret-key",
        name="Clave secreta de Stripe",
        severity=Severity.CRITICAL,
        pattern=_r(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b"),
        description="Clave de producción de Stripe: permite mover dinero real.",
        remediation="Revócala en el panel de Stripe ahora mismo y revisa los cargos recientes.",
    ),
    Regla(
        id="stripe-test-key",
        name="Clave de pruebas de Stripe",
        severity=Severity.LOW,
        pattern=_r(r"\b(?:sk|rk)_test_[A-Za-z0-9]{20,}\b"),
        description="Clave de entorno de pruebas: no mueve dinero, pero no debería versionarse.",
        remediation="Sácala a una variable de entorno por higiene.",
    ),
    Regla(
        id="slack-token",
        name="Token de Slack",
        severity=Severity.CRITICAL,
        pattern=_r(r"\bxox[baprse]-[A-Za-z0-9-]{10,}\b"),
        description="Token de Slack: da acceso al espacio de trabajo.",
        remediation=ROTAR,
    ),
    Regla(
        id="slack-webhook",
        name="Webhook de Slack",
        severity=Severity.HIGH,
        pattern=_r(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_+/]{8,}"),
        description="Permite publicar mensajes en un canal sin más autenticación.",
        remediation="Borra el webhook en Slack y crea otro.",
    ),
    Regla(
        id="discord-webhook",
        name="Webhook de Discord",
        severity=Severity.HIGH,
        pattern=_r(r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]{60,}"),
        description="Permite publicar mensajes en un canal sin más autenticación.",
        remediation="Borra el webhook en Discord y crea otro.",
    ),
    Regla(
        id="google-api-key",
        name="Clave de API de Google",
        severity=Severity.HIGH,
        pattern=_r(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        description="Clave de API de Google. Según su configuración puede generar gasto.",
        remediation="Restríngela o revócala en la consola de Google Cloud.",
    ),
    Regla(
        id="anthropic-key",
        name="Clave de API de Anthropic",
        severity=Severity.CRITICAL,
        pattern=_r(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
        description="Clave de API de Anthropic: el consumo se factura a su dueño.",
        remediation=ROTAR,
    ),
    Regla(
        id="openai-key",
        name="Clave de API de OpenAI",
        severity=Severity.CRITICAL,
        pattern=_r(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b"),
        description="Clave de API de OpenAI: el consumo se factura a su dueño.",
        remediation=ROTAR,
    ),
    Regla(
        id="telegram-bot-token",
        name="Token de bot de Telegram",
        severity=Severity.HIGH,
        pattern=_r(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b"),
        description="Da control total sobre el bot.",
        remediation="Revoca el token con @BotFather.",
    ),
    Regla(
        id="sendgrid-key",
        name="Clave de API de SendGrid",
        severity=Severity.HIGH,
        pattern=_r(r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{30,}\b"),
        description="Permite enviar correo en nombre del dominio configurado.",
        remediation=ROTAR,
    ),
    Regla(
        id="twilio-key",
        name="Clave de API de Twilio",
        severity=Severity.HIGH,
        pattern=_r(r"\bSK[0-9a-fA-F]{32}\b"),
        description="Permite enviar SMS y llamadas con cargo a la cuenta.",
        remediation=ROTAR,
    ),
    Regla(
        id="npm-token",
        name="Token de npm",
        severity=Severity.CRITICAL,
        pattern=_r(r"\bnpm_[A-Za-z0-9]{36}\b"),
        description="Permite publicar paquetes en nombre de su dueño.",
        remediation=ROTAR,
    ),
    Regla(
        id="pypi-token",
        name="Token de PyPI",
        severity=Severity.CRITICAL,
        pattern=_r(r"\bpypi-[A-Za-z0-9_-]{50,}\b"),
        description="Permite publicar paquetes en nombre de su dueño.",
        remediation=ROTAR,
    ),
    Regla(
        id="jwt",
        name="JSON Web Token",
        severity=Severity.MEDIUM,
        pattern=_r(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        description=(
            "Un JWT suele ser una sesión ya emitida. Puede estar caducado, pero también "
            "llevar datos personales, porque su carga va codificada, no cifrada."
        ),
        remediation="Comprueba qué contiene y si sigue siendo válido; si lo es, invalídalo.",
    ),
    Regla(
        id="connection-string",
        name="Cadena de conexión con contraseña",
        severity=Severity.CRITICAL,
        pattern=_r(
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|ftp|mssql)://"
            r"[^:@\s/]{1,64}:([^@\s/]{3,})@[^\s/]+",
            re.IGNORECASE,
        ),
        group=1,
        description="Credenciales de base de datos incrustadas en una URL.",
        remediation="Saca la cadena a una variable de entorno y cambia la contraseña.",
    ),
]

# -- Reglas contextuales ----------------------------------------------------

# Nombres de variable que sugieren que lo asignado es un secreto.
_NOMBRES = (
    r"(?:api[_-]?key|apikey|secret[_-]?key|secret|token|passwd|password|pwd|"
    r"auth[_-]?token|access[_-]?token|refresh[_-]?token|private[_-]?key|"
    r"client[_-]?secret|credential|passphrase|contrasena|contrasena)"
)

REGLAS_CONTEXTUALES: list[Regla] = [
    Regla(
        id="generic-assignment",
        name="Posible secreto asignado a una variable",
        severity=Severity.HIGH,
        pattern=_r(
            rf"""{_NOMBRES}\w*\s*[:=]\s*["']([^"'\s]{{{LONGITUD_MINIMA},}})["']""",
            re.IGNORECASE,
        ),
        group=1,
        requiere_entropia=True,
        description=(
            "Una variable con nombre de secreto a la que se asigna un valor de aspecto "
            "aleatorio. El nombre no basta: se exige además entropía alta."
        ),
        remediation="Sácalo a una variable de entorno o a un gestor de secretos.",
    ),
    Regla(
        id="authorization-header",
        name="Cabecera Authorization con credencial",
        severity=Severity.HIGH,
        pattern=_r(
            r"""["']?[Aa]uthorization["']?\s*[:=]\s*["'](?:Bearer|Basic|Token)\s+([^"'\s]{8,})["']"""
        ),
        group=1,
        requiere_entropia=True,
        description="Credencial incrustada en una cabecera de autorización.",
        remediation="Constrúyela en tiempo de ejecución desde una variable de entorno.",
    ),
]

REGLAS: list[Regla] = REGLAS_CONOCIDAS + REGLAS_CONTEXTUALES


# -- Entropía y falsos positivos -------------------------------------------


def entropia(valor: str) -> float:
    """Entropía de Shannon en bits por carácter.

    Un texto en lenguaje natural ronda los 3 bits; una clave aleatoria en base64
    se acerca a 6. Sirve para distinguir «password = "changeme"» de un secreto
    de verdad.
    """
    if not valor:
        return 0.0
    total = len(valor)
    return -sum((n / total) * math.log2(n / total) for n in Counter(valor).values())


# Valores que aparecen en ejemplos, plantillas y documentación. Si el secreto
# contiene alguno, casi seguro que no es real.
_MARCADORES = (
    "example",
    "ejemplo",
    "sample",
    "placeholder",
    "changeme",
    "change_me",
    "your",
    "tu_",
    "mi_",
    "my_",
    "dummy",
    "fake",
    "foobar",
    "insert",
    "redacted",
    "removed",
    "hidden",
    "xxxx",
    "yyyy",
    "zzzz",
    "aaaa",
    "1234567890",
    "abcdef",
    "todo",
    "fixme",
    "notreal",
    "dont_use",
    "test_key",
    "testkey",
    "lorem",
    "asdf",
    "qwerty",
    "secret_here",
)

# Formas de interpolación: el valor real lo pone otra cosa en tiempo de ejecución.
_INTERPOLACION = re.compile(
    r"""\$\{|\{\{|<%|%\(|%s\b|\{[a-z_]+\}|^<[^>]+>$|^\$[A-Z_]+$|^process\.env|^os\.environ""",
    re.IGNORECASE,
)


def es_marcador(valor: str) -> bool:
    """¿El valor tiene pinta de ser un ejemplo o un hueco por rellenar?"""
    bajo = valor.lower()
    if any(marcador in bajo for marcador in _MARCADORES):
        return True
    if _INTERPOLACION.search(valor):
        return True
    # Un solo carácter repetido ('xxxxxxxx', '00000000').
    return len(set(bajo)) <= 2


def redacta(secreto: str) -> str:
    """Deja ver lo justo para identificarlo sin publicarlo otra vez.

    El informe puede acabar en un log de CI o en un ticket, así que nunca debe
    contener el secreto entero.
    """
    if len(secreto) <= 8:
        return "*" * len(secreto)
    return f"{secreto[:4]}{'*' * min(len(secreto) - 6, 24)}{secreto[-2:]}"
