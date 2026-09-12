"""Pruebas del verificador TLS.

Los certificados se generan al vuelo con `cryptography`, así que las
comprobaciones se ejercitan sin abrir ninguna conexión.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from atalaya.core.finding import Severity
from atalaya.modules.tls_check import TlsInput, TlsModule, _limpia_host

modulo = TlsModule()


def gravedades(findings) -> set[Severity]:
    return {f.severity for f in findings}


def cert(
    *,
    dias_restantes: int = 90,
    vigencia_dias: int | None = None,
    algoritmo=None,
    clave=None,
    emisor: str | None = None,
    sans: list[str] | None = ("ejemplo.com",),
) -> x509.Certificate:
    """Construye un certificado a medida para lo que quiera probar cada test."""
    clave = clave or ec.generate_private_key(ec.SECP256R1())
    ahora = datetime.now(timezone.utc)
    fin = ahora + timedelta(days=dias_restantes)
    inicio = fin - timedelta(days=vigencia_dias if vigencia_dias is not None else 90)

    sujeto = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ejemplo.com")])
    nombre_emisor = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, emisor)] if emisor else sujeto
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(sujeto)
        .issuer_name(nombre_emisor)
        .public_key(clave.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(inicio)
        .not_valid_after(fin)
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in sans]), critical=False
        )
    return builder.sign(clave, algoritmo or hashes.SHA256())


class TestLimpiaHost:
    @pytest.mark.parametrize(
        ("entrada", "esperado"),
        [
            ("ejemplo.com", "ejemplo.com"),
            ("https://ejemplo.com", "ejemplo.com"),
            ("https://ejemplo.com/ruta?a=1", "ejemplo.com"),
            ("http://ejemplo.com:8443", "ejemplo.com"),
            ("  ejemplo.com  ", "ejemplo.com"),
            ("[2001:db8::1]", "[2001:db8::1]"),
        ],
    )
    def test_extrae_el_dominio(self, entrada, esperado):
        assert _limpia_host(entrada) == esperado

    def test_el_objetivo_incluye_el_puerto(self):
        assert modulo.target_of(TlsInput(host="https://x.com/a", port=8443)) == "x.com:8443"


class TestVigencia:
    def test_certificado_sano(self):
        findings = modulo._check_vigencia(cert(dias_restantes=90))
        assert gravedades(findings) == {Severity.OK}

    @pytest.mark.parametrize(
        ("dias", "gravedad"),
        [(3, Severity.CRITICAL), (12, Severity.HIGH), (25, Severity.MEDIUM), (60, Severity.OK)],
    )
    def test_umbrales_de_caducidad(self, dias, gravedad):
        findings = modulo._check_vigencia(cert(dias_restantes=dias))
        assert gravedad in gravedades(findings)

    def test_certificado_caducado(self):
        findings = modulo._check_vigencia(cert(dias_restantes=-10))
        assert Severity.CRITICAL in gravedades(findings)
        assert any("caducado" in f.title for f in findings)

    def test_vigencia_excesiva(self):
        findings = modulo._check_vigencia(cert(dias_restantes=90, vigencia_dias=800))
        assert Severity.LOW in gravedades(findings)
        assert any("validez excesivo" in f.title for f in findings)


class TestFirma:
    def test_sha256_es_correcto(self):
        findings = modulo._check_firma(cert())
        assert gravedades(findings) == {Severity.OK}

    @pytest.mark.parametrize(
        ("algoritmo", "fragmento"),
        [("sha1", "SHA-1"), ("md5", "MD5")],
    )
    def test_firmas_obsoletas_son_criticas(self, algoritmo, fragmento):
        """`cryptography` ya no permite firmar con SHA-1 ni MD5, así que se usa un doble.

        Los certificados que hay ahí fuera sí los llevan, y es justo lo que el
        módulo tiene que detectar.
        """
        falso = SimpleNamespace(
            signature_hash_algorithm=SimpleNamespace(name=algoritmo),
            signature_algorithm_oid=SimpleNamespace(_name=f"{algoritmo}WithRSAEncryption"),
        )
        findings = modulo._check_firma(falso)
        assert gravedades(findings) == {Severity.CRITICAL}
        assert fragmento in findings[0].title


class TestClave:
    def test_rsa_2048_es_correcto(self):
        clave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        findings = modulo._check_clave(cert(clave=clave))
        assert gravedades(findings) == {Severity.OK}

    def test_rsa_1024_es_debil(self):
        clave = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        findings = modulo._check_clave(cert(clave=clave))
        assert gravedades(findings) == {Severity.HIGH}

    def test_curva_p256_es_correcta(self):
        findings = modulo._check_clave(cert())
        assert gravedades(findings) == {Severity.OK}


class TestNombres:
    def test_sin_san_es_grave(self):
        findings = modulo._check_nombres(cert(sans=None))
        assert gravedades(findings) == {Severity.HIGH}

    def test_lista_los_nombres_cubiertos(self):
        findings = modulo._check_nombres(cert(sans=["a.com", "b.com"]))
        assert "a.com" in findings[0].evidence

    def test_detecta_certificado_comodin(self):
        findings = modulo._check_nombres(cert(sans=["*.ejemplo.com"]))
        assert any("comodín" in f.title for f in findings)


class TestAutofirmado:
    def test_emisor_igual_a_sujeto(self):
        findings = modulo._check_autofirmado(cert(), error_verificacion=None)
        assert gravedades(findings) == {Severity.HIGH}

    def test_emitido_por_una_ca(self):
        findings = modulo._check_autofirmado(cert(emisor="Mi CA"), error_verificacion=None)
        assert findings == []

    def test_no_duplica_si_la_validacion_ya_fallo(self):
        findings = modulo._check_autofirmado(cert(), error_verificacion="self-signed certificate")
        assert findings == []


class TestCifrado:
    def test_suite_moderna(self):
        findings = modulo._check_cifrado("TLSv1.3", ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256))
        assert gravedades(findings) == {Severity.OK}

    @pytest.mark.parametrize(
        "suite", ["ECDHE-RSA-RC4-SHA", "DES-CBC3-SHA", "NULL-SHA", "EXP-RC2-CBC-MD5"]
    )
    def test_suites_debiles(self, suite):
        findings = modulo._check_cifrado("TLSv1.2", (suite, "TLSv1.2", 128))
        assert Severity.HIGH in gravedades(findings)

    def test_clave_de_sesion_corta(self):
        findings = modulo._check_cifrado("TLSv1.2", ("ECDHE-RSA-AES64-GCM-SHA256", "TLSv1.2", 64))
        assert Severity.HIGH in gravedades(findings)

    def test_sin_cifrado_negociado(self):
        assert modulo._check_cifrado("TLSv1.3", ()) == []


class TestVerificacion:
    def test_caducado_lo_reporta_la_comprobacion_de_vigencia(self):
        """No se duplica: `_check_vigencia` lo cuenta con fecha y días exactos."""
        assert modulo._finding_verificacion("certificate has expired") is None

    def test_nombre_que_no_casa_es_critico(self):
        hallazgo = modulo._finding_verificacion(
            "Hostname mismatch, certificate is not valid for 'x.com'."
        )
        assert hallazgo.severity is Severity.CRITICAL

    def test_autofirmado_es_alto(self):
        hallazgo = modulo._finding_verificacion("self-signed certificate")
        assert hallazgo.severity is Severity.HIGH

    def test_error_desconocido_no_se_pierde(self):
        hallazgo = modulo._finding_verificacion("algo raro del handshake")
        assert hallazgo.severity is Severity.HIGH
        assert "algo raro" in hallazgo.evidence
