"""Pruebas del verificador TLS.

Los certificados se generan al vuelo con `cryptography`, así que las
comprobaciones se ejercitan sin abrir ninguna conexión.
"""

from __future__ import annotations

import ssl
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from atalaya.core.finding import CheckStatus, EvaluationStatus, FindingKind, Severity
from atalaya.core.module import Coverage
from atalaya.modules.tls_check import Soporte, TlsInput, TlsModule, _limpia_host

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


# -- fallos de red: rechazo frente a "no se pudo determinar" -------------------


class _SocketFalso:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def close(self):
        pass


@pytest.fixture
def red(monkeypatch):
    """Controla la conexión TCP y el handshake de `_soporta` sin tocar la red.

    `red(conectar=..., handshake=...)`: cada uno es una excepción a lanzar o None
    para que esa fase salga bien.
    """

    def instalar(conectar: BaseException | None = None, handshake: BaseException | None = None):
        def create_connection(*args, **kwargs):
            if conectar is not None:
                raise conectar
            return _SocketFalso()

        def wrap_socket(self, sock, server_hostname=None):
            if handshake is not None:
                raise handshake
            return _SocketFalso()

        monkeypatch.setattr("atalaya.modules.tls_check.socket.create_connection", create_connection)
        monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap_socket)

    return instalar


def _error_ssl(reason: str) -> ssl.SSLError:
    exc = ssl.SSLError(1, f"[SSL: {reason}] {reason.lower()}")
    exc.reason = reason
    return exc


class TestSoporteDeVersion:
    V12 = ssl.TLSVersion.TLSv1_2

    def test_handshake_completo_es_aceptada(self, red):
        red()
        assert modulo._soporta("x.com", 443, 5, self.V12)[0] is Soporte.SI

    def test_alerta_tls_es_rechazo(self, red):
        red(handshake=_error_ssl("TLSV1_ALERT_PROTOCOL_VERSION"))
        assert modulo._soporta("x.com", 443, 5, self.V12)[0] is Soporte.NO

    @pytest.mark.parametrize("corte", [ConnectionResetError(), ssl.SSLEOFError()])
    def test_que_el_servidor_corte_el_handshake_es_rechazo(self, red, corte):
        red(handshake=corte)
        assert modulo._soporta("x.com", 443, 5, self.V12)[0] is Soporte.NO

    def test_timeout_en_el_handshake_no_es_un_rechazo(self, red):
        red(handshake=TimeoutError("The handshake operation timed out"))
        estado, detalle = modulo._soporta("x.com", 443, 5, self.V12)
        assert estado is Soporte.INCIERTO
        assert "5 s" in detalle

    @pytest.mark.parametrize(
        "fallo", [TimeoutError("timed out"), ConnectionRefusedError("refused"), OSError("no route")]
    )
    def test_no_poder_conectar_no_dice_nada_de_la_version(self, red, fallo):
        red(conectar=fallo)
        estado, detalle = modulo._soporta("x.com", 443, 5, self.V12)
        assert estado is Soporte.INCIERTO
        assert "conexión" in detalle

    def test_sin_protocolos_disponibles_es_limitacion_local(self, red):
        red(handshake=_error_ssl("NO_PROTOCOLS_AVAILABLE"))
        estado, detalle = modulo._soporta("x.com", 443, 5, self.V12)
        assert estado is Soporte.LOCAL
        assert "OpenSSL" in detalle


class TestProtocolos:
    def _probar(self, monkeypatch, estados: dict[str, Soporte], negociado: str = "TLSv1.3"):
        etiquetas = {
            ssl.TLSVersion.TLSv1_3: "TLSv1.3",
            ssl.TLSVersion.TLSv1_2: "TLSv1.2",
            ssl.TLSVersion.TLSv1_1: "TLSv1.1",
            ssl.TLSVersion.TLSv1: "TLSv1.0",
        }

        def soporta(host, port, timeout, version):
            estado = estados[etiquetas[version]]
            return estado, None if estado in (Soporte.SI, Soporte.NO) else "motivo"

        monkeypatch.setattr(modulo, "_soporta", soporta)
        cov = Coverage()
        findings = modulo._check_protocolos("x.com", 443, 5, negociado, cov)
        return findings, {c.id: c.status for c in cov.checks}

    def test_timeouts_en_las_modernas_no_dan_un_critico_falso(self, monkeypatch):
        """Antes un timeout contaba como rechazo y salía «no acepta TLS 1.2 ni 1.3»."""
        findings, checks = self._probar(
            monkeypatch,
            {
                "TLSv1.3": Soporte.INCIERTO,
                "TLSv1.2": Soporte.INCIERTO,
                "TLSv1.1": Soporte.NO,
                "TLSv1.0": Soporte.NO,
            },
            negociado="desconocido",
        )
        assert Severity.CRITICAL not in gravedades(findings)
        assert checks["protocolo-TLSv1.2"] is CheckStatus.UNDETERMINED
        assert checks["protocolo-TLSv1.0"] is CheckStatus.DONE

    def test_si_ambas_modernas_se_rechazan_es_critico(self, monkeypatch):
        findings, _ = self._probar(
            monkeypatch,
            {
                "TLSv1.3": Soporte.NO,
                "TLSv1.2": Soporte.NO,
                "TLSv1.1": Soporte.SI,
                "TLSv1.0": Soporte.SI,
            },
            negociado="TLSv1.1",
        )
        assert Severity.CRITICAL in gravedades(findings)

    def test_la_version_negociada_cuenta_como_aceptada(self, monkeypatch):
        """Si la sonda de TLS 1.3 falla por red pero el handshake principal lo usó, se sabe."""
        findings, checks = self._probar(
            monkeypatch,
            {
                "TLSv1.3": Soporte.INCIERTO,
                "TLSv1.2": Soporte.SI,
                "TLSv1.1": Soporte.NO,
                "TLSv1.0": Soporte.NO,
            },
        )
        assert checks["protocolo-TLSv1.3"] is CheckStatus.DONE
        assert not any("TLS 1.3" in f.title for f in findings)

    def test_una_version_obsoleta_aceptada_es_vulnerabilidad(self, monkeypatch):
        findings, _ = self._probar(
            monkeypatch,
            {
                "TLSv1.3": Soporte.SI,
                "TLSv1.2": Soporte.SI,
                "TLSv1.1": Soporte.NO,
                "TLSv1.0": Soporte.SI,
            },
        )
        obsoletas = [f for f in findings if "acepta TLSv1.0" in f.title]
        assert obsoletas and obsoletas[0].kind is FindingKind.VULNERABILITY

    def test_sin_tls13_confirmado_avisa_en_bajo(self, monkeypatch):
        findings, _ = self._probar(
            monkeypatch,
            {
                "TLSv1.3": Soporte.NO,
                "TLSv1.2": Soporte.SI,
                "TLSv1.1": Soporte.NO,
                "TLSv1.0": Soporte.NO,
            },
            negociado="TLSv1.2",
        )
        assert any("no ofrece TLS 1.3" in f.title for f in findings)


class TestAnalisisTls:
    """El análisis entero con las conexiones sustituidas."""

    def _preparar(self, monkeypatch, soporte: Soporte = Soporte.NO):
        der = cert(emisor="CA de pruebas").public_bytes(serialization.Encoding.DER)
        monkeypatch.setattr(modulo, "_verificar", lambda host, port, timeout: None)
        monkeypatch.setattr(
            modulo,
            "_recoger",
            lambda host, port, timeout: (
                der,
                "TLSv1.3",
                ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
            ),
        )

        def soporta(host, port, timeout, version):
            if version >= ssl.TLSVersion.TLSv1_2:
                return Soporte.SI, None
            return soporte, None if soporte is Soporte.NO else "sin respuesta en 5 s"

        monkeypatch.setattr(modulo, "_soporta", soporta)

    def test_todo_concluido_da_nota(self, monkeypatch):
        self._preparar(monkeypatch)
        r = modulo.scan(TlsInput(host="x.com"))
        assert r.status is EvaluationStatus.COMPLETE
        assert r.grade is not None
        assert r.coverage()["undetermined"] == 0

    def test_un_timeout_en_tls10_deja_el_analisis_incompleto(self, monkeypatch):
        self._preparar(monkeypatch, soporte=Soporte.INCIERTO)
        r = modulo.scan(TlsInput(host="x.com"))
        assert r.status is EvaluationStatus.INCOMPLETE
        assert r.grade is None
        assert {c.id for c in r.pending_checks} == {"protocolo-TLSv1.1", "protocolo-TLSv1.0"}

    def test_desactivar_los_protocolos_es_una_omision(self, monkeypatch):
        self._preparar(monkeypatch)
        r = modulo.scan(TlsInput(host="x.com", check_protocols=False))
        assert r.status is EvaluationStatus.COMPLETE
        assert r.coverage()["skipped"] == 1

    def test_si_no_se_puede_conectar_no_se_evalua(self, monkeypatch):
        def sin_red(host, port, timeout):
            raise TimeoutError("timed out")

        monkeypatch.setattr(modulo, "_verificar", sin_red)
        r = modulo.scan(TlsInput(host="x.com"))
        assert r.status is EvaluationStatus.NOT_EVALUATED
        assert r.grade is None
