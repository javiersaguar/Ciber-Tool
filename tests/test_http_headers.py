"""Pruebas del auditor de cabeceras HTTP.

Las comprobaciones reciben ya las cabeceras normalizadas, así que se pueden
probar una a una sin tocar la red.
"""

from __future__ import annotations

import httpx
import pytest

from atalaya.core.finding import Severity
from atalaya.modules.http_headers import HttpHeadersInput, HttpHeadersModule

modulo = HttpHeadersModule()


def gravedades(findings) -> set[Severity]:
    return {f.severity for f in findings}


def titulos(findings) -> str:
    return " | ".join(f.title for f in findings)


class TestHsts:
    def test_ausente_es_grave(self):
        findings = modulo._check_hsts({}, es_https=True)
        assert gravedades(findings) == {Severity.HIGH}
        assert "HSTS" in titulos(findings)

    def test_no_se_evalua_sobre_http(self):
        assert modulo._check_hsts({}, es_https=False) == []

    def test_max_age_corto(self):
        findings = modulo._check_hsts(
            {"strict-transport-security": "max-age=3600; includeSubDomains"}, True
        )
        assert Severity.MEDIUM in gravedades(findings)

    def test_max_age_cero_desactiva_la_politica(self):
        findings = modulo._check_hsts({"strict-transport-security": "max-age=0"}, True)
        assert Severity.HIGH in gravedades(findings)

    def test_sin_subdominios_avisa_en_bajo(self):
        findings = modulo._check_hsts({"strict-transport-security": "max-age=31536000"}, True)
        assert Severity.OK in gravedades(findings)
        assert Severity.LOW in gravedades(findings)

    def test_configuracion_correcta(self):
        findings = modulo._check_hsts(
            {"strict-transport-security": "max-age=31536000; includeSubDomains; preload"}, True
        )
        assert gravedades(findings) == {Severity.OK}


class TestCsp:
    def test_ausente_es_grave(self):
        findings = modulo._check_csp({})
        assert gravedades(findings) == {Severity.HIGH}

    def test_solo_informe_no_protege(self):
        findings = modulo._check_csp({"content-security-policy-report-only": "default-src 'self'"})
        assert gravedades(findings) == {Severity.MEDIUM}
        assert "informe" in titulos(findings)

    @pytest.mark.parametrize("directiva", ["'unsafe-inline'", "'unsafe-eval'"])
    def test_directivas_peligrosas(self, directiva):
        findings = modulo._check_csp(
            {
                "content-security-policy": (
                    f"default-src 'self'; script-src {directiva}; base-uri 'self'"
                )
            }
        )
        assert Severity.MEDIUM in gravedades(findings)

    def test_comodin_en_script_src(self):
        findings = modulo._check_csp(
            {"content-security-policy": "default-src 'self'; script-src *; base-uri 'self'"}
        )
        assert Severity.MEDIUM in gravedades(findings)

    def test_un_dominio_con_asterisco_no_es_comodin(self):
        """script-src *.cdn.com restringe; no debe confundirse con el comodín suelto."""
        findings = modulo._check_csp(
            {"content-security-policy": "default-src 'self'; script-src *.cdn.com; base-uri 'self'"}
        )
        assert gravedades(findings) == {Severity.OK}

    def test_politica_razonable(self):
        findings = modulo._check_csp(
            {"content-security-policy": "default-src 'self'; object-src 'none'; base-uri 'self'"}
        )
        assert gravedades(findings) == {Severity.OK}


class TestClickjacking:
    def test_sin_nada_avisa(self):
        findings = modulo._check_frame_options({})
        assert gravedades(findings) == {Severity.MEDIUM}

    def test_frame_ancestors_es_suficiente(self):
        findings = modulo._check_frame_options(
            {"content-security-policy": "frame-ancestors 'none'"}
        )
        assert gravedades(findings) == {Severity.OK}

    @pytest.mark.parametrize("valor", ["DENY", "SAMEORIGIN", "sameorigin"])
    def test_valores_validos(self, valor):
        findings = modulo._check_frame_options({"x-frame-options": valor})
        assert gravedades(findings) == {Severity.OK}

    def test_allow_from_esta_obsoleto(self):
        findings = modulo._check_frame_options({"x-frame-options": "ALLOW-FROM https://x.com"})
        assert gravedades(findings) == {Severity.MEDIUM}


class TestCorsYVarias:
    def test_comodin_con_credenciales_es_grave(self):
        findings = modulo._check_cors(
            {
                "access-control-allow-origin": "*",
                "access-control-allow-credentials": "true",
            }
        )
        assert gravedades(findings) == {Severity.HIGH}

    def test_comodin_solo_es_informativo(self):
        findings = modulo._check_cors({"access-control-allow-origin": "*"})
        assert gravedades(findings) == {Severity.LOW}

    def test_sin_cors_no_dice_nada(self):
        assert modulo._check_cors({}) == []

    def test_nosniff_correcto(self):
        findings = modulo._check_content_type_options({"x-content-type-options": "nosniff"})
        assert gravedades(findings) == {Severity.OK}

    def test_referrer_policy_permisiva(self):
        findings = modulo._check_referrer_policy({"referrer-policy": "unsafe-url"})
        assert gravedades(findings) == {Severity.MEDIUM}

    def test_xss_protection_obsoleta(self):
        findings = modulo._check_legacy_xss({"x-xss-protection": "1; mode=block"})
        assert gravedades(findings) == {Severity.LOW}

    def test_xss_protection_desactivada_es_correcto(self):
        assert modulo._check_legacy_xss({"x-xss-protection": "0"}) == []


class TestFugaDeVersiones:
    def test_server_con_version(self):
        findings = modulo._check_info_leak({"server": "nginx/1.18.0"})
        assert gravedades(findings) == {Severity.LOW}

    def test_server_sin_version_no_avisa(self):
        assert modulo._check_info_leak({"server": "nginx"}) == []

    def test_varias_cabeceras_suman(self):
        findings = modulo._check_info_leak({"server": "Apache/2.4.1", "x-powered-by": "PHP/8.1.2"})
        assert len(findings) == 2


class TestCookies:
    def _respuesta(self, *cookies: str) -> httpx.Response:
        return httpx.Response(200, headers=[("set-cookie", c) for c in cookies])

    def test_cookie_sin_atributos_acumula_avisos(self):
        findings = modulo._check_cookies(self._respuesta("sid=abc123"), es_https=True)
        assert gravedades(findings) == {Severity.HIGH, Severity.MEDIUM, Severity.LOW}

    def test_cookie_bien_configurada(self):
        findings = modulo._check_cookies(
            self._respuesta("sid=abc; Secure; HttpOnly; SameSite=Strict"), es_https=True
        )
        assert gravedades(findings) == {Severity.OK}

    def test_secure_no_se_exige_sobre_http(self):
        findings = modulo._check_cookies(
            self._respuesta("sid=abc; HttpOnly; SameSite=Lax"), es_https=False
        )
        assert gravedades(findings) == {Severity.OK}

    def test_sin_cookies_no_dice_nada(self):
        assert modulo._check_cookies(self._respuesta(), es_https=True) == []

    def test_el_nombre_de_la_cookie_aparece_en_el_hallazgo(self):
        findings = modulo._check_cookies(self._respuesta("token=x; Secure"), es_https=True)
        assert all("token" in f.title for f in findings)


class TestEntradas:
    def test_el_user_agent_por_defecto_es_ascii(self):
        """Las cabeceras HTTP no admiten caracteres fuera de ASCII."""
        HttpHeadersInput(url="x.com").user_agent.encode("ascii")

    def test_el_timeout_debe_ser_positivo(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            HttpHeadersInput(url="x.com", timeout=0)

    def test_el_objetivo_es_el_primer_campo(self):
        assert modulo.target_of(HttpHeadersInput(url="ejemplo.com")) == "ejemplo.com"
