"""Pruebas del auditor de cabeceras HTTP.

Las comprobaciones reciben ya las cabeceras normalizadas, así que se pueden
probar una a una sin tocar la red.
"""

from __future__ import annotations

import httpx
import pytest

from atalaya.core.finding import EvaluationStatus, FindingKind, Severity
from atalaya.core.report import render_json
from atalaya.modules.http_headers import (
    ORIGEN_SONDA,
    HttpHeadersInput,
    HttpHeadersModule,
    cookie_redactada,
    parse_cookie,
    parse_csp,
)

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
    def test_comodin_con_credenciales_no_es_explotable_por_si_solo(self):
        """Los navegadores rechazan esa combinación; lo explotable es reflejar el Origin."""
        findings = modulo._check_cors(
            {
                "access-control-allow-origin": "*",
                "access-control-allow-credentials": "true",
            }
        )
        assert gravedades(findings) == {Severity.LOW}
        assert findings[0].kind is FindingKind.HARDENING

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


class TestCookiesParser:
    """Los atributos se leen por separado del nombre y del valor."""

    def _respuesta(self, *cookies: str) -> httpx.Response:
        return httpx.Response(200, headers=[("set-cookie", c) for c in cookies])

    def test_el_nombre_secure_session_no_cuenta_como_atributo_secure(self):
        findings = modulo._check_cookies(
            self._respuesta("secure_session=abc; HttpOnly; SameSite=Lax"), es_https=True
        )
        assert gravedades(findings) == {Severity.HIGH}
        assert "Secure" in findings[0].title

    def test_un_valor_con_palabras_de_atributo_no_engana(self):
        findings = modulo._check_cookies(
            self._respuesta("sid=httponly-secure-samesite"), es_https=True
        )
        assert gravedades(findings) == {Severity.HIGH, Severity.MEDIUM, Severity.LOW}

    def test_los_atributos_no_distinguen_mayusculas_ni_espacios(self):
        findings = modulo._check_cookies(
            self._respuesta("sid=abc;secure ;  HTTPONLY;samesite = strict"), es_https=True
        )
        assert gravedades(findings) == {Severity.OK}

    def test_la_evidencia_oculta_el_valor(self):
        secreto = "eyJhbGciOiJIUzI1NiJ9.s3cr3t0"
        findings = modulo._check_cookies(
            self._respuesta(f"session={secreto}; Path=/; HttpOnly"), es_https=True
        )
        assert findings
        for f in findings:
            assert secreto not in (f.evidence or "")
            assert f.evidence == "session=[OCULTO]; Path=/; HttpOnly"

    def test_un_atributo_desconocido_tambien_se_oculta(self):
        cookie = parse_cookie("sid=abc; X-Debug=token123; Secure")
        assert cookie_redactada(cookie) == "sid=[OCULTO]; X-Debug=[OCULTO]; Secure"

    def test_las_cookies_de_borrado_no_se_evaluan(self):
        respuesta = self._respuesta(
            "sid=; Path=/",
            "old=x; Max-Age=0",
            "older=x; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
        )
        assert modulo._check_cookies(respuesta, es_https=True) == []

    def test_samesite_none_sin_secure(self):
        findings = modulo._check_cookies(
            self._respuesta("sid=abc; HttpOnly; SameSite=None"), es_https=False
        )
        assert gravedades(findings) == {Severity.MEDIUM}
        assert "SameSite=None" in findings[0].title

    def test_samesite_no_valido(self):
        findings = modulo._check_cookies(
            self._respuesta("sid=abc; Secure; HttpOnly; SameSite=Siempre"), es_https=True
        )
        assert gravedades(findings) == {Severity.LOW}

    def test_prefijo_host_exige_path_y_sin_domain(self):
        findings = modulo._check_cookies(
            self._respuesta("__Host-sid=abc; Secure; HttpOnly; SameSite=Lax; Domain=x.com"),
            es_https=True,
        )
        assert any("__Host-" in f.title for f in findings)

    def test_prefijo_host_bien_puesto(self):
        findings = modulo._check_cookies(
            self._respuesta("__Host-sid=abc; Secure; HttpOnly; SameSite=Lax; Path=/"),
            es_https=True,
        )
        assert gravedades(findings) == {Severity.OK}


class TestCspInterpretada:
    def _csp(self, valor: str):
        return modulo._check_csp({"content-security-policy": valor})

    def test_unsafe_inline_en_style_src_no_es_un_problema_de_scripts(self):
        findings = self._csp("default-src 'self'; style-src 'unsafe-inline'; base-uri 'self'")
        assert gravedades(findings) == {Severity.OK}

    def test_unsafe_inline_con_nonce_queda_neutralizado(self):
        findings = self._csp(
            "default-src 'self'; script-src 'nonce-abc' 'unsafe-inline'; base-uri 'self'"
        )
        assert gravedades(findings) == {Severity.OK}

    @pytest.mark.parametrize("fuente", ["https:", "*", "https://*", "data:"])
    def test_fuentes_que_admiten_cualquier_origen(self, fuente):
        findings = self._csp(f"default-src 'self'; script-src {fuente}; base-uri 'self'")
        assert any("cualquier origen" in f.title for f in findings)

    def test_strict_dynamic_ignora_la_lista_de_hosts(self):
        findings = self._csp(
            "script-src 'nonce-abc' 'strict-dynamic' https: 'unsafe-inline'; "
            "object-src 'none'; base-uri 'none'"
        )
        assert gravedades(findings) == {Severity.OK}

    def test_varias_politicas_se_suman(self):
        """Si una de las dos restringe, el comodín de la otra no abre nada."""
        findings = self._csp("script-src *; object-src 'none'; base-uri 'self', script-src 'self'")
        assert not any("cualquier origen" in f.title for f in findings)

    def test_la_directiva_se_lee_por_nombre_no_por_subcadena(self):
        """`script-src-elem` no es `script-src`."""
        politicas = parse_csp("script-src-elem 'self'; default-src *")
        assert set(politicas[0]) == {"script-src-elem", "default-src"}

    def test_sin_object_src_ni_default_src(self):
        findings = self._csp("script-src 'self'; base-uri 'self'")
        assert any("object-src" in f.title for f in findings)


class TestFrameAncestors:
    def _check(self, csp: str, xfo: str | None = None):
        cabeceras = {"content-security-policy": csp}
        if xfo:
            cabeceras["x-frame-options"] = xfo
        return modulo._check_frame_options(cabeceras)

    @pytest.mark.parametrize("valor", ["*", "https:", "https://*", "* 'self'"])
    def test_abierto_a_cualquier_origen_no_protege(self, valor):
        findings = self._check(f"frame-ancestors {valor}")
        assert gravedades(findings) == {Severity.MEDIUM}
        assert "cualquier sitio" in findings[0].title

    def test_la_csp_manda_sobre_x_frame_options(self):
        """Con frame-ancestors presente, el navegador ignora X-Frame-Options."""
        findings = self._check("frame-ancestors *", xfo="DENY")
        assert gravedades(findings) == {Severity.MEDIUM}

    @pytest.mark.parametrize(
        "valor", ["'none'", "'self'", "https://socio.com", "'self' https://*.socio.com", ""]
    )
    def test_valores_que_restringen(self, valor):
        findings = self._check(f"default-src 'self'; frame-ancestors {valor}")
        assert gravedades(findings) == {Severity.OK}

    def test_la_lista_de_origenes_aparece_en_la_evidencia(self):
        findings = self._check("frame-ancestors 'self' https://socio.com")
        assert "https://socio.com" in findings[0].evidence

    def test_solo_en_modo_informe_no_protege(self):
        findings = modulo._check_frame_options(
            {"content-security-policy-report-only": "frame-ancestors 'none'"}
        )
        assert gravedades(findings) == {Severity.MEDIUM}

    def test_mencionarlo_en_otro_sitio_no_cuenta(self):
        """El texto frame-ancestors dentro de un report-uri no es la directiva."""
        findings = self._check("default-src 'self'; report-uri /frame-ancestors")
        assert gravedades(findings) == {Severity.MEDIUM}


class TestCabecerasDeLista:
    def test_x_frame_options_contradictorio(self):
        findings = modulo._check_frame_options({"x-frame-options": "DENY, SAMEORIGIN"})
        assert gravedades(findings) == {Severity.MEDIUM}
        assert "contradictorios" in findings[0].description

    def test_x_frame_options_repetido_igual(self):
        findings = modulo._check_frame_options({"x-frame-options": "DENY, deny"})
        assert gravedades(findings) == {Severity.OK}

    def test_nosniff_repetido(self):
        findings = modulo._check_content_type_options(
            {"x-content-type-options": "nosniff, nosniff"}
        )
        assert gravedades(findings) == {Severity.OK}

    def test_referrer_policy_gana_el_ultimo_valor_valido(self):
        findings = modulo._check_referrer_policy(
            {"referrer-policy": "unsafe-url, strict-origin-when-cross-origin"}
        )
        assert gravedades(findings) == {Severity.OK}

    def test_referrer_policy_sin_valores_validos(self):
        findings = modulo._check_referrer_policy({"referrer-policy": "nunca"})
        assert gravedades(findings) == {Severity.LOW}

    def test_hsts_sin_max_age_no_vale(self):
        findings = modulo._check_hsts({"strict-transport-security": "includeSubDomains"}, True)
        assert gravedades(findings) == {Severity.HIGH}
        assert "no válida" in findings[0].title

    def test_hsts_repetido_solo_cuenta_el_primero(self):
        findings = modulo._check_hsts(
            {"strict-transport-security": "max-age=0, max-age=31536000; includeSubDomains"},
            True,
        )
        assert any("max-age=0" in f.title for f in findings)

    def test_hsts_con_max_age_entre_comillas(self):
        findings = modulo._check_hsts(
            {"strict-transport-security": 'max-age="31536000"; includeSubDomains'}, True
        )
        assert gravedades(findings) == {Severity.OK}


class TestReflejoCors:
    def test_reflejo_con_credenciales_es_vulnerabilidad(self):
        findings = modulo._check_cors_reflejo(
            {
                "access-control-allow-origin": ORIGEN_SONDA,
                "access-control-allow-credentials": "true",
            }
        )
        assert gravedades(findings) == {Severity.HIGH}
        assert findings[0].kind is FindingKind.VULNERABILITY

    def test_reflejo_sin_credenciales(self):
        findings = modulo._check_cors_reflejo({"access-control-allow-origin": ORIGEN_SONDA})
        assert gravedades(findings) == {Severity.LOW}
        assert findings[0].kind is FindingKind.HARDENING

    def test_sin_reflejo_no_dice_nada(self):
        assert modulo._check_cors_reflejo({"access-control-allow-origin": "https://a.com"}) == []


# -- análisis completo contra un servidor simulado -----------------------------

CABECERAS_SANAS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": (
        "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    ),
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=()",
}


@pytest.fixture
def servidor(monkeypatch):
    """Sustituye la red: `servidor(fn)` hace que fn conteste las peticiones del módulo."""

    def instalar(manejador):
        original = httpx.Client

        def cliente(*args, **kwargs):
            return original(*args, transport=httpx.MockTransport(manejador), **kwargs)

        monkeypatch.setattr("atalaya.modules.http_headers.httpx.Client", cliente)

    return instalar


class TestAnalisisCompleto:
    def test_un_sitio_sano_tiene_nota_y_cobertura_completa(self, servidor):
        servidor(lambda request: httpx.Response(200, headers=CABECERAS_SANAS))
        r = modulo.scan(HttpHeadersInput(url="https://ejemplo.com"))
        assert r.status is EvaluationStatus.COMPLETE
        assert r.grade == "A+"
        assert r.coverage()["undetermined"] == 0
        assert {c.id for c in r.checks} >= {"csp", "cookies", "clickjacking", "cors-reflejo"}

    def test_si_no_hay_red_no_se_evalua(self, servidor):
        def sin_red(request):
            raise httpx.ConnectError("sin ruta al host", request=request)

        servidor(sin_red)
        r = modulo.scan(HttpHeadersInput(url="https://ejemplo.com"))
        assert r.status is EvaluationStatus.NOT_EVALUATED
        assert r.grade is None
        assert "ConnectError" in r.error

    def test_si_falla_la_sonda_cors_queda_incompleto(self, servidor):
        def manejador(request):
            if "origin" in request.headers:
                raise httpx.ReadTimeout("lento", request=request)
            return httpx.Response(200, headers=CABECERAS_SANAS)

        servidor(manejador)
        r = modulo.scan(HttpHeadersInput(url="https://ejemplo.com"))
        assert r.status is EvaluationStatus.INCOMPLETE
        assert r.grade is None
        assert [c.id for c in r.pending_checks] == ["cors-reflejo"]

    def test_la_sonda_detecta_el_reflejo(self, servidor):
        def manejador(request):
            cabeceras = dict(CABECERAS_SANAS)
            if "origin" in request.headers:
                cabeceras["access-control-allow-origin"] = request.headers["origin"]
                cabeceras["access-control-allow-credentials"] = "true"
            return httpx.Response(200, headers=cabeceras)

        servidor(manejador)
        r = modulo.scan(HttpHeadersInput(url="https://ejemplo.com"))
        assert any(f.kind is FindingKind.VULNERABILITY for f in r.findings)

    def test_desactivar_la_sonda_es_una_omision_y_no_quita_la_nota(self, servidor):
        servidor(lambda request: httpx.Response(200, headers=CABECERAS_SANAS))
        r = modulo.scan(HttpHeadersInput(url="https://ejemplo.com", probe_cors=False))
        assert r.status is EvaluationStatus.COMPLETE
        assert r.coverage()["skipped"] == 1

    def test_el_informe_json_no_contiene_el_valor_de_la_cookie(self, servidor):
        secreto = "f3a9c1d7e5b2-sesion-real"
        servidor(
            lambda request: httpx.Response(
                200, headers=[*CABECERAS_SANAS.items(), ("set-cookie", f"sid={secreto}")]
            )
        )
        informe = render_json(modulo.scan(HttpHeadersInput(url="https://ejemplo.com")))
        assert secreto not in informe
        assert "sid=[OCULTO]" in informe
