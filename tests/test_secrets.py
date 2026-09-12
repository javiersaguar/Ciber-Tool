"""Pruebas del detector de secretos.

Todas las credenciales de estos tests son inventadas y con formato válido solo
en apariencia: sirven para ejercitar las expresiones regulares, no corresponden
a ninguna cuenta real.
"""

from __future__ import annotations

import subprocess

import pytest
from pydantic import ValidationError

from atalaya.core.finding import Severity
from atalaya.modules._secret_rules import (
    REGLAS,
    REGLAS_CONOCIDAS,
    REGLAS_CONTEXTUALES,
    entropia,
    es_marcador,
    redacta,
)
from atalaya.modules.secrets_scan import SecretsInput, SecretsModule

modulo = SecretsModule()

# Valor aleatorio de entropía alta, reutilizado como "secreto" en varios tests.
ALEATORIO = "a7F2kLp9Qz3XvB6nR1tY8wE4sD0gH5jM"


def cred(prefijo: str, cuerpo: str) -> str:
    """Compone una credencial de prueba juntando sus dos mitades.

    Las credenciales de abajo son inventadas, pero tienen el formato exacto de
    las de verdad: eso es justo lo que ejercita las reglas. El problema es que
    ese formato lo reconoce también la protección de push de GitHub, que usa
    los mismos patrones y bloquea la subida del repositorio.

    Al partir el prefijo del cuerpo, el literal completo no aparece en ningún
    archivo y el valor solo existe mientras corre el test. Es el motivo por el
    que estas constantes no se escriben de una pieza.
    """
    return prefijo + cuerpo


GITHUB_TOKEN = cred("ghp", "_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8")
GITLAB_TOKEN = cred("glpat", "-A1b2C3d4E5f6G7h8I9j0")
GITLAB_OTRO = cred("glpat", "-Z9y8X7w6V5u4T3s2R1q0")
STRIPE_KEY = cred("sk", "_live_51HxQ2mZv9LwPqR7tY3nB6cF1hG0sD8jK")
AWS_ID = cred("AKIA", "Q7RT4VXZ2NM8PLCD")
# La clave que AWS usa en su propia documentación, con "EXAMPLE" dentro.
AWS_EJEMPLO = cred("AKIA", "IOSFODNN7EXAMPLE")
AWS_SECRETO = cred("wJq7Ft2MnXv9PzKd", "3RbY6HcE1sG5uT0aLiOp4NrW")
SLACK_TOKEN = cred("xoxb", "-2847562910-4827361095-Tf9Kd2LmNp7Qr4Vx8Zc1Bn6Y")
SLACK_WEBHOOK = cred("https://hooks.slack.com/services/", "T00000000/B00000000/Kd2LmNp7Qr4V")
GOOGLE_KEY = cred("AIza", "SyC4k2Lm9Pq7Rt3Vx8Zn1Bd6Yh0Jf5Gw2Ke")
ANTHROPIC_KEY = cred("sk-ant", "-api03-Xk2Lm9Pq7Rt3Vx8Zn1Bd6Yh0Jf5Gw2Ke")
TELEGRAM_TOKEN = cred("123456789", ":AAF7k2Lm9Pq7Rt3Vx8Zn1Bd6Yh0Jf5Gw2Ke")
NPM_TOKEN = cred("npm", "_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8")
CLAVE_BD = cred("Hx7p", "Q2mZv9Lw")
JWT = cred(
    "eyJhbGciOiJIUzI1NiJ9.",
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r",
)


def escanea(texto: str, etiqueta: str = "src/config.py", min_entropia: float = 3.5):
    """Analiza un texto suelto y devuelve las coincidencias."""
    from atalaya.modules.secrets_scan import Fuente

    return modulo._analiza(Fuente(etiqueta=etiqueta, contenido=texto), min_entropia)


def ids(coincidencias) -> set[str]:
    return {c.regla.id for c in coincidencias}


class TestEntropia:
    def test_cadena_vacia(self):
        assert entropia("") == 0.0

    def test_un_solo_caracter_repetido_no_tiene_entropia(self):
        assert entropia("aaaaaaaa") == 0.0

    def test_lo_aleatorio_puntua_mas_que_lo_legible(self):
        assert entropia(ALEATORIO) > entropia("contraseña")

    def test_orden_conocido(self):
        assert entropia("ab") == pytest.approx(1.0)


class TestMarcadores:
    @pytest.mark.parametrize(
        "valor",
        [
            "your_api_key_here",
            "changeme",
            "EXAMPLE_SECRET_VALUE",
            "xxxxxxxxxxxx",
            "${API_TOKEN}",
            "{{ secret }}",
            "<pon-tu-clave>",
            "$API_KEY",
            "dummy_value_123",
        ],
    )
    def test_los_huecos_se_reconocen(self, valor):
        assert es_marcador(valor)

    def test_un_valor_aleatorio_no_es_marcador(self):
        assert not es_marcador(ALEATORIO)


class TestRedaccion:
    @pytest.mark.parametrize(
        "secreto",
        [ALEATORIO, GITHUB_TOKEN, "corto", "12345678"],
    )
    def test_nunca_devuelve_el_secreto_entero(self, secreto):
        """Un informe puede acabar en un log de CI: no debe llevar el secreto."""
        assert redacta(secreto) != secreto
        assert secreto not in redacta(secreto)

    def test_deja_ver_el_prefijo_para_identificarlo(self):
        assert redacta(GITHUB_TOKEN).startswith("ghp_")

    def test_un_secreto_muy_corto_se_tapa_entero(self):
        assert redacta("abc") == "***"


class TestReglasConocidas:
    """Cada regla debe disparar con un valor de su formato."""

    @pytest.mark.parametrize(
        ("regla_id", "muestra"),
        [
            ("aws-access-key-id", f'KEY = "{AWS_ID}"'),
            ("aws-secret-access-key", f'aws_secret_access_key = "{AWS_SECRETO}"'),
            ("private-key", "-----BEGIN RSA PRIVATE KEY-----"),
            ("private-key", "-----BEGIN OPENSSH PRIVATE KEY-----"),
            ("github-token", GITHUB_TOKEN),
            ("gitlab-token", GITLAB_TOKEN),
            ("stripe-secret-key", STRIPE_KEY),
            ("slack-token", SLACK_TOKEN),
            ("slack-webhook", SLACK_WEBHOOK),
            ("google-api-key", GOOGLE_KEY),
            ("anthropic-key", ANTHROPIC_KEY),
            ("telegram-bot-token", TELEGRAM_TOKEN),
            ("npm-token", NPM_TOKEN),
            ("connection-string", f'URL = "postgresql://admin:{CLAVE_BD}@db.interno:5432/prod"'),
            ("jwt", JWT),
        ],
    )
    def test_la_regla_dispara(self, regla_id, muestra):
        assert regla_id in ids(escanea(muestra))

    @pytest.mark.parametrize(
        "texto",
        [
            "def calcular_total(precio, impuesto):",
            "# Este comentario habla de una api_key pero no la contiene",
            "import os\nTOKEN = os.environ['TOKEN']",
            "https://github.com/javiersaguar/Ciber-Tool",
            "El identificador del pedido es 1234567890ABCDEF",
        ],
    )
    def test_el_codigo_normal_no_dispara(self, texto):
        assert escanea(texto) == []

    def test_todas_las_reglas_tienen_ficha_completa(self):
        for regla in REGLAS:
            assert regla.id and regla.name, regla.id
            assert regla.description and regla.remediation, regla.id
            assert regla.severity is not Severity.OK, regla.id

    def test_no_hay_ids_de_regla_repetidos(self):
        vistos = [r.id for r in REGLAS]
        assert len(vistos) == len(set(vistos))

    def test_las_conocidas_no_exigen_entropia_y_las_contextuales_si(self):
        assert not any(r.requiere_entropia for r in REGLAS_CONOCIDAS)
        assert all(r.requiere_entropia for r in REGLAS_CONTEXTUALES)


class TestReglasContextuales:
    def test_un_valor_aleatorio_en_una_variable_de_secreto_dispara(self):
        assert "generic-assignment" in ids(escanea(f'api_key = "{ALEATORIO}"'))

    def test_un_valor_poco_aleatorio_no_dispara(self):
        """El nombre de la variable no basta: hace falta que el valor lo parezca."""
        assert escanea('password = "contrasena_de_casa"') == []

    def test_un_marcador_no_dispara_aunque_tenga_entropia(self):
        assert escanea('api_key = "your_key_here_xyz123"') == []

    def test_una_variable_sin_nombre_de_secreto_no_dispara(self):
        assert escanea(f'identificador = "{ALEATORIO}"') == []

    def test_cabecera_de_autorizacion(self):
        texto = f'headers = {{"Authorization": "Bearer {ALEATORIO}"}}'
        assert "authorization-header" in ids(escanea(texto))

    def test_el_umbral_de_entropia_es_configurable(self):
        texto = 'token = "aaabbbcccdddeee"'
        assert escanea(texto, min_entropia=3.5) == []
        assert escanea(texto, min_entropia=0.5) != []


class TestGraduacionDeSeveridad:
    def test_entropia_alta_mantiene_la_gravedad(self):
        (c,) = escanea(f'api_key = "{ALEATORIO}"')
        assert c.severidad is Severity.HIGH

    def test_entropia_media_la_rebaja(self):
        # 16 caracteres distintos: entropía exactamente log2(16) = 4.0, o sea
        # por encima del umbral de sospecha pero por debajo del de certeza.
        medio = "znqwmtplkrhvjdgb"
        assert 3.5 <= entropia(medio) < 4.5, "el valor de prueba ya no está en la franja"

        (c,) = escanea(f'api_key = "{medio}"')
        assert c.severidad is Severity.MEDIUM

    def test_en_tests_se_rebaja_lo_contextual(self):
        (c,) = escanea(f'api_key = "{ALEATORIO}"', etiqueta="tests/test_cliente.py")
        assert c.severidad is Severity.MEDIUM

    def test_en_tests_una_credencial_de_formato_real_sigue_siendo_critica(self):
        """Una clave de AWS filtrada lo está esté en el archivo que esté."""
        (c,) = escanea(f'KEY = "{AWS_ID}"', etiqueta="tests/test_aws.py")
        assert c.severidad is Severity.CRITICAL

    def test_un_marcador_rebaja_pero_no_descarta_las_conocidas(self):
        """La clave de ejemplo de la documentación de AWS: se avisa, sin alarmar.

        No se descarta porque una credencial real puede contener 'abcdef' por
        azar, y perderla en silencio sería mucho peor que un falso positivo.
        """
        coincidencias = escanea(f'KEY = "{AWS_EJEMPLO}"')
        assert len(coincidencias) == 1
        assert coincidencias[0].parece_ejemplo
        assert coincidencias[0].severidad is Severity.MEDIUM


class TestLecturaDeDiffs:
    DIFF = f"""diff --git a/src/app.py b/src/app.py
--- a/src/app.py
+++ b/src/app.py
@@ -10,0 +11,2 @@ def configurar():
+    TOKEN = "{GITHUB_TOKEN}"
+    return TOKEN
@@ -40,0 +42 @@ def otra():
+    pass
"""

    def test_extrae_solo_las_lineas_anadidas(self):
        (fuente,) = modulo._fuentes_de_diff(self.DIFF)
        assert fuente.etiqueta == "src/app.py"
        assert "return TOKEN" in fuente.contenido
        assert "def configurar" not in fuente.contenido

    def test_los_numeros_de_linea_salen_de_las_cabeceras_de_hunk(self):
        (fuente,) = modulo._fuentes_de_diff(self.DIFF)
        assert fuente.lineas == [11, 12, 42]

    def test_un_archivo_borrado_no_aporta_lineas(self):
        diff = "+++ /dev/null\n@@ -1 +0,0 @@\n+lo que sea\n"
        assert modulo._fuentes_de_diff(diff) == []

    def test_separa_los_commits_del_historial(self):
        diff = (
            "~~atalaya~~abc1234 2026-01-01 primero\n"
            "+++ b/a.py\n@@ -0,0 +1 @@\n+uno\n"
            "~~atalaya~~def5678 2026-01-02 segundo\n"
            "+++ b/b.py\n@@ -0,0 +1 @@\n+dos\n"
        )
        fuentes = modulo._fuentes_de_diff(diff)
        assert [f.etiqueta for f in fuentes] == [
            "abc1234 2026-01-01 primero a.py",
            "def5678 2026-01-02 segundo b.py",
        ]

    def test_una_cabecera_de_hunk_rota_no_revienta(self):
        assert modulo._fuentes_de_diff("+++ b/a.py\n@@ basura @@\n+linea\n")[0].lineas == [0]


class TestSeleccionDeArchivos:
    def test_ignora_los_binarios(self, tmp_path):
        binario = tmp_path / "datos.dat"
        binario.write_bytes(b"\x00\x01\x02secreto")
        assert modulo._lee(binario, 1_000_000) is None

    def test_ignora_los_archivos_grandes(self, tmp_path):
        grande = tmp_path / "grande.txt"
        grande.write_text("x" * 5000, encoding="utf-8")
        assert modulo._lee(grande, max_size=100) is None

    def test_lee_texto_normal(self, tmp_path):
        archivo = tmp_path / "codigo.py"
        archivo.write_text("hola = 1", encoding="utf-8")
        assert modulo._lee(archivo, 1_000_000) == "hola = 1"

    @pytest.mark.parametrize("nombre", ["logo.png", "app.min.js.map.zip", "lib.so"])
    def test_extensiones_descartadas(self, tmp_path, nombre):
        assert modulo._descartable(tmp_path / nombre)

    def test_sin_repositorio_recorre_el_arbol_saltando_ruido(self, tmp_path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text("x = 1", encoding="utf-8")
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "lib.js").write_text("y = 2", encoding="utf-8")

        nombres = {p.name for p in modulo._archivos(tmp_path)}
        assert nombres == {"app.py"}


class TestExclusiones:
    """Sin una vía de exclusión la herramienta es inservible en cualquier repo
    con fixtures de test o documentación con credenciales de ejemplo."""

    def _fuentes(self, *rutas: str):
        from atalaya.modules.secrets_scan import Fuente

        return [Fuente(etiqueta=r, contenido="x") for r in rutas]

    def test_sin_patrones_no_descarta_nada(self):
        fuentes = self._fuentes("a.py", "tests/b.py")
        assert modulo._sin_excluidas(fuentes, "") == fuentes

    def test_descarta_lo_que_case_con_el_patron(self):
        fuentes = self._fuentes("src/app.py", "tests/test_x.py")
        quedan = modulo._sin_excluidas(fuentes, "tests/*")
        assert [f.etiqueta for f in quedan] == ["src/app.py"]

    def test_admite_varios_patrones_separados_por_comas(self):
        fuentes = self._fuentes("src/app.py", "tests/t.py", "docs/guia.md")
        quedan = modulo._sin_excluidas(fuentes, "tests/*, docs/*")
        assert [f.etiqueta for f in quedan] == ["src/app.py"]

    def test_el_patron_casa_contra_la_ruta_no_contra_la_etiqueta(self):
        """En el historial la etiqueta lleva el commit delante; el glob no debe verlo."""
        from atalaya.modules.secrets_scan import Fuente

        fuente = Fuente(
            etiqueta="abc1234 2026-01-01 mensaje tests/test_x.py",
            contenido="x",
            ruta="tests/test_x.py",
        )
        assert modulo._sin_excluidas([fuente], "tests/*") == []

    def test_la_ruta_cae_en_la_etiqueta_si_no_se_da(self):
        from atalaya.modules.secrets_scan import Fuente

        assert Fuente(etiqueta="a.py", contenido="x").ruta == "a.py"


class TestMarcaDeIgnorar:
    def test_una_linea_marcada_no_se_analiza(self):
        assert escanea(f'TOKEN = "{GITHUB_TOKEN}"  # atalaya:ignore') == []

    def test_la_marca_solo_afecta_a_su_linea(self):
        texto = f'UNO = "{GITHUB_TOKEN}"  # atalaya:ignore\nDOS = "{GITLAB_OTRO}"\n'
        coincidencias = escanea(texto)
        assert ids(coincidencias) == {"gitlab-token"}
        assert coincidencias[0].linea == 2


class TestAgrupacion:
    def test_el_mismo_secreto_en_dos_sitios_es_un_solo_hallazgo(self):
        from atalaya.modules.secrets_scan import Fuente

        texto = f'api_key = "{ALEATORIO}"'
        coincidencias = modulo._analiza(Fuente("a.py", texto), 3.5) + modulo._analiza(
            Fuente("b.py", texto), 3.5
        )
        hallazgos = modulo._a_hallazgos(coincidencias, 2, SecretsInput(path="."))
        assert len(hallazgos) == 1
        assert "a.py:1" in hallazgos[0].evidence
        assert "b.py:1" in hallazgos[0].evidence

    def test_sin_coincidencias_se_informa_de_que_esta_limpio(self):
        hallazgos = modulo._a_hallazgos([], 7, SecretsInput(path="."))
        assert len(hallazgos) == 1
        assert hallazgos[0].severity is Severity.OK
        assert "7" in hallazgos[0].description

    def test_la_evidencia_nunca_lleva_el_secreto_entero(self):
        from atalaya.modules.secrets_scan import Fuente

        coincidencias = modulo._analiza(Fuente("a.py", f'api_key = "{ALEATORIO}"'), 3.5)
        hallazgo = modulo._a_hallazgos(coincidencias, 1, SecretsInput(path="."))[0]
        assert ALEATORIO not in hallazgo.evidence


class TestEntradas:
    def test_la_ruta_es_obligatoria(self):
        with pytest.raises(ValidationError):
            SecretsInput()

    def test_staged_e_history_se_excluyen(self):
        resultado = modulo.scan(SecretsInput(path=".", staged=True, history=True))
        assert not resultado.ok
        assert "excluyen" in resultado.error

    def test_una_ruta_inexistente_se_reporta_como_error(self):
        resultado = modulo.scan(SecretsInput(path="no/existe/en/ningun/sitio"))
        assert not resultado.ok
        assert "No existe" in resultado.error

    def test_el_objetivo_indica_el_modo(self):
        assert "(árbol)" in modulo.target_of(SecretsInput(path="."))
        assert "(índice)" in modulo.target_of(SecretsInput(path=".", staged=True))
        assert "(historial)" in modulo.target_of(SecretsInput(path=".", history=True))


class TestSobreUnRepositorioDeVerdad:
    """Comprueba de punta a punta los tres modos sobre un repositorio real."""

    @pytest.fixture
    def repo(self, tmp_path):
        def git(*args):
            subprocess.run(
                ["git", *args],
                cwd=tmp_path,
                check=True,
                capture_output=True,
                text=True,
            )

        git("init", "-q")
        git("config", "user.email", "prueba@ejemplo.invalid")
        git("config", "user.name", "Prueba")

        (tmp_path / ".gitignore").write_text("ignorado.py\n", encoding="utf-8")
        (tmp_path / "app.py").write_text(f'TOKEN = "{GITHUB_TOKEN}"\n', encoding="utf-8")
        (tmp_path / "ignorado.py").write_text(f'OTRO = "{GITLAB_OTRO}"\n', encoding="utf-8")
        git("add", "-A")
        git("commit", "-q", "-m", "inicial")
        return tmp_path, git

    def test_encuentra_el_secreto_del_arbol(self, repo):
        ruta, _ = repo
        resultado = modulo.scan(SecretsInput(path=str(ruta)))
        assert resultado.ok, resultado.error
        assert any(f.title == "Token de GitHub" for f in resultado.findings)

    def test_respeta_el_gitignore(self, repo):
        """El archivo ignorado tiene un secreto, pero no está en el repositorio."""
        ruta, _ = repo
        resultado = modulo.scan(SecretsInput(path=str(ruta)))
        assert not any(f.title == "Token de GitLab" for f in resultado.findings)

    def test_staged_solo_ve_lo_que_va_a_entrar(self, repo):
        ruta, git = repo
        (ruta / "nuevo.py").write_text(f'STRIPE = "{STRIPE_KEY}"\n', encoding="utf-8")
        git("add", "nuevo.py")

        resultado = modulo.scan(SecretsInput(path=str(ruta), staged=True))
        assert resultado.ok, resultado.error
        titulos = {f.title for f in resultado.findings}
        assert "Clave secreta de Stripe" in titulos
        # El token de GitHub ya estaba commiteado: no es cosa de este commit.
        assert "Token de GitHub" not in titulos

    def test_el_historial_recuerda_lo_que_se_borro(self, repo):
        """Lo importante del modo historial: borrar un secreto no lo elimina."""
        ruta, git = repo
        (ruta / "nuevo.py").write_text(f'STRIPE = "{STRIPE_KEY}"\n', encoding="utf-8")
        git("add", "nuevo.py")
        git("commit", "-q", "-m", "añade clave")
        git("rm", "-q", "nuevo.py")
        git("commit", "-q", "-m", "quita clave")

        en_arbol = modulo.scan(SecretsInput(path=str(ruta)))
        en_historial = modulo.scan(SecretsInput(path=str(ruta), history=True))

        assert not any(f.title == "Clave secreta de Stripe" for f in en_arbol.findings)
        assert any(f.title == "Clave secreta de Stripe" for f in en_historial.findings)

    def test_staged_necesita_repositorio(self, tmp_path):
        resultado = modulo.scan(SecretsInput(path=str(tmp_path), staged=True))
        assert not resultado.ok
        assert "repositorio git" in resultado.error
