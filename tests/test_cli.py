"""Pruebas de la CLI generada desde el registro."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from atalaya.cli import EXIT_HALLAZGOS, EXIT_OK, Umbral, _codigo_salida, app
from atalaya.core.finding import Finding, ScanResult, Severity
from atalaya.core.registry import get_registry

runner = CliRunner()

# rich recorta la ayuda al ancho del terminal, y el de por defecto en los tests
# parte los nombres de las opciones largas.
ANCHO = {"COLUMNS": "200", "TERMINAL_WIDTH": "200"}


def ayuda(*args: str) -> str:
    return runner.invoke(app, [*args, "--help"], env=ANCHO).output


def resultado(*severidades: Severity, error: str | None = None) -> ScanResult:
    return ScanResult(
        module_id="m",
        module_name="M",
        target="t",
        error=error,
        findings=[Finding(severity=s, title="x") for s in severidades],
    )


class TestComandosGenerados:
    def test_cada_modulo_tiene_su_subcomando(self):
        salida = ayuda()
        for module_id in get_registry().ids():
            assert module_id in salida

    def test_list_muestra_los_modulos(self):
        resultado_cli = runner.invoke(app, ["list"])
        assert resultado_cli.exit_code == 0
        assert "http-headers" in resultado_cli.output

    def test_la_ayuda_describe_los_campos_del_input_model(self):
        """Los argumentos salen del InputModel, no están escritos a mano."""
        salida = ayuda("tls")
        assert "--port" in salida
        assert "--timeout" in salida
        assert "--check-protocols" in salida

    def test_las_opciones_comunes_estan_en_todos(self):
        for module_id in get_registry().ids():
            salida = ayuda(module_id)
            assert "--formato" in salida, module_id
            assert "--salida" in salida, module_id
            assert "--fallar-en" in salida, module_id

    def test_falta_el_argumento_obligatorio(self):
        assert runner.invoke(app, ["tls"]).exit_code != 0

    def test_entrada_invalida_se_explica(self):
        """El puerto está acotado en el InputModel; la CLI debe respetarlo."""
        resultado_cli = runner.invoke(app, ["tls", "ejemplo.com", "--port", "99999"])
        assert resultado_cli.exit_code != 0

    def test_version(self):
        resultado_cli = runner.invoke(app, ["--version"])
        assert resultado_cli.exit_code == 0
        assert "Atalaya" in resultado_cli.output


class TestCodigoDeSalida:
    def test_sin_hallazgos(self):
        assert _codigo_salida(resultado(), Umbral.high) == EXIT_OK

    def test_por_debajo_del_umbral(self):
        assert _codigo_salida(resultado(Severity.LOW, Severity.MEDIUM), Umbral.high) == EXIT_OK

    def test_en_el_umbral(self):
        assert _codigo_salida(resultado(Severity.HIGH), Umbral.high) == EXIT_HALLAZGOS

    def test_por_encima_del_umbral(self):
        assert _codigo_salida(resultado(Severity.CRITICAL), Umbral.high) == EXIT_HALLAZGOS

    def test_umbral_mas_estricto(self):
        assert _codigo_salida(resultado(Severity.LOW), Umbral.low) == EXIT_HALLAZGOS
        assert _codigo_salida(resultado(Severity.LOW), Umbral.medium) == EXIT_OK

    def test_nunca_falla(self):
        assert _codigo_salida(resultado(Severity.CRITICAL), Umbral.nunca) == EXIT_OK

    def test_un_error_del_modulo_tiene_prioridad(self):
        from atalaya.cli import EXIT_ERROR

        assert _codigo_salida(resultado(error="se rompió"), Umbral.nunca) == EXIT_ERROR


class TestFormatos:
    """Se ejercita con un módulo real pero sin red: el objetivo no resuelve."""

    HOST_INEXISTENTE = "no-existe.invalid"

    def test_json_es_valido_incluso_al_fallar(self):
        resultado_cli = runner.invoke(
            app, ["tls", self.HOST_INEXISTENTE, "--formato", "json", "--timeout", "2"]
        )
        datos = json.loads(resultado_cli.stdout)
        assert datos["module_id"] == "tls"
        assert datos["error"] is not None

    def test_guarda_el_informe_en_un_fichero(self, tmp_path):
        destino = tmp_path / "informe.html"
        runner.invoke(
            app,
            [
                "tls",
                self.HOST_INEXISTENTE,
                "--formato",
                "html",
                "--salida",
                str(destino),
                "--timeout",
                "2",
            ],
        )
        assert destino.exists()
        assert "<!doctype html>" in destino.read_text(encoding="utf-8")


class TestOpcionesReservadas:
    def test_ningun_modulo_pisa_las_opciones_comunes(self):
        """Si un módulo usara 'formato' o 'salida' como campo, la CLI se rompería."""
        from atalaya.cli import OPCIONES_COMUNES

        for modulo in get_registry().all():
            colision = OPCIONES_COMUNES & set(modulo.InputModel.model_fields)
            assert not colision, f"{modulo.id} colisiona en {colision}"
