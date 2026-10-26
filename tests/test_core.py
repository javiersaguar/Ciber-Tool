"""Pruebas del núcleo: puntuación, contrato de módulo y registro."""

from __future__ import annotations

import pytest
from pydantic import BaseModel

from atalaya.core.finding import (
    Check,
    CheckStatus,
    EvaluationStatus,
    Finding,
    FindingKind,
    ScanResult,
    Severity,
)
from atalaya.core.module import Category, Coverage, ScanModule
from atalaya.core.registry import ModuleRegistry, get_registry
from atalaya.core.report import render_html, render_json, render_terminal


def hallazgo(severity: Severity, title: str = "x") -> Finding:
    return Finding(severity=severity, title=title)


def resultado(*severidades: Severity) -> ScanResult:
    return ScanResult(
        module_id="prueba",
        module_name="Prueba",
        target="ejemplo.com",
        findings=[hallazgo(s) for s in severidades],
    )


class TestPuntuacion:
    def test_sin_hallazgos_es_perfecto(self):
        r = resultado()
        assert r.score == 100
        assert r.grade == "A+"

    def test_cada_gravedad_resta_su_peso(self):
        assert resultado(Severity.CRITICAL).score == 50
        assert resultado(Severity.HIGH).score == 75
        assert resultado(Severity.MEDIUM).score == 90
        assert resultado(Severity.LOW).score == 97

    def test_info_y_ok_no_penalizan(self):
        assert resultado(Severity.INFO, Severity.OK, Severity.OK).score == 100

    def test_la_puntuacion_no_baja_de_cero(self):
        r = resultado(*[Severity.CRITICAL] * 5)
        assert r.score == 0
        assert r.grade == "F"

    @pytest.mark.parametrize(
        ("severidades", "puntos", "nota"),
        [
            ((), 100, "A+"),
            ((Severity.LOW,), 97, "A"),
            ((Severity.MEDIUM,), 90, "A"),
            ((Severity.MEDIUM, Severity.LOW), 87, "B"),
            ((Severity.HIGH,), 75, "C"),
            ((Severity.CRITICAL,), 50, "D"),
            ((Severity.CRITICAL, Severity.MEDIUM), 40, "E"),
            ((Severity.CRITICAL, Severity.HIGH), 25, "F"),
        ],
    )
    def test_tramos_de_nota(self, severidades, puntos, nota):
        r = resultado(*severidades)
        assert r.score == puntos
        assert r.grade == nota


class TestOrdenYRecuento:
    def test_ordena_de_mas_grave_a_menos(self):
        r = resultado(Severity.LOW, Severity.CRITICAL, Severity.MEDIUM, Severity.HIGH)
        assert [f.severity for f in r.by_severity()] == [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
        ]

    def test_cuenta_por_gravedad(self):
        r = resultado(Severity.HIGH, Severity.HIGH, Severity.LOW)
        assert r.count(Severity.HIGH) == 2
        assert r.count(Severity.LOW) == 1
        assert r.count(Severity.CRITICAL) == 0


class TestScanModule:
    """El contrato: `scan` mide el tiempo y captura los fallos del módulo."""

    class Entrada(BaseModel):
        objetivo: str
        extra: int = 3

    def _modulo(self, fn):
        """Módulo de usar y tirar cuyo `run` es la función que se le pase.

        `run` se define dentro del cuerpo de la clase a propósito: ABCMeta fija
        los métodos abstractos al crearla, así que asignarlo después no basta.
        """
        entrada = self.Entrada

        class Modulo(ScanModule):
            id = "falso"
            name = "Falso"
            description = "Módulo de prueba."
            category = Category.RECON
            InputModel = entrada

            def run(self, inputs):
                return fn(inputs)

        return Modulo()

    def test_scan_envuelve_los_hallazgos(self):
        modulo = self._modulo(lambda inputs: [hallazgo(Severity.HIGH, "algo")])
        result = modulo.scan(self.Entrada(objetivo="a.com"))
        assert result.ok
        assert result.module_id == "falso"
        assert result.target == "a.com"
        assert len(result.findings) == 1

    def test_una_excepcion_no_propaga_y_queda_registrada(self):
        def explota(inputs):
            raise ValueError("se rompió")

        result = self._modulo(explota).scan(self.Entrada(objetivo="a.com"))
        assert not result.ok
        assert result.error == "ValueError: se rompió"
        assert result.findings == []

    def test_target_por_defecto_es_el_primer_campo(self):
        modulo = self._modulo(lambda inputs: [])
        assert modulo.target_of(self.Entrada(objetivo="host.com")) == "host.com"

    def test_el_esquema_de_entrada_describe_los_campos(self):
        modulo = self._modulo(lambda inputs: [])
        esquema = modulo.input_schema()
        assert set(esquema["properties"]) == {"objetivo", "extra"}
        assert esquema["required"] == ["objetivo"]


class TestRegistry:
    def _modulo(self, module_id: str):
        class Entrada(BaseModel):
            objetivo: str

        class Modulo(ScanModule):
            id = module_id
            name = "M"
            description = "d"
            category = Category.WEB
            InputModel = Entrada

            def run(self, inputs):
                return []

        return Modulo()

    def test_registrar_y_recuperar(self):
        registry = ModuleRegistry()
        modulo = self._modulo("uno")
        registry.register(modulo)
        assert registry.get("uno") is modulo
        assert "uno" in registry
        assert len(registry) == 1

    def test_ids_duplicados_se_rechazan(self):
        registry = ModuleRegistry()
        registry.register(self._modulo("uno"))
        with pytest.raises(ValueError, match="ya hay un módulo|Ya hay un módulo"):
            registry.register(self._modulo("uno"))

    def test_id_desconocido_lista_los_disponibles(self):
        registry = ModuleRegistry()
        registry.register(self._modulo("uno"))
        with pytest.raises(KeyError, match="uno"):
            registry.get("inexistente")


class TestDescubrimiento:
    """El registro global se construye solo a partir de `atalaya/modules/`."""

    def test_encuentra_los_modulos_instalados(self):
        registry = get_registry()
        assert {"http-headers", "tls"} <= set(registry.ids())

    def test_todos_cumplen_el_contrato(self):
        for modulo in get_registry().all():
            assert isinstance(modulo.id, str) and modulo.id
            assert isinstance(modulo.name, str) and modulo.name
            assert issubclass(modulo.InputModel, BaseModel)
            assert modulo.InputModel.model_fields, "necesita al menos el objetivo"
            assert callable(modulo.run)


class TestRenderizado:
    def test_json_incluye_nota_y_resumen(self):
        import json

        datos = json.loads(render_json(resultado(Severity.HIGH, Severity.LOW)))
        assert datos["grade"] == "C"
        assert datos["score"] == 72
        assert datos["summary"] == {"high": 1, "low": 1}

    def test_html_escapa_el_contenido(self):
        r = ScanResult(
            module_id="m",
            module_name="M",
            target="<script>alert(1)</script>",
            findings=[Finding(severity=Severity.HIGH, title="<img onerror=x>")],
        )
        html = render_html(r)
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html
        assert "<img onerror=x>" not in html

    def test_terminal_no_revienta_con_un_resultado_fallido(self, capsys):
        from rich.console import Console

        r = resultado(Severity.HIGH)
        r.error = "algo falló"
        render_terminal(r, Console(width=100), verbose=True)
        assert "algo falló" in capsys.readouterr().out


class TestEstadoDeEvaluacion:
    """Un análisis que falla o queda a medias no puede presentarse con nota."""

    def test_un_fallo_sin_hallazgos_no_se_evalua(self):
        r = ScanResult(module_id="m", module_name="M", target="t", error="ConnectError: x")
        assert r.status is EvaluationStatus.NOT_EVALUATED
        assert r.score is None
        assert r.grade is None
        assert r.score_upper_bound is None

    def test_un_fallo_con_hallazgos_parciales_queda_incompleto(self):
        r = resultado(Severity.LOW)
        r.error = "el servicio no pudo continuar"
        assert r.status is EvaluationStatus.INCOMPLETE
        assert r.grade is None
        assert r.score_upper_bound == 97

    def test_una_comprobacion_sin_determinar_impide_la_nota(self):
        r = resultado(Severity.LOW)
        r.checks = [
            Check(id="a", name="A"),
            Check(id="b", name="B", status=CheckStatus.UNDETERMINED, detail="timeout"),
        ]
        assert r.status is EvaluationStatus.INCOMPLETE
        assert r.score is None
        assert r.score_upper_bound == 97
        assert [c.id for c in r.pending_checks] == ["b"]

    def test_una_omision_pedida_no_impide_la_nota(self):
        r = resultado()
        r.checks = [
            Check(id="a", name="A"),
            Check(id="b", name="B", status=CheckStatus.SKIPPED),
        ]
        assert r.status is EvaluationStatus.COMPLETE
        assert r.grade == "A+"

    def test_si_ninguna_comprobacion_concluye_no_se_evalua(self):
        r = resultado()
        r.checks = [Check(id="a", name="A", status=CheckStatus.UNDETERMINED)]
        assert r.status is EvaluationStatus.NOT_EVALUATED
        assert r.grade is None

    def test_la_cobertura_cuenta_por_estado(self):
        r = resultado()
        r.checks = [
            Check(id="a", name="A"),
            Check(id="b", name="B", status=CheckStatus.SKIPPED),
            Check(id="c", name="C", status=CheckStatus.UNDETERMINED),
        ]
        assert r.coverage() == {"done": 1, "skipped": 1, "undetermined": 1, "total": 3}


class TestCoverage:
    def test_una_comprobacion_que_revienta_queda_pendiente(self):
        cov = Coverage()

        def rota():
            raise KeyError("campo")

        assert cov.run("rota", "Rota", rota) == []
        assert cov.run("sana", "Sana", lambda: [hallazgo(Severity.LOW)])[0].severity is Severity.LOW
        estados = {c.id: c.status for c in cov.checks}
        assert estados == {"rota": CheckStatus.UNDETERMINED, "sana": CheckStatus.DONE}
        assert "KeyError" in cov.checks[0].detail

    def test_scan_recoge_la_cobertura_del_scan_output(self):
        class Entrada(BaseModel):
            objetivo: str

        class Modulo(ScanModule):
            id = "con-cobertura"
            name = "M"
            description = "d"
            category = Category.WEB
            InputModel = Entrada

            def run(self, inputs):
                cov = Coverage()
                cov.done("a", "A")
                cov.undetermined("b", "B", "timeout")
                return cov.output([hallazgo(Severity.MEDIUM)])

        r = Modulo().scan(Entrada(objetivo="x"))
        assert r.ok
        assert len(r.findings) == 1
        assert r.status is EvaluationStatus.INCOMPLETE
        assert r.score_upper_bound == 90


class TestInformesSinNota:
    def _fallido(self) -> ScanResult:
        return ScanResult(module_id="m", module_name="M", target="t", error="ConnectError: sin red")

    def test_terminal_no_muestra_a_plus_si_fallo(self, capsys):
        from rich.console import Console

        render_terminal(self._fallido(), Console(width=120))
        salida = capsys.readouterr().out
        assert "NO EVALUADO" in salida
        assert "A+" not in salida
        assert "100/100" not in salida

    def test_terminal_lista_lo_pendiente_y_la_cobertura(self, capsys):
        from rich.console import Console

        r = resultado(Severity.LOW)
        r.checks = [
            Check(id="a", name="Cabeceras"),
            Check(
                id="b",
                name="Soporte de TLSv1.0",
                status=CheckStatus.UNDETERMINED,
                detail="sin respuesta en 10 s",
            ),
        ]
        render_terminal(r, Console(width=140))
        salida = capsys.readouterr().out
        assert "ANÁLISIS INCOMPLETO" in salida
        assert "como máximo 97/100" in salida
        assert "1 de 2 comprobaciones" in salida
        assert "Soporte de TLSv1.0" in salida
        assert "sin respuesta en 10 s" in salida

    def test_json_de_un_fallo_no_trae_nota(self):
        import json

        datos = json.loads(render_json(self._fallido()))
        assert datos["status"] == "not_evaluated"
        assert datos["score"] is None
        assert datos["grade"] is None

    def test_json_completo_trae_estado_y_cobertura(self):
        import json

        datos = json.loads(render_json(resultado(Severity.LOW)))
        assert datos["status"] == "complete"
        assert datos["grade"] == "A"
        assert datos["coverage"]["total"] == 0

    def test_html_de_un_fallo_no_trae_nota(self):
        html = render_html(self._fallido())
        assert "No evaluado" in html
        assert 'class="grade"' not in html
        assert "100/100" not in html

    def test_html_muestra_el_tipo_de_hallazgo(self):
        r = ScanResult(
            module_id="m",
            module_name="M",
            target="t",
            findings=[Finding(severity=Severity.HIGH, title="x", kind=FindingKind.VULNERABILITY)],
        )
        assert "Vulnerabilidad demostrada" in render_html(r)
