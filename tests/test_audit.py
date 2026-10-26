import json
import socket

import pytest
from typer.testing import CliRunner

from atalaya.cli import app
from atalaya.core.audit import AuditRun, HistoryStore, compare_runs, run_audit
from atalaya.core.finding import Check, CheckStatus, Finding, ScanResult
from atalaya.core.registry import get_registry
from atalaya.core.workbench import render_workbench


def run(findings=(), incomplete=False, configuration=None):
    return AuditRun(
        target="https://example.org/",
        configuration=configuration or {},
        results=[
            ScanResult(
                module_id="m",
                module_name="Módulo",
                target="example.org",
                findings=list(findings),
                checks=[
                    Check(
                        id="c",
                        name="C",
                        status=CheckStatus.UNDETERMINED if incomplete else CheckStatus.DONE,
                    )
                ],
            )
        ],
    )


def issue(title="Issue", severity="high", attributes=None):
    return Finding(
        rule_id="test.rule",
        location="/path",
        title=title,
        severity=severity,
        attributes=attributes or {},
    )


def test_history_roundtrip_and_target_configuration_isolation(tmp_path):
    store = HistoryStore(tmp_path)
    original = run([issue()])
    store.save(original)
    assert store.get(original.id) == original
    assert store.latest(original) == original
    assert len(store.list()) == 1
    assert store.latest(run(configuration={"different": True})) is None
    other = original.model_copy(update={"target": "https://other.example/"})
    assert store.latest(other) is None


def test_evidence_changes_do_not_create_new_findings():
    before = run([issue()])
    after = run([issue(title="Translated title")])
    after.results[0].findings[0].evidence = "Volatile timestamp 123"
    diff = compare_runs(before, after)
    assert len(diff["unchanged"]) == 1
    assert not diff["new"]
    assert not diff["resolved"]


def test_service_version_changes_are_detected():
    diff = compare_runs(
        run([issue(attributes={"version": "1"})]), run([issue(attributes={"version": "2"})])
    )
    assert len(diff["changed"]) == 1


def test_incomplete_does_not_resolve_and_survives_multiple_runs():
    first = run([issue()])
    partial = run(incomplete=True)
    partial.comparison = compare_runs(first, partial)
    assert not partial.comparison["resolved"]
    assert len(partial.comparison["unverified"]) == 1
    another_partial = run(incomplete=True)
    another_partial.comparison = compare_runs(partial, another_partial)
    assert len(another_partial.comparison["unverified"]) == 1
    complete = run()
    assert len(compare_runs(another_partial, complete)["resolved"]) == 1


def test_incompatible_runs_cannot_be_compared():
    with pytest.raises(ValueError):
        compare_runs(run(), run(configuration={"other": True}))


def test_audit_plan_validates_before_any_scan(monkeypatch):
    called = []
    module = get_registry().get("http-headers")
    monkeypatch.setattr(module, "scan", lambda inputs: called.append(inputs))
    with pytest.raises(ValueError):
        run_audit("https://example.org", modules="http-headers,ssh-honeypot")
    assert not called


def test_http_target_does_not_run_tls_and_configures_real_port(monkeypatch):
    called = []
    module = get_registry().get("services")

    def scan(inputs):
        called.append(inputs)
        return ScanResult(module_id="services", module_name="Services", target=inputs.host)

    monkeypatch.setattr(module, "scan", scan)
    result = run_audit("http://127.0.0.1:12345", modules="tls,services", ports="12345")
    assert result.configuration["modules"] == ["services"]
    assert called[0].http_ports == "12345"


def test_audit_cli_history_export_and_no_save(tmp_path):
    runner = CliRunner()
    history = tmp_path / "history"
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        args = [
            "audit",
            "http://127.0.0.1",
            "--modules",
            "tcp-ports",
            "--ports",
            str(port),
            "--history-dir",
            str(history),
            "--formato",
            "json",
        ]
        first = runner.invoke(app, args)
        assert first.exit_code == 0, first.output
        saved = json.loads(first.stdout)
        assert saved["status"] == "complete"
        second = runner.invoke(app, args)
        assert second.exit_code == 0, second.output
        assert json.loads(second.stdout)["previous_id"] == saved["id"]
        listing = runner.invoke(app, ["history", "list", "--history-dir", str(history), "--json"])
        assert len(json.loads(listing.stdout)) == 2
        html = tmp_path / "report.html"
        exported = runner.invoke(
            app,
            [
                "history",
                "show",
                saved["id"],
                "--history-dir",
                str(history),
                "--formato",
                "html",
                "--salida",
                str(html),
            ],
        )
        assert exported.exit_code == 0, exported.output
        assert "tcp-ports" in html.read_text(encoding="utf-8")
        assert runner.invoke(app, args + ["--no-save"]).exit_code == 0
        assert len(HistoryStore(history).list()) == 2


def test_workbench_escapes_untrusted_data_and_disallows_script_links():
    finding = issue(title='<script>alert("x")</script>')
    finding.references = ["javascript:alert(1)", "https://example.org/reference"]
    result = run([finding]).results[0]
    html = render_workbench([result], "<img src=x>", "Audit")
    assert "<script>alert" not in html
    assert "<img src=x>" not in html
    assert "javascript:alert" not in html
    assert "https://example.org/reference" in html
    assert 'id="search"' in html
    assert 'id="severity"' in html
    assert 'id="theme"' in html
