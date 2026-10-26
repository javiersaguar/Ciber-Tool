"""Descubrimiento contra HTTP local, páginas comodín y límites operativos."""

import asyncio
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from atalaya.cli import app
from atalaya.core.finding import Severity
from atalaya.modules.web_paths import MAX_BODY, Probe, WebPathsInput, WebPathsModule, clean_path


@pytest.fixture
def site():
    state = {"routes": {}, "requests": [], "wildcard": False, "status": 404}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            state["requests"].append((self.path, time.monotonic()))
            status, body, headers = state["routes"].get(
                self.path,
                (
                    200 if state["wildcard"] else state["status"],
                    b"Missing: " + self.path.encode(),
                    {},
                ),
            )
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def scan(site, tmp_path, paths, **kwargs):
    wordlist = tmp_path / "paths.txt"
    wordlist.write_text("\n".join(paths), encoding="utf-8")
    return WebPathsModule().scan(WebPathsInput(url=site[0], wordlist=wordlist, rate=20, **kwargs))


def test_sensitive_findings_do_not_leak_content(site, tmp_path):
    site[1]["routes"] = {
        "/.env": (200, b"DB_PASSWORD=do-not-print-me\nAPI_TOKEN=also-private\n", {}),
        "/.git/HEAD": (200, b"ref: refs/heads/main\n", {}),
        "/admin": (403, b"Forbidden", {}),
    }
    result = scan(site, tmp_path, [".env", ".git/HEAD", "admin", "missing"])
    assert result.error is None
    assert result.count(Severity.HIGH) == 2
    assert len(result.findings) == 4
    assert "do-not-print-me" not in result.model_dump_json()
    assert "also-private" not in result.model_dump_json()
    assert "HTTP 403" in str(result.findings)


def test_reflected_wildcard_pages_are_omitted(site, tmp_path):
    site[1]["wildcard"] = True
    result = scan(site, tmp_path, ["admin", ".env"])
    assert result.error is None
    assert len(result.findings) == 1
    assert "omitidas: 2" in result.findings[-1].evidence


def test_redirects_are_not_followed(site, tmp_path):
    site[1]["routes"]["/admin"] = (302, b"", {"Location": "http://outside.invalid/private"})
    result = scan(site, tmp_path, ["admin"])
    assert result.error is None
    assert len(site[1]["requests"]) == 3
    assert "outside.invalid" not in result.model_dump_json()


def test_base_path_and_rate_limit(site, tmp_path, monkeypatch):
    starts = []
    original = WebPathsModule._request

    async def request(self, *args):
        starts.append(time.perf_counter())
        return await original(self, *args)

    monkeypatch.setattr(WebPathsModule, "_request", request)
    result = scan((site[0] + "/app", site[1]), tmp_path, ["admin"])
    assert result.error is None
    requests = site[1]["requests"]
    assert all(path.startswith("/app/") for path, _ in requests)
    # Medir inicios del cliente, no llegadas al servidor, que pueden agruparse.
    assert all(b - a >= 0.045 for a, b in zip(starts, starts[1:], strict=False))


def test_stop_on_rate_limit(site, tmp_path):
    site[1]["status"] = 429
    result = scan(site, tmp_path, ["admin", "login"])
    assert result.error is None
    assert len(site[1]["requests"]) == 1
    assert "429/503: True" in result.findings[-1].evidence


def test_large_body_is_bounded(site, tmp_path):
    site[1]["routes"]["/large"] = (200, b"x" * (MAX_BODY * 2), {})
    result = scan(site, tmp_path, ["large"])
    assert result.error is None
    assert f"{MAX_BODY} bytes" in result.findings[0].evidence


def test_html_at_env_path_is_not_confirmed_exposure(site, tmp_path):
    site[1]["routes"]["/.env"] = (200, b"<html>\nDB_PASSWORD=x\nAPI_TOKEN=y\n</html>", {})
    assert scan(site, tmp_path, [".env"]).count(Severity.HIGH) == 0


@pytest.mark.parametrize(
    "value",
    [
        "../secret",
        "a/../b",
        "https://host/x",
        "%2e%2e/x",
        "a?token=x",
        "a#frag",
        "a\\b",
        "%252e%252e/x",
        "",
    ],
)
def test_invalid_paths(value):
    with pytest.raises(ValueError):
        clean_path(value)


@pytest.mark.parametrize(
    "value",
    [
        "ftp://host",
        "https://u:p@host",
        "http://host/?q=x",
        "http://host/#frag",
        "http://host:99999",
    ],
)
def test_invalid_urls(value):
    with pytest.raises(ValidationError):
        WebPathsInput(url=value)


def test_dictionary_limits(tmp_path):
    path = tmp_path / "paths.txt"
    for content in ["x" * 65537, "\n".join(f"path-{i}" for i in range(257)), "# empty"]:
        path.write_text(content, encoding="utf-8")
        result = WebPathsModule().scan(WebPathsInput(url="http://127.0.0.1", wordlist=path))
        assert result.error


def test_deadline_cancels_requests_and_retains_findings(monkeypatch, tmp_path):
    cancelled = []

    async def request(self, client, url, path):
        if path.startswith("atalaya-not-found-"):
            return Probe(path, 404, b"", "")
        if path == "admin":
            return Probe(path, 200, b"Admin", "")
        try:
            await asyncio.sleep(10)
        finally:
            cancelled.append(path)

    monkeypatch.setattr(WebPathsModule, "_request", request)
    result = scan(
        ("http://127.0.0.1", {}), tmp_path, ["admin", "slow"], total_timeout=0.4, concurrency=1
    )
    assert result.error is None
    assert cancelled == ["slow"]
    assert "no probadas: 1" in result.findings[-1].evidence


def test_cli_reports_exposure_and_failure_threshold(site, tmp_path):
    site[1]["routes"]["/.git/HEAD"] = (200, b"ref: refs/heads/main\n", {})
    wordlist = tmp_path / "paths.txt"
    wordlist.write_text(".git/HEAD", encoding="utf-8")
    result = CliRunner().invoke(
        app,
        ["web-paths", site[0], "--wordlist", str(wordlist), "--rate", "20", "--formato", "json"],
    )
    assert result.exit_code == 2, result.output
    assert json.loads(result.stdout)["findings"][0]["severity"] == "high"
