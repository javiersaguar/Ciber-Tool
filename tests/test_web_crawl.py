import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from atalaya.core.finding import EvaluationStatus
from atalaya.modules.web_crawl import CrawlInput, WebCrawlModule, scoped_url


@pytest.fixture
def site():
    state = {"requests": [], "routes": {}}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            state["requests"].append(("GET", self.path))
            status, body, headers = state["routes"].get(self.path, (200, b"<html>OK</html>", {}))
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
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


@pytest.mark.parametrize(
    "link",
    [
        "https://outside.example/",
        "http://user:pass@example.org/app/",
        "/elsewhere",
        "/app/../secret",
        "/app/%2e%2e/secret",
        "/app/logout",
        "javascript:alert(1)",
        "//example.org:8080/app/",
    ],
)
def test_scope_rejects_outside_links(link):
    assert scoped_url("http://example.org/app/", "http://example.org/app/", link) is None


def test_same_origin_normalization():
    assert (
        scoped_url("http://example.org/", "http://example.org/", "/a?secret=value#hash")
        == "http://example.org/a"
    )


def test_crawl_never_submits_forms_or_keeps_values(site):
    url, state = site
    state["routes"]["/app/"] = (
        200,
        b"""<a href="page?token=private">Page</a>
    <a href="page?token=another">Duplicate</a><a href="https://outside.invalid/">Outside</a>
    <form action="submit" method="post"><input name="password" value="do-not-store"></form>
    <script src="/app/main.js?key=private"></script>""",
        {},
    )
    result = WebCrawlModule().scan(CrawlInput(url=url + "/app", rate=10))
    assert result.error is None
    assert state["requests"] == [("GET", "/app/"), ("GET", "/app/page")]
    assert "do-not-store" not in result.model_dump_json()
    assert "private" not in result.model_dump_json()
    assert {f.rule_id for f in result.findings} >= {
        "crawl.page",
        "crawl.form",
        "crawl.parameters",
        "crawl.endpoint",
    }
    assert result.status is EvaluationStatus.COMPLETE


def test_page_budget_is_incomplete(site):
    url, state = site
    state["routes"]["/"] = (200, b'<a href="/second">Second</a>', {})
    result = WebCrawlModule().scan(CrawlInput(url=url, max_pages=1, rate=10))
    assert len(state["requests"]) == 1
    assert result.status is EvaluationStatus.INCOMPLETE
    assert result.grade is None


def test_redirect_cannot_leave_scope(site):
    url, state = site
    state["routes"]["/"] = (302, b"", {"Location": "https://outside.invalid/"})
    result = WebCrawlModule().scan(CrawlInput(url=url, rate=10))
    assert result.error is None
    assert state["requests"] == [("GET", "/")]


def test_server_throttle_stops_crawl(site):
    url, state = site
    state["routes"]["/"] = (429, b"Slow down", {})
    result = WebCrawlModule().scan(CrawlInput(url=url, rate=10))
    assert result.grade is None
    assert len(state["requests"]) == 1
