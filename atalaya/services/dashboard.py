"""Panel privado: HTTP en loopback, token Bearer y snapshots por SSE."""

import asyncio
import contextlib
import hmac
import json
from importlib.resources import files

from aiohttp import web

from atalaya.core.report import render_json


class Dashboard:
    def __init__(self, inputs, context, token, stats):
        self.inputs = inputs
        self.context = context
        self.token = token
        self.stats = stats
        self.data = {}
        self.streams = 0
        host = (
            f"[{inputs.dashboard_host}]" if ":" in inputs.dashboard_host else inputs.dashboard_host
        )
        self.authority = f"{host}:{inputs.dashboard_port}"
        self.url = f"http://{self.authority}"
        self.runner = None
        self.app = web.Application(middlewares=[self.guard], client_max_size=1024)
        self.app.router.add_get("/", self.asset)
        self.app.router.add_get("/app.js", self.asset)
        self.app.router.add_get("/style.css", self.asset)
        self.app.router.add_get("/api/snapshot", self.snapshot)
        self.app.router.add_get("/api/report", self.report)
        self.app.router.add_get("/api/events", self.events)

    @property
    def headers(self):
        return {
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; img-src 'self'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'none'",
        }

    @web.middleware
    async def guard(self, request, handler):
        # No confiar en X-Forwarded-* ni en nombres DNS que permitan rebinding.
        if request.host != self.authority:
            raise web.HTTPForbidden()
        if request.headers.get("Origin", self.url) != self.url:
            raise web.HTTPForbidden()
        if request.path.startswith("/api/"):
            supplied = request.headers.get("Authorization", "").encode()
            if not hmac.compare_digest(supplied, f"Bearer {self.token}".encode()):
                raise web.HTTPUnauthorized(headers={**self.headers, "WWW-Authenticate": "Bearer"})
        response = await handler(request)
        response.headers.update(self.headers)
        return response

    async def asset(self, request):
        name = {"/": "index.html", "/app.js": "app.js", "/style.css": "style.css"}[request.path]
        content_type = {
            "index.html": "text/html",
            "app.js": "text/javascript",
            "style.css": "text/css",
        }[name]
        text = files("atalaya.services.static").joinpath(name).read_text(encoding="utf-8")
        return web.Response(text=text, content_type=content_type)

    def payload(self):
        return {
            **self.data,
            "stats": dict(self.stats),
            "report": json.loads(render_json(self.context.snapshot())),
        }

    async def snapshot(self, request):
        return web.json_response(self.payload())

    async def report(self, request):
        return web.Response(
            text=render_json(self.context.snapshot()), content_type="application/json"
        )

    async def events(self, request):
        if self.streams >= 4:
            raise web.HTTPServiceUnavailable(text="Límite de paneles activos alcanzado")
        self.streams += 1
        response = web.StreamResponse(headers={**self.headers, "Content-Type": "text/event-stream"})
        try:
            await response.prepare(request)
            while not self.context.stop.is_set():
                data = ("data: " + json.dumps(self.payload(), ensure_ascii=True) + "\n\n").encode()
                # Sin colas por navegador: snapshot cada segundo, cliente lento fuera.
                await asyncio.wait_for(response.write(data), timeout=3)
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(self.context.stop.wait(), timeout=1)
        except (ConnectionError, asyncio.TimeoutError):
            pass
        finally:
            self.streams -= 1
        return response

    async def start(self):
        self.runner = web.AppRunner(
            self.app,
            access_log=None,
            shutdown_timeout=3,
            keepalive_timeout=5,
            max_line_size=2048,
            max_field_size=2048,
        )
        await self.runner.setup()
        await web.TCPSite(
            self.runner, self.inputs.dashboard_host, self.inputs.dashboard_port
        ).start()

    async def close(self):
        if self.runner:
            await self.runner.cleanup()
