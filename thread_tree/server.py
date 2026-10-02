"""Dependency-free HTTP server: static UI + JSON API.

Config endpoints accept a secret (the Thread dataset), so they are protected against other web
pages talking to localhost: JSON content type (forces a CORS preflight), Host allow-list (DNS
rebinding) and Origin check. The network key is never part of any response.
"""

from __future__ import annotations

import ipaddress
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .engine import Engine
from .runtime import ConfigLocked, Controller
from .topology import snapshot

WEB_DIR = Path(__file__).parent / "web"
MAX_BODY = 8192
_TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
          ".css": "text/css; charset=utf-8", ".json": "application/json; charset=utf-8",
          ".svg": "image/svg+xml"}


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def make_server(engine: Engine, host: str, port: int, controller: Controller) -> ThreadingHTTPServer:
    # On a loopback bind only local names are valid Host values; otherwise names are unknown.
    allowed_hosts = {"localhost", "127.0.0.1", "::1"} if is_loopback(host) else None

    def host_ok(header: str | None) -> bool:
        if allowed_hosts is None:
            return True
        if not header:
            return False
        name = header.rsplit(":", 1)[0] if not header.startswith("[") else header[: header.find("]") + 1]
        return name.strip("[]").lower() in allowed_hosts

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # quiet: never log request data
            pass

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, obj) -> None:
            self._send(code, json.dumps(obj).encode(), _TYPES[".json"])

        def _guard(self) -> bool:
            if not host_ok(self.headers.get("Host")):
                self._json(403, {"error": "forbidden host"})
                return False
            return True

        def do_GET(self):
            if not self._guard():
                return
            path = self.path.split("?", 1)[0]
            if path == "/api/topology":
                return self._json(200, snapshot(engine))
            if path == "/api/status":
                return self._json(200, controller.status())
            if path == "/api/config":
                return self._json(200, controller.config())
            rel = "index.html" if path == "/" else path.lstrip("/")
            target = (WEB_DIR / rel).resolve()
            if WEB_DIR.resolve() not in target.parents or not target.is_file():
                return self._send(404, b"not found", "text/plain")
            self._send(200, target.read_bytes(), _TYPES.get(target.suffix, "application/octet-stream"))

        def _config_write(self, action: str) -> None:
            if not self._guard():
                return
            origin = self.headers.get("Origin")
            if origin and urlsplit(origin).netloc != self.headers.get("Host"):
                return self._json(403, {"error": "forbidden origin"})
            if self.path.split("?", 1)[0] != "/api/config/dataset":
                return self._json(404, {"error": "not found"})
            try:
                if action == "set":
                    if not (self.headers.get("Content-Type") or "").startswith("application/json"):
                        return self._json(415, {"error": "content type must be application/json"})
                    length = int(self.headers.get("Content-Length") or 0)
                    if not 0 < length <= MAX_BODY:
                        return self._json(413, {"error": "body too large or empty"})
                    value = json.loads(self.rfile.read(length)).get("dataset")
                    if not isinstance(value, str):
                        raise ValueError("field 'dataset' (hex string) missing")
                    return self._json(200, controller.set_dataset(value))
                return self._json(200, controller.clear_dataset())
            except ConfigLocked as exc:
                self._json(403, {"error": "locked", "reason": str(exc)})
            except (ValueError, json.JSONDecodeError) as exc:
                self._json(400, {"error": str(exc)})

        def do_POST(self):
            self._config_write("set")

        def do_DELETE(self):
            self._config_write("clear")

    return ThreadingHTTPServer((host, port), Handler)
