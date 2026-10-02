"""Dependency-free HTTP server: static UI + JSON API.

Config endpoints accept a secret (the Thread dataset), so they are protected against other web
pages talking to localhost: JSON content type (forces a CORS preflight), Host allow-list (DNS
rebinding) and Origin check. The network key is never part of any response.
"""

from __future__ import annotations

import ipaddress
import json
import socket
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


LOCAL_NAMES = {"localhost", "127.0.0.1", "::1"}


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (getattr(ip, "ipv4_mapped", None) or ip).is_loopback


def host_name(header: str | None) -> str:
    """Host header without port and brackets."""
    if not header:
        return ""
    name = header[: header.find("]") + 1] if header.startswith("[") else header.rsplit(":", 1)[0]
    return name.strip("[]").lower()


def may_write(client_ip: str, host_header: str | None, allow_remote: bool) -> bool:
    """Who may change the dataset: everybody if allow_remote (the default of the CLI), otherwise only
    this machine (incl. SSH tunnels) addressed by a local name, which also defeats DNS rebinding
    (--local-config-only)."""
    return allow_remote or (is_loopback(client_ip) and host_name(host_header) in LOCAL_NAMES)


def make_server(engine: Engine, host: str, port: int, controller: Controller) -> ThreadingHTTPServer:
    # On a loopback bind only local names are valid Host values; otherwise names are unknown.
    bound_to_loopback = is_loopback(host)

    def host_ok(header: str | None) -> bool:
        return not bound_to_loopback or host_name(header) in LOCAL_NAMES

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
                cfg = controller.config()
                if cfg["editable"] and not may_write(self.client_address[0], self.headers.get("Host"),
                                                     controller.allow_remote_config):
                    cfg["editable"], cfg["locked_reason"] = False, "remote"
                return self._json(200, cfg)
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
            if controller.editable and not may_write(self.client_address[0], self.headers.get("Host"),
                                                     controller.allow_remote_config):
                return self._json(403, {"error": "locked", "reason": "remote"})
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

    class Server(ThreadingHTTPServer):
        address_family = socket.AF_INET6 if ":" in host else socket.AF_INET

    return Server((host, port), Handler)
