"""`harness inspect`: a local, single-user inspection UI.

Serves one static page and a small JSON API on 127.0.0.1. Simulation, policy
and audit views run locally on the same engine as the CLI. The escalation
view proxies to a running harness HTTP API with an approver token that stays
in this process and is never sent to the browser.

Local web servers that can approve actions are CSRF and DNS-rebinding
targets, so every API request must carry the per-session nonce embedded in the
page (a cross-origin page cannot read it, and the custom header forces a CORS
preflight this server never answers), and the Host header must name this server.
"""

from __future__ import annotations

import json
import secrets
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit

from . import model

NONCE_HEADER = "X-Inspect-Nonce"
MAX_BODY = 2_000_000


class InspectServer:
    def __init__(
        self,
        *,
        tasks: list[str | Path] | None = None,
        audit_path: str | Path | None = None,
        harness_url: str | None = None,
        approver_token: Callable[[], str] | None = None,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError("harness inspect binds to loopback only")
        self.tasks = [Path(t).resolve() for t in (tasks or [])]
        self.audit_path = str(Path(audit_path).resolve()) if audit_path else ""
        self.harness_url = harness_url.rstrip("/") if harness_url else None
        self._approver_token = approver_token
        self.nonce = secrets.token_urlsafe(24)
        try:
            self.server = ThreadingHTTPServer((host, port), _make_handler(self))
        except OSError as exc:
            if port == 0 or exc.errno not in (48, 98):  # EADDRINUSE (macOS, Linux)
                raise
            self.server = ThreadingHTTPServer((host, 0), _make_handler(self))  # preferred port busy: take a free one
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}/"
        self._thread: threading.Thread | None = None

    def start(self) -> "InspectServer":
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    # -- API -----------------------------------------------------------------------

    def config(self) -> dict[str, Any]:
        return {
            "tasks": [str(t) for t in self.tasks],
            "audit_path": self.audit_path,
            "approvals": {"configured": bool(self.harness_url and self._approver_token), "harness_url": self.harness_url},
        }

    def load_task(self, path: str) -> dict[str, Any]:
        import yaml

        task_path = Path(path).expanduser().resolve()
        if not task_path.is_file():
            raise model.InputError(f"task file not found: {task_path}")
        text = task_path.read_text(encoding="utf-8")
        data = yaml.safe_load(text) or {}
        contract_texts, sources = [], []
        if isinstance(data, dict):
            sources = ([data["contract"]] if "contract" in data else []) + list(data.get("contracts") or [])
        for source in sources:
            if isinstance(source, str):
                contract_texts.append((task_path.parent / source).read_text(encoding="utf-8").strip())
            elif isinstance(source, dict):
                contract_texts.append(yaml.safe_dump(source, sort_keys=False).strip())
        return {"path": str(task_path), "base_dir": str(task_path.parent), "task_text": text, "contracts_text": "\n---\n".join(contract_texts)}

    def approvals(self) -> tuple[int, Any]:
        return self._proxy("GET", "/v1/approvals")

    def decide(self, approval_id: str, verdict: str, note: str) -> tuple[int, Any]:
        if verdict not in ("approve", "reject"):
            raise model.InputError("verdict must be approve or reject")
        if not approval_id.replace("-", "").isalnum():
            raise model.InputError("invalid approval id")
        return self._proxy("POST", f"/v1/approvals/{approval_id}", {"verdict": verdict, "note": note})

    def _proxy(self, method: str, path: str, body: dict | None = None) -> tuple[int, Any]:
        if not (self.harness_url and self._approver_token):
            raise model.InputError("approvals are not configured: start with --harness-url and --approver-token-file")
        req = urllib.request.Request(
            self.harness_url + path,
            data=json.dumps(body).encode() if body is not None else None,
            method=method,
            headers={"Authorization": f"Bearer {self._approver_token()}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read() or b"{}")
            except json.JSONDecodeError:
                return exc.code, {"error": f"harness returned HTTP {exc.code}"}
        except OSError as exc:
            return 502, {"error": f"cannot reach harness at {self.harness_url}: {exc}"}


def _make_handler(app: InspectServer):
    page = resources.files("harness.inspect").joinpath("static/index.html").read_text(encoding="utf-8")

    class Handler(BaseHTTPRequestHandler):
        server_version = "harness-inspect"
        timeout = 30

        def log_message(self, *args):
            pass

        def _send(self, code: int, body: Any, content_type: str = "application/json", extra: dict | None = None) -> None:
            data = body if isinstance(body, bytes) else json.dumps(body, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _host_ok(self) -> bool:
            host = (self.headers.get("Host") or "").lower()
            return host in (f"127.0.0.1:{app.port}", f"localhost:{app.port}", f"[::1]:{app.port}")

        def _authorized(self) -> bool:
            given = self.headers.get(NONCE_HEADER, "")
            return self._host_ok() and secrets.compare_digest(given, app.nonce)

        def _json_body(self) -> dict:
            raw_length = self.headers.get("Content-Length", "")
            if not raw_length.isdigit() or int(raw_length) > MAX_BODY:
                raise model.InputError("request body missing or too large")
            data = json.loads(self.rfile.read(int(raw_length)) or b"{}")
            if not isinstance(data, dict):
                raise model.InputError("request body must be a JSON object")
            return data

        def do_GET(self) -> None:
            url = urlsplit(self.path)
            if not self._host_ok():
                self._send(403, {"error": "unexpected Host header"})
                return
            if url.path in ("/", "/index.html"):
                html = page.replace("__INSPECT_NONCE__", app.nonce).encode()
                csp = f"default-src 'none'; script-src 'nonce-{app.nonce}'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
                self._send(200, html, "text/html; charset=utf-8", {"Content-Security-Policy": csp})
                return
            if not self._authorized():
                self._send(403, {"error": "missing or invalid inspect nonce"})
                return
            q = {k: v[0] for k, v in parse_qs(url.query).items()}
            self._dispatch(lambda: self._get(url.path, q))

        def do_POST(self) -> None:
            if not self._authorized():
                self._send(403, {"error": "missing or invalid inspect nonce"})
                return
            url = urlsplit(self.path)
            self._dispatch(lambda: self._post(url.path, self._json_body()))

        def _dispatch(self, fn: Callable[[], tuple[int, Any]]) -> None:
            try:
                code, body = fn()
                self._send(code, body)
            except model.InputError as exc:
                self._send(422, {"error": str(exc)})
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._send(400, {"error": "invalid JSON"})
            except Exception as exc:  # local developer tool: show the failure instead of hanging the UI
                self._send(500, {"error": f"{type(exc).__name__}: {exc}"})

        def _get(self, path: str, q: dict[str, str]) -> tuple[int, Any]:
            if path == "/api/config":
                return 200, app.config()
            if path == "/api/task":
                return 200, app.load_task(q.get("path", ""))
            if path == "/api/audit":
                return 200, model.audit_view(
                    q.get("path") or app.audit_path,
                    agent=q.get("agent", ""), action=q.get("action", ""), decision=q.get("decision", ""),
                    event=q.get("event", ""), decision_id=q.get("decision_id", ""), limit=int(q.get("limit", "500")),
                )
            if path == "/api/approvals":
                return app.approvals()
            return 404, {"error": "not found"}

        def _post(self, path: str, body: dict) -> tuple[int, Any]:
            if path == "/api/simulate":
                return 200, model.simulate(body.get("task_text", ""), body.get("contracts_text", ""), body.get("base_dir") or ".")
            if path == "/api/policy":
                return 200, model.policy(body.get("contracts_text", ""))
            if path == "/api/explain":
                return 200, model.explain(body.get("contracts_text", ""), body.get("agent", ""), body.get("action", ""), body.get("arguments", {}), body.get("contract_id"))
            if path == "/api/diff":
                return 200, model.diff(body.get("left", ""), body.get("right", ""))
            if path.startswith("/api/approvals/"):
                return app.decide(path.rsplit("/", 1)[-1], body.get("verdict", ""), str(body.get("note", "")))
            return 404, {"error": "not found"}

    return Handler
