"""Reference controlled tool endpoint.

A stand-in for a real consequential system (a database, a payments API). It
accepts requests only when they carry the executor's credential, and records
every side effect it performs in a ledger, so tests can prove that an
unauthorized request produced no side effect — not merely that a decision
object said "deny".

    python -m harness.toolservice --port 9100 --credential-file /run/secrets/tool_credential --ledger ledger.jsonl
"""

from __future__ import annotations

import argparse
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .secretsource import read_secret


class ToolService:
    def __init__(self, credential: str, ledger: str | Path, host: str = "127.0.0.1", port: int = 0) -> None:
        self._credential = credential
        self.ledger = Path(ledger)
        self._lock = threading.Lock()
        service = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # quiet
                pass

            def do_GET(self):
                if self.path == "/health":
                    self._send(200, {"ok": True})
                else:
                    self._send(404, {"error": "not found"})

            def do_POST(self):
                auth = self.headers.get("Authorization", "")
                if not hmac.compare_digest(auth.encode(), f"Bearer {service._credential}".encode()):
                    self._send(401, {"error": "unauthorized"})
                    return
                length = min(int(self.headers.get("Content-Length") or 0), 1_000_000)
                try:
                    payload = json.loads(self.rfile.read(length) or b"{}")
                except json.JSONDecodeError:
                    self._send(400, {"error": "invalid json"})
                    return
                with service._lock:
                    with service.ledger.open("a", encoding="utf-8") as fh:
                        fh.write(json.dumps({"path": self.path, "payload": payload}) + "\n")
                self._send(200, {"ok": True, "path": self.path, "stored": payload})

            def _send(self, code, body):
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer((host, port), Handler)
        self.url = f"http://{host}:{self.server.server_address[1]}"
        self._thread: threading.Thread | None = None

    def side_effects(self) -> list[dict]:
        if not self.ledger.exists():
            return []
        return [json.loads(line) for line in self.ledger.read_text().splitlines() if line.strip()]

    def start(self) -> "ToolService":
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9100)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--credential-env")
    source.add_argument("--credential-file")
    parser.add_argument("--ledger", default="tool-ledger.jsonl")
    args = parser.parse_args()
    try:
        credential = read_secret({"credential_env": args.credential_env, "credential_file": args.credential_file}, "credential", "tool service")
    except ValueError as exc:
        parser.error(str(exc))
    service = ToolService(credential, args.ledger, args.host, args.port)
    print(f"controlled tool endpoint on {service.url}", flush=True)
    service.server.serve_forever()


if __name__ == "__main__":
    main()
