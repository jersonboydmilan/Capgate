"""Run the harness HTTP API.

`HarnessServer` starts the transport-independent `HarnessAPI` (harness.api) on
one of two transports:

  * ``uvicorn`` — production: h11 parsing plus the ASGI layer in harness.asgi.
    Run behind a proxy that bounds slow headers (see deploy/proxy).
  * ``stdlib`` — development and tests without extra dependencies.

The default is uvicorn when it is installed; override with ``transport=`` or the
``CAPGATE_HTTP_TRANSPORT`` environment variable.
"""

from __future__ import annotations

import os
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .api import MAX_BODY, HarnessAPI, Response
from .core import Harness
from .identity import TokenAuthority
from .ratelimit import RateLimitConfig
from .workload import WorkloadIdentity

REQUEST_TIMEOUT_SECONDS = 10.0


class TLSConfig:
    """Server TLS, optionally requiring and verifying client certificates (mTLS).

    With `client_ca`, the peer must present a certificate chaining to that CA;
    the harness then reads the peer's SPIFFE ID (URI SAN) and RFC 8705 SHA-256
    thumbprint and enforces any workload binding on the token. Verification is
    done by the stdlib `ssl` module, so no third-party library is needed.
    """

    def __init__(self, certfile: str, keyfile: str, *, client_ca: str | None = None, require_client_cert: bool = True) -> None:
        self.certfile, self.keyfile, self.client_ca = certfile, keyfile, client_ca
        self.require_client_cert = require_client_cert and client_ca is not None

    def server_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(self.certfile, self.keyfile)
        if self.client_ca is not None:
            ctx.load_verify_locations(self.client_ca)
            ctx.verify_mode = ssl.CERT_REQUIRED if self.require_client_cert else ssl.CERT_OPTIONAL
        return ctx


def default_transport() -> str:
    chosen = os.environ.get("CAPGATE_HTTP_TRANSPORT")
    if chosen:
        return chosen
    try:
        import uvicorn  # noqa: F401
    except ImportError:
        return "stdlib"
    return "uvicorn"


class HarnessServer:
    def __init__(
        self,
        harness: Harness,
        authority: TokenAuthority,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        rate_limit: RateLimitConfig | None = None,
        transport: str | None = None,
        trusted_proxies: list[str] | None = None,
        tls: "TLSConfig | None" = None,
    ) -> None:
        self.api = HarnessAPI(harness, authority, rate_limit=rate_limit)
        self.transport = transport or default_transport()
        if self.transport not in ("uvicorn", "stdlib"):
            raise ValueError(f"unknown transport {self.transport!r}")
        self.tls = tls
        self._thread: threading.Thread | None = None
        self._scheme = "https" if tls else "http"
        if self.transport == "stdlib":
            self.server: Any = ThreadingHTTPServer((host, port), _make_handler(self.api))
            if tls is not None:
                self.server.socket = tls.server_context().wrap_socket(self.server.socket, server_side=True)
                # a client that aborts the mTLS handshake (e.g. no cert) is not a server error: don't dump a traceback
                self.server.handle_error = lambda request, client_address: None
            self.address = self.server.server_address[:2]
        else:
            import uvicorn

            from .asgi import create_app

            self._socket = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.bind((host, port))
            self.address = self._socket.getsockname()[:2]
            ssl_kwargs = {}
            if tls is not None:
                ssl_kwargs = {"ssl_certfile": tls.certfile, "ssl_keyfile": tls.keyfile}
                if tls.client_ca is not None:
                    ssl_kwargs["ssl_ca_certs"] = tls.client_ca
                    ssl_kwargs["ssl_cert_reqs"] = ssl.CERT_REQUIRED if tls.require_client_cert else ssl.CERT_OPTIONAL
            config = uvicorn.Config(
                create_app(self.api, trusted_proxies=trusted_proxies),
                lifespan="off",
                **ssl_kwargs,
                log_level="warning",
                access_log=False,
                server_header=False,
                date_header=False,
                timeout_keep_alive=5,
                limit_concurrency=256,
                h11_max_incomplete_event_size=16_000,
                proxy_headers=False,  # client address comes from X-Real-IP of trusted proxies only (harness.asgi)
            )
            self.server = uvicorn.Server(config)
        self.url = f"{self._scheme}://{self.address[0]}:{self.address[1]}"

    @property
    def harness(self) -> Harness:
        return self.api.harness

    @property
    def authority(self) -> TokenAuthority:
        return self.api.authority

    @property
    def limiter(self):
        return self.api.limiter

    def start(self) -> "HarnessServer":
        if self.transport == "stdlib":
            self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self._thread.start()
            return self
        self._thread = threading.Thread(target=self.server.run, kwargs={"sockets": [self._socket]}, daemon=True)
        self._thread.start()
        deadline = time.time() + 10
        while not self.server.started:
            if time.time() > deadline or not self._thread.is_alive():
                raise RuntimeError("uvicorn did not start")
            time.sleep(0.01)
        return self

    def serve_forever(self) -> None:
        if self.transport == "stdlib":
            self.server.serve_forever()
        else:
            self.server.run(sockets=[self._socket])

    def stop(self) -> None:
        if self.transport == "stdlib":
            self.server.shutdown()
            self.server.server_close()
            return
        self.server.should_exit = True
        if self._thread:
            self._thread.join(timeout=10)
        self._socket.close()


def _make_handler(api: HarnessAPI):
    class Handler(BaseHTTPRequestHandler):
        server_version = "capgate"
        timeout = REQUEST_TIMEOUT_SECONDS  # per-socket-operation timeout: stalled clients cannot hold a thread

        def log_message(self, *args):
            pass

        def _send(self, response: Response) -> None:
            data = response.encode()
            self.send_response(response.status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            for name, value in response.headers.items():
                self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)
            if response.close:
                self.close_connection = True

        def _read_body(self) -> bytes | None:
            raw_length = self.headers.get("Content-Length")
            if raw_length is None or not raw_length.strip().isdigit():
                return None  # missing, negative or non-numeric: never "read until EOF"
            length = int(raw_length)
            if length > MAX_BODY:
                return None
            try:
                raw = self.rfile.read(length)
            except OSError:  # includes socket timeout
                return None
            return raw if len(raw) == length else None

        def _peer_workload(self) -> WorkloadIdentity | None:
            conn = self.connection
            if not isinstance(conn, ssl.SSLSocket):
                return None
            der = conn.getpeercert(binary_form=True)
            if not der:
                return None  # client sent no cert (CERT_OPTIONAL); token bindings then fail closed
            return WorkloadIdentity.from_peercert(conn.getpeercert(), der)

        def _handle(self) -> None:
            headers = {k: v for k, v in self.headers.items()}
            body = None
            if self.command == "POST":
                body = self._read_body()
                if body is None:
                    self._send(Response(400, {"error": "request body must be a JSON object under 1MB with a valid Content-Length"}, close=True))
                    return
            self._send(api.dispatch(self.command, self.path, headers, body, self.client_address[0], self._peer_workload()))

        do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _handle

    return Handler
