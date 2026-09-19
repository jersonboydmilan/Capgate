"""Reference SPIFFE-aware mTLS edge.

Terminates the agent's mutual-TLS connection, verifies the client certificate
against a CA (trust bundle), and forwards each request to the harness over
plain HTTP on an internal network, adding the *verified* workload identity:

    X-Client-Spiffe-Id:       spiffe://…      (the client cert's URI SAN, if any)
    X-Client-Cert-Thumbprint: <base64url SHA-256 of the client cert DER>   (RFC 8705)
    X-Real-IP:                <agent's address>

Any client-supplied copy of those headers is stripped first, so an agent
cannot forge its own identity. The harness believes these only from the edge's
network (its `trusted_proxies`).

This is the offline, dependency-free reference terminator — the stdlib `ssl`
module does the cert verification and SAN/thumbprint extraction. In production
an Envoy/SPIRE or ghostunnel sidecar does the same job and forwards the same
headers; the harness does not care which, it only trusts the source network.

    python -m capgate.mtlsedge --listen 0.0.0.0:8443 --upstream http://harness:8080 \
        --cert /run/secrets/edge.pem --key /run/secrets/edge.key --client-ca /run/secrets/ca.pem
"""

from __future__ import annotations

import argparse
import http.client
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .workload import WorkloadIdentity

MAX_BODY = 1_000_000
REQUEST_TIMEOUT_SECONDS = 10.0
UPSTREAM_TIMEOUT_SECONDS = 30.0
# Identity headers are authoritative from the edge; never pass a client's own copies through.
STRIP = {"x-client-spiffe-id", "x-client-cert-thumbprint", "x-real-ip", "x-forwarded-for", "forwarded"}
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"}


class MTLSEdge:
    def __init__(self, upstream: str, cert: str, key: str, client_ca: str, *, host: str = "127.0.0.1", port: int = 0) -> None:
        up = urlsplit(upstream)
        if up.scheme != "http" or not up.hostname:
            raise ValueError("upstream must be http://host:port (the internal harness address)")
        self.upstream_host = up.hostname
        self.upstream_port = up.port or 80
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert, key)
        ctx.load_verify_locations(client_ca)
        ctx.verify_mode = ssl.CERT_REQUIRED  # no client cert -> no connection
        self._ctx = ctx
        self.server = ThreadingHTTPServer((host, port), _make_handler(self))
        self.server.handle_error = lambda request, client_address: None  # a bad handshake is not a server error
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.address = self.server.server_address[:2]
        self.url = f"https://{self.address[0]}:{self.address[1]}"
        self._thread: threading.Thread | None = None

    def start(self) -> "MTLSEdge":
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def serve_forever(self) -> None:
        self.server.serve_forever()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def _make_handler(edge: MTLSEdge):
    class Handler(BaseHTTPRequestHandler):
        server_version = "capgate-mtls-edge"
        protocol_version = "HTTP/1.1"
        timeout = REQUEST_TIMEOUT_SECONDS

        def log_message(self, *args):
            pass

        def _identity(self) -> WorkloadIdentity | None:
            conn = self.connection
            if not isinstance(conn, ssl.SSLSocket):
                return None
            der = conn.getpeercert(binary_form=True)
            if not der:
                return None
            return WorkloadIdentity.from_peercert(conn.getpeercert(), der)

        def _fail(self, code: int, message: str) -> None:
            body = f'{{"error":"{message}"}}'.encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def _handle(self) -> None:
            identity = self._identity()
            if identity is None or not identity.present:
                self._fail(400, "client certificate required")
                return
            body = b""
            if self.command in ("POST", "PUT", "PATCH"):
                raw_len = self.headers.get("Content-Length")
                if raw_len is None or not raw_len.strip().isdigit() or int(raw_len) > MAX_BODY:
                    self._fail(413, "missing or oversized body")
                    return
                try:
                    body = self.rfile.read(int(raw_len))
                except OSError:
                    self._fail(408, "request timed out")
                    return
                if len(body) != int(raw_len):
                    self._fail(400, "short body")
                    return

            headers = {k: v for k, v in self.headers.items() if k.lower() not in STRIP and k.lower() not in HOP_BY_HOP}
            headers["X-Real-IP"] = self.client_address[0]
            headers["X-Client-Cert-Thumbprint"] = identity.thumbprint or ""
            if identity.spiffe_id:
                headers["X-Client-Spiffe-Id"] = identity.spiffe_id
            headers["Connection"] = "close"

            try:
                conn = http.client.HTTPConnection(edge.upstream_host, edge.upstream_port, timeout=UPSTREAM_TIMEOUT_SECONDS)
                conn.request(self.command, self.path, body=body if body else None, headers=headers)
                resp = conn.getresponse()
                payload = resp.read()
            except OSError:
                self._fail(502, "upstream unavailable")
                return
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() not in HOP_BY_HOP and k.lower() != "content-length":
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)
            self.close_connection = True
            conn.close()

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _handle

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--listen", default="0.0.0.0:8443", help="host:port to accept agent mTLS on")
    parser.add_argument("--upstream", required=True, help="internal harness URL, e.g. http://harness:8080")
    parser.add_argument("--cert", required=True, help="edge server certificate (PEM)")
    parser.add_argument("--key", required=True, help="edge server private key (PEM)")
    parser.add_argument("--client-ca", required=True, help="CA bundle that agent client certs must chain to (PEM)")
    args = parser.parse_args()
    host, _, port = args.listen.rpartition(":")
    edge = MTLSEdge(args.upstream, args.cert, args.key, args.client_ca, host=host or "0.0.0.0", port=int(port))
    print(f"capgate mTLS edge on {edge.url} -> {args.upstream}", flush=True)
    try:
        edge.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
