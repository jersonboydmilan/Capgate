"""ASGI transport for the harness API (production: run under uvicorn).

    capgate serve server.yaml               # uses this transport when uvicorn is installed

HTTP parsing is done by uvicorn/h11. This layer adds what the harness needs on
top: a streaming body-size cap (413 before the whole body is buffered), a
per-chunk read timeout (a stalled body cannot hold a worker), header-size and
method checks, and it runs the blocking harness API in a thread pool.

uvicorn does not bound how slowly request *headers* arrive. In the reference
deployment nginx sits in front and enforces header/body timeouts and sizes;
do the same (or use an equivalent proxy) wherever untrusted agents connect.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
from typing import Any

from .api import MAX_BODY, HarnessAPI, Response
from .workload import WorkloadIdentity, parse_spiffe_id

BODY_CHUNK_TIMEOUT_SECONDS = 10.0
MAX_HEADER_BYTES = 16_000


def create_app(api: HarnessAPI, *, trusted_proxies: list[str] | None = None) -> Any:
    """Build the ASGI app.

    `trusted_proxies`: CIDRs of front proxies whose forwarded headers are
    believed — X-Real-IP for the client address, and, for mTLS terminated at
    the proxy, X-Client-Spiffe-Id / X-Client-Cert-Thumbprint for the verified
    workload identity. Headers from any other source are ignored, so a client
    cannot forge its own workload identity.
    """
    networks = [ipaddress.ip_network(n, strict=False) for n in (trusted_proxies or [])]

    def from_trusted_proxy(scope: dict) -> bool:
        if not networks:
            return False
        peer = (scope.get("client") or ("", 0))[0]
        try:
            return any(ipaddress.ip_address(peer) in net for net in networks)
        except ValueError:
            return False

    def client_address(scope: dict, headers: dict[str, str], trusted: bool) -> str:
        peer = (scope.get("client") or ("unknown", 0))[0]
        real = headers.get("x-real-ip")
        if real and trusted:
            try:
                return str(ipaddress.ip_address(real.strip()))
            except ValueError:
                pass
        return peer

    def forwarded_workload(headers: dict[str, str], trusted: bool) -> WorkloadIdentity | None:
        if not trusted:
            return None  # never believe workload headers from a non-proxy peer
        spiffe = headers.get("x-client-spiffe-id") or None
        thumbprint = headers.get("x-client-cert-thumbprint") or None
        if spiffe is None and thumbprint is None:
            return None
        if spiffe is not None:
            try:
                parse_spiffe_id(spiffe)
            except Exception:
                return WorkloadIdentity(verified=True)  # malformed → present but matches nothing
        return WorkloadIdentity(spiffe_id=spiffe, thumbprint=thumbprint, verified=True)

    async def send_response(send: Any, response: Response, *, head: bool = False) -> None:
        body = response.encode()
        headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()), (b"cache-control", b"no-store")]
        headers += [(k.lower().encode(), v.encode()) for k, v in response.headers.items()]
        if response.close:
            headers.append((b"connection", b"close"))
        await send({"type": "http.response.start", "status": response.status, "headers": headers})
        await send({"type": "http.response.body", "body": b"" if head else body})

    async def app(scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            return

        raw_headers = scope.get("headers") or []
        if sum(len(k) + len(v) for k, v in raw_headers) > MAX_HEADER_BYTES:
            await send_response(send, Response(431, {"error": "request headers too large"}, close=True))
            return
        headers: dict[str, str] = {}
        for k, v in raw_headers:
            key = k.decode("latin-1").lower()
            if key in headers:  # duplicate headers are ambiguous (e.g. two Authorization headers): refuse
                await send_response(send, Response(400, {"error": f"duplicate header: {key}"}, close=True))
                return
            headers[key] = v.decode("latin-1")

        method = scope.get("method", "GET")
        declared = headers.get("content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > MAX_BODY):
            await send_response(send, Response(413 if declared.isdigit() else 400, {"error": "request body must be under 1MB with a valid Content-Length"}, close=True))
            return

        body = bytearray()
        if method == "POST":
            while True:
                try:
                    message = await asyncio.wait_for(receive(), timeout=BODY_CHUNK_TIMEOUT_SECONDS)
                except asyncio.TimeoutError:
                    await send_response(send, Response(408, {"error": "request body timed out"}, close=True))
                    return
                if message["type"] == "http.disconnect":
                    return
                body.extend(message.get("body", b""))
                if len(body) > MAX_BODY:
                    await send_response(send, Response(413, {"error": "request body must be under 1MB"}, close=True))
                    return
                if not message.get("more_body"):
                    break

        target = scope.get("raw_path", scope.get("path", "/").encode()).decode("latin-1")
        if scope.get("query_string"):
            target += "?" + scope["query_string"].decode("latin-1")
        trusted = from_trusted_proxy(scope)
        response = await asyncio.to_thread(
            api.dispatch, method, target, headers, bytes(body) if method == "POST" else None,
            client_address(scope, headers, trusted), forwarded_workload(headers, trusted),
        )
        await send_response(send, response, head=method == "HEAD")

    return app
