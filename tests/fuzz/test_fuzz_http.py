"""Raw-socket fuzzing of both HTTP transports.

For arbitrary and mutated request bytes: the server answers or closes the
connection promptly, keeps serving afterwards, and no tool ever runs.
"""

import os
import socket
import time

import pytest
from hypothesis import given, settings, strategies as st

from capgate import AuditLog, Harness, TaskContract
from capgate.identity import Keyring, TokenAuthority
from capgate.ratelimit import RateLimitConfig
from capgate.server import HarnessServer

DEEP = os.environ.get("HYPOTHESIS_PROFILE") == "deep"
VALID = b'POST /v1/actions HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nAuthorization: Bearer TOKEN\r\nContent-Length: 44\r\n\r\n{"action":"web.search","arguments":{"q":1}}'


@pytest.fixture(scope="module", params=["uvicorn", "stdlib"])
def server(request):
    calls = []
    contract = TaskContract.from_dict({"contract_id": "c", "goal": "g", "max_steps": 1_000_000, "agents": {"worker": {"capabilities": {"web.search": "allow"}}}})
    harness = Harness(contract, tools={"web.search": lambda a: calls.append(a)}, audit=AuditLog())
    authority = TokenAuthority(Keyring.generate())
    srv = HarnessServer(harness, authority, transport=request.param, rate_limit=RateLimitConfig(enabled=False)).start()
    srv.calls = calls
    yield srv
    srv.stop()


def exchange(address, payload: bytes, wait: float = 0.8) -> bytes:
    # No half-close: uvicorn treats a client EOF as a disconnect and sends nothing, which would
    # only hide responses from this test; an agent that half-closes merely loses its own reply.
    with socket.create_connection(address, timeout=wait) as s:
        try:
            s.sendall(payload)
        except OSError:
            return b""
        chunks = []
        try:
            while True:
                data = s.recv(65536)
                if not data:
                    break
                chunks.append(data)
        except (socket.timeout, OSError):
            pass
        return b"".join(chunks)


def healthy(address) -> bool:
    reply = exchange(address, b"GET /v1/health HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n")
    return reply.startswith(b"HTTP/1.1 200") or reply.startswith(b"HTTP/1.0 200")


def mutate(data: bytes, ops) -> bytes:
    buf = bytearray(data)
    for kind, pos, byte in ops:
        if not buf:
            break
        i = pos % len(buf)
        if kind == 0:
            buf[i] = byte
        elif kind == 1:
            buf.insert(i, byte)
        else:
            del buf[i]
    return bytes(buf)


@settings(max_examples=400 if DEEP else 20)
@given(ops=st.lists(st.tuples(st.integers(0, 2), st.integers(0, 10_000), st.integers(0, 255)), min_size=1, max_size=8))
def test_mutated_requests_never_execute_and_server_survives(server, ops):
    before = len(server.calls)
    started = time.time()
    exchange(server.address, mutate(VALID, ops))  # the token placeholder is not a valid token: nothing may execute
    assert time.time() - started < 12
    assert len(server.calls) == before


@settings(max_examples=200 if DEEP else 10)
@given(payload=st.binary(max_size=600))
def test_random_bytes(server, payload):
    exchange(server.address, payload)
    assert server.calls == []


@pytest.mark.parametrize("payload", [
    b"GET /v1/health HTTP/1.1\r\nHost: h\r\n" + b"X-Pad: " + b"a" * 100_000 + b"\r\n\r\n",                       # huge header
    b"POST /v1/actions HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n",  # TE + CL smuggling
    b"POST /v1/actions HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length: 50\r\n\r\n{}{}{}",           # duplicate CL
    b"POST /v1/actions HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFF\r\n",               # absurd chunk size
    b"GET /v1/health HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer a\r\nAuthorization: Bearer b\r\n\r\n",          # duplicate auth
    b"GET /" + b"a" * 70_000 + b" HTTP/1.1\r\nHost: h\r\n\r\n",                                                    # huge target
    b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03" + b"\x00" * 64,                                              # TLS hello to plain HTTP
    b"GET /v1/health HTTP/9.9\r\n\r\n",
    b"POST /v1/actions HTTP/1.1\r\nHost: h\r\nContent-Length: 18446744073709551616\r\n\r\n",                     # CL overflow
])
def test_classic_http_attacks(server, payload):
    exchange(server.address, payload)
    assert server.calls == []
    assert healthy(server.address)


def test_server_still_healthy_after_fuzzing(server):
    assert healthy(server.address)
    assert server.harness.audit.verify()
    assert server.harness.audit.query(event="server_error") == []
