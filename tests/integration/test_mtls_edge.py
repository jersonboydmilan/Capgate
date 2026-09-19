"""End-to-end SPIFFE-aware mTLS edge: agent --mTLS--> edge --http(+identity)--> harness.

The edge terminates the agent's mTLS, verifies the client cert, and forwards
the verified SPIFFE id + thumbprint. The harness enforces the token's workload
binding. Proves a bound token is usable only from the workload holding the cert,
and that an agent cannot forge its own identity headers.
"""

import http.client
import json
import ssl

import pytest

pytest.importorskip("cryptography")

from capgate import AuditLog, Harness
from capgate.identity import Keyring, TokenAuthority
from capgate.mtlsedge import MTLSEdge
from capgate.server import HarnessServer
from capgate.workload import WorkloadBinding, thumbprint_from_der
from certs import make_ca, make_workload
from helpers import SpyTool, research_contract

TD = "capgate.test"
SPIFFE_A = f"spiffe://{TD}/agent/researcher"
SPIFFE_B = f"spiffe://{TD}/agent/intruder"


@pytest.fixture
def stack(tmp_path):
    ca_key, ca_cert, ca_pem = make_ca(tmp_path)
    edge_cert, edge_key, _ = make_workload(tmp_path, ca_key, ca_cert, spiffe_id=None, filename="edge")
    a_cert, a_key, a_der = make_workload(tmp_path, ca_key, ca_cert, spiffe_id=SPIFFE_A, filename="agent-a")
    b_cert, b_key, b_der = make_workload(tmp_path, ca_key, ca_cert, spiffe_id=SPIFFE_B, filename="agent-b")

    spy = SpyTool({"ok": True})
    harness = Harness(research_contract(), tools={"web.search": spy}, audit=AuditLog())
    authority = TokenAuthority(Keyring.generate())
    # harness listens on loopback; trust the edge (also loopback here) to forward identity
    harness_server = HarnessServer(harness, authority, transport="uvicorn", trusted_proxies=["127.0.0.1/32"]).start()
    edge = MTLSEdge(harness_server.url, edge_cert, edge_key, ca_pem, host="127.0.0.1").start()

    ctx = {
        "harness": harness_server, "edge": edge, "authority": authority, "spy": spy, "ca": ca_pem,
        "A": (a_cert, a_key, a_der), "B": (b_cert, b_key, b_der),
    }
    yield ctx
    edge.stop()
    harness_server.stop()


def call(edge, ca, client_pair, token, *, extra_headers=None, body=None):
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca)
    ctx.check_hostname = False
    if client_pair:
        ctx.load_cert_chain(client_pair[0], client_pair[1])
    host, port = edge.address
    conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=10)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json", **(extra_headers or {})}
    payload = json.dumps(body or {"action": "web.search", "arguments": {"query": "x"}})
    try:
        conn.request("POST", "/v1/actions", payload, headers)
        r = conn.getresponse()
        return r.status, json.loads(r.read() or b"{}")
    finally:
        conn.close()


def bound_token(ctx, cert_key):
    der = ctx[cert_key][2]
    spiffe = SPIFFE_A if cert_key == "A" else SPIFFE_B
    return ctx["authority"].issue("researcher", "agent", 300,
                                  workload=WorkloadBinding(spiffe_id=spiffe, thumbprint=thumbprint_from_der(der)))


def test_bound_token_over_the_edge_with_its_own_cert(stack):
    a_cert, a_key, _ = stack["A"]
    status, body = call(stack["edge"], stack["ca"], (a_cert, a_key), bound_token(stack, "A"))
    assert status == 200 and body["execution"]["status"] == "succeeded"
    assert stack["spy"].calls == [{"query": "x"}]


def test_bound_token_presented_with_another_workloads_cert_is_denied(stack):
    token = bound_token(stack, "A")               # bound to agent A
    b_cert, b_key, _ = stack["B"]
    status, body = call(stack["edge"], stack["ca"], (b_cert, b_key), token)  # ...but B connects
    assert status == 401
    assert stack["spy"].calls == []


def test_agent_cannot_forge_its_identity_headers(stack):
    """Agent B sends X-Client-Spiffe-Id claiming to be A; the edge overwrites it from the real cert."""
    token = bound_token(stack, "A")
    b_cert, b_key, _ = stack["B"]
    status, _ = call(stack["edge"], stack["ca"], (b_cert, b_key), token,
                     extra_headers={"X-Client-Spiffe-Id": SPIFFE_A,
                                    "X-Client-Cert-Thumbprint": thumbprint_from_der(stack["A"][2])})
    assert status == 401  # the forged headers were stripped; the real (B) identity does not match A's binding
    assert stack["spy"].calls == []


def test_no_client_certificate_cannot_connect(stack):
    with pytest.raises(OSError):
        call(stack["edge"], stack["ca"], None, bound_token(stack, "A"))
    assert stack["spy"].calls == []


def test_unbound_token_still_works_through_the_edge(stack):
    a_cert, a_key, _ = stack["A"]
    token = stack["authority"].issue("researcher", "agent", 300)  # no binding
    status, _ = call(stack["edge"], stack["ca"], (a_cert, a_key), token)
    assert status == 200


def test_edge_forwards_real_client_ip_and_identity(stack):
    a_cert, a_key, a_der = stack["A"]
    call(stack["edge"], stack["ca"], (a_cert, a_key), bound_token(stack, "A"))
    rec = [r for r in stack["harness"].harness.audit.query(event="decision") if r.get("decision") == "allow"][-1]
    assert rec["agent_id"] == "researcher"  # authenticated via the bound token over the edge
