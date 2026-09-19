"""Workload identity: a token bound to a workload is useless without that workload's client cert.

Covers the pure binding logic, the stdlib server terminating real mTLS, and the
forwarded-header path a trusted mTLS proxy uses.
"""

import http.client
import json
import ssl

import pytest

pytest.importorskip("cryptography")

from capgate import AuditLog, Harness
from capgate.identity import Keyring, TokenAuthority, TokenError
from capgate.server import HarnessServer, TLSConfig
from capgate.workload import (
    WorkloadBinding, WorkloadIdentity, parse_spiffe_id, thumbprint_from_der, WorkloadError,
)
from certs import make_ca, make_workload
from helpers import SpyTool, research_contract

TD = "example.org"
SPIFFE_A = f"spiffe://{TD}/agent/researcher"
SPIFFE_B = f"spiffe://{TD}/agent/other"


# ---- unit: SPIFFE parsing + thumbprint ----------------------------------------------

@pytest.mark.parametrize("bad", ["", "http://x", "spiffe://", "spiffe:///path", "spiffe://EXAMPLE/p", "spiffe://x/..", "spiffe://x/a?b", "spiffe://x/a#b"])
def test_invalid_spiffe_ids_rejected(bad):
    with pytest.raises(WorkloadError):
        parse_spiffe_id(bad)


def test_spiffe_ok():
    sid = parse_spiffe_id(SPIFFE_A)
    assert sid.trust_domain == TD and sid.path == "/agent/researcher" and str(sid) == SPIFFE_A


def test_thumbprint_is_stable_base64url_sha256():
    tp = thumbprint_from_der(b"cert-bytes")
    import base64, hashlib
    assert tp == base64.urlsafe_b64encode(hashlib.sha256(b"cert-bytes").digest()).rstrip(b"=").decode()
    assert len(tp) == 43 and "=" not in tp


# ---- binding enforcement in the authority -------------------------------------------

def authority():
    return TokenAuthority(Keyring.generate())


def test_bound_token_needs_matching_workload():
    a = authority()
    der = b"the-agent-cert-der"
    binding = WorkloadBinding(spiffe_id=SPIFFE_A, thumbprint=thumbprint_from_der(der))
    token = a.issue("researcher", "agent", 300, workload=binding)
    good = WorkloadIdentity.from_peercert({"subjectAltName": (("URI", SPIFFE_A),)}, der)

    assert a.verify(token, workload=good).sub == "researcher"
    with pytest.raises(TokenError, match="TOKEN_BINDING_REQUIRED"):
        a.verify(token)                                   # no cert at all
    with pytest.raises(TokenError, match="TOKEN_BINDING_REQUIRED"):
        a.verify(token, workload=WorkloadIdentity())      # unverified/empty
    with pytest.raises(TokenError, match="TOKEN_BINDING_MISMATCH"):
        a.verify(token, workload=WorkloadIdentity.from_peercert({"subjectAltName": (("URI", SPIFFE_A),)}, b"different-der"))
    with pytest.raises(TokenError, match="TOKEN_BINDING_MISMATCH"):
        a.verify(token, workload=WorkloadIdentity.from_peercert({"subjectAltName": (("URI", SPIFFE_B),)}, der))


def test_unbound_token_ignores_any_presented_cert():
    a = authority()
    token = a.issue("researcher", "agent", 300)
    assert a.verify(token, workload=WorkloadIdentity(spiffe_id=SPIFFE_A, thumbprint="x" * 43, verified=True)).sub == "researcher"


def test_thumbprint_only_and_spiffe_only_bindings():
    a = authority()
    der = b"c"
    tp = thumbprint_from_der(der)
    tok_tp = a.issue("researcher", "agent", 300, workload=WorkloadBinding(thumbprint=tp))
    assert a.verify(tok_tp, workload=WorkloadIdentity(thumbprint=tp, verified=True)).sub == "researcher"
    with pytest.raises(TokenError, match="MISMATCH"):
        a.verify(tok_tp, workload=WorkloadIdentity(thumbprint="y" * 43, verified=True))
    tok_sp = a.issue("researcher", "agent", 300, workload=WorkloadBinding(spiffe_id=SPIFFE_A))
    assert a.verify(tok_sp, workload=WorkloadIdentity(spiffe_id=SPIFFE_A, verified=True)).sub == "researcher"


# ---- end to end over real mTLS (stdlib transport) -----------------------------------

@pytest.fixture
def mtls(tmp_path):
    ca_key, ca_cert, ca_pem = make_ca(tmp_path)
    server_cert, server_key, _ = make_workload(tmp_path, ca_key, ca_cert, spiffe_id=None, filename="server")
    a_cert, a_key, a_der = make_workload(tmp_path, ca_key, ca_cert, spiffe_id=SPIFFE_A, filename="agent-a")
    b_cert, b_key, b_der = make_workload(tmp_path, ca_key, ca_cert, spiffe_id=SPIFFE_B, filename="agent-b")

    spy = SpyTool()
    harness = Harness(research_contract(), tools={"web.search": spy}, audit=AuditLog())
    authority = TokenAuthority(Keyring.generate())
    tls = TLSConfig(server_cert, server_key, client_ca=ca_pem, require_client_cert=True)
    server = HarnessServer(harness, authority, transport="stdlib", tls=tls).start()
    ctx = {"server": server, "authority": authority, "spy": spy, "ca": ca_pem,
           "A": (a_cert, a_key, a_der), "B": (b_cert, b_key, b_der)}
    yield ctx
    server.stop()


def call(server, ca, client_pair, token, action="web.search"):
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca)
    ctx.check_hostname = False
    if client_pair:
        ctx.load_cert_chain(client_pair[0], client_pair[1])
    host, port = server.address
    conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=10)
    try:
        conn.request("POST", "/v1/actions", json.dumps({"action": action, "arguments": {"query": "x"}}),
                     {"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        r = conn.getresponse()
        return r.status, json.loads(r.read() or b"{}")
    finally:
        conn.close()


def test_bound_token_works_only_with_its_own_cert(mtls):
    a = mtls["authority"]
    a_cert, a_key, a_der = mtls["A"]
    binding = WorkloadBinding(spiffe_id=SPIFFE_A, thumbprint=thumbprint_from_der(a_der))
    token = a.issue("researcher", "agent", 300, workload=binding)

    status, body = call(mtls["server"], mtls["ca"], (a_cert, a_key), token)
    assert status == 200 and body["execution"]["status"] == "succeeded"
    assert mtls["spy"].calls == [{"query": "x"}]

    # same token, the OTHER workload's cert -> rejected, nothing executes
    b_cert, b_key, _ = mtls["B"]
    status, body = call(mtls["server"], mtls["ca"], (b_cert, b_key), token)
    assert status == 401
    assert mtls["spy"].calls == [{"query": "x"}]


def test_stolen_bound_token_without_the_key_is_useless(mtls):
    """A token exfiltrated to a machine that lacks the workload's client key cannot be used."""
    a = mtls["authority"]
    a_cert, a_key, a_der = mtls["A"]
    token = a.issue("researcher", "agent", 300, workload=WorkloadBinding(spiffe_id=SPIFFE_A, thumbprint=thumbprint_from_der(a_der)))
    # attacker presents no client cert; the server requires one, so the handshake itself fails
    # (surfaces as SSLError or a connection reset depending on platform/OpenSSL)
    with pytest.raises(OSError):
        call(mtls["server"], mtls["ca"], None, token)
    assert mtls["spy"].calls == []


def test_unbound_token_still_works_over_mtls(mtls):
    a = mtls["authority"]
    a_cert, a_key, _ = mtls["A"]
    token = a.issue("researcher", "agent", 300)  # no binding
    status, _ = call(mtls["server"], mtls["ca"], (a_cert, a_key), token)
    assert status == 200


# ---- forwarded-header path (trusted mTLS proxy in front of uvicorn) ------------------

def test_forwarded_workload_identity_from_trusted_proxy_only():
    from capgate.api import HarnessAPI

    a = TokenAuthority(Keyring.generate())
    der = b"agent-a-der"
    binding = WorkloadBinding(spiffe_id=SPIFFE_A, thumbprint=thumbprint_from_der(der))
    api = HarnessAPI(Harness(research_contract(), tools={"web.search": SpyTool()}, audit=AuditLog()), a)
    token = a.issue("researcher", "agent", 300, workload=binding)
    hdrs = {"Authorization": f"Bearer {token}"}

    # the transport builds WorkloadIdentity only for trusted peers; simulate both
    trusted = WorkloadIdentity(spiffe_id=SPIFFE_A, thumbprint=thumbprint_from_der(der), verified=True)
    ok = api.dispatch("POST", "/v1/actions", hdrs, b'{"action":"web.search","arguments":{}}', "10.0.0.9", trusted)
    assert ok.status == 200
    # no identity (as if headers came from an untrusted peer and were dropped) -> binding required
    denied = api.dispatch("POST", "/v1/actions", hdrs, b'{"action":"web.search","arguments":{}}', "1.2.3.4", None)
    assert denied.status == 401
