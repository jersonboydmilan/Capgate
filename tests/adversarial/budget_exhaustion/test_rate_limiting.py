"""Floods against the HTTP boundary: per-principal and per-client limits, bounded audit growth."""

import json
import socket
import urllib.error
import urllib.request

import pytest

from capgate import AuditLog, Harness
from capgate.identity import Keyring, TokenAuthority
from capgate.ratelimit import RateLimitConfig, TokenBucket
from capgate.server import HarnessServer
from helpers import SpyTool, delegation_contracts


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def test_token_bucket_refills_and_evicts():
    clock = Clock()
    bucket = TokenBucket(rate=2, burst=3, max_keys=2, clock=clock)
    assert [bucket.take("a")[0] for _ in range(4)] == [True, True, True, False]
    allowed, retry = bucket.take("a")
    assert not allowed and 0 < retry <= 0.5
    clock.t += 0.5
    assert bucket.take("a")[0]
    bucket.take("b"); bucket.take("c")  # "a" is least recently used and evicted
    assert len(bucket._buckets) == 2 and "a" not in bucket._buckets


def post(url, token, body):
    req = urllib.request.Request(url + "/v1/actions", data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}


@pytest.fixture
def stack():
    harness = Harness(delegation_contracts(), tools={"web.search": SpyTool()}, audit=AuditLog())
    authority = TokenAuthority(Keyring.generate())
    config = RateLimitConfig(client_rate=1000, client_burst=1000, principal_rate=0.5, principal_burst=5, auth_failure_audit_per_minute=3)
    server = HarnessServer(harness, authority, rate_limit=config).start()
    yield server, harness, authority
    server.stop()


def test_flooding_principal_is_throttled_without_starving_others(stack):
    server, harness, authority = stack
    a = authority.issue("agent-a", "agent", 60)
    b = authority.issue("agent-b", "agent", 60)
    statuses = [post(server.url, a, {"action": "web.search", "arguments": {"q": i}})[0] for i in range(12)]
    assert statuses[:5] == [200] * 5 and set(statuses[5:]) == {429}
    status, headers = post(server.url, a, {"action": "web.search", "arguments": {}})
    assert status == 429 and int(headers["retry-after"]) >= 1
    assert post(server.url, b, {"action": "web.search", "arguments": {}})[0] == 200  # other agents unaffected

    decisions = harness.audit.query(event="decision", agent_id="agent-a")
    assert len(decisions) == 5  # throttled requests never reached policy or spent budget
    limited = harness.audit.query(event="rate_limited")
    assert 1 <= len(limited) <= 3 and limited[0]["principal"] == "agent-a"


def test_unauthenticated_flood_does_not_grow_the_audit_trail(stack):
    server, harness, _ = stack
    for _ in range(200):
        assert post(server.url, "garbage", {"action": "web.search"})[0] == 401
    failures = harness.audit.query(event="authentication_failed")
    assert len(failures) == 3  # sampled, not 200


def test_suppressed_failures_are_counted_in_the_next_record():
    clock = Clock()
    from capgate.ratelimit import AuditSampler

    sampler = AuditSampler(per_minute=2, max_keys=100, clock=clock)
    assert [sampler.admit("ip") for _ in range(5)] == [(True, 0), (True, 0), (False, 0), (False, 0), (False, 0)]
    clock.t += 30
    assert sampler.admit("ip") == (True, 3)  # evidence of the flood is preserved


def test_client_limit_applies_before_token_verification():
    harness = Harness(delegation_contracts(), audit=AuditLog())
    authority = TokenAuthority(Keyring.generate())
    verified = []
    original = authority.verify
    authority.verify = lambda token: verified.append(token) or original(token)
    server = HarnessServer(harness, authority, rate_limit=RateLimitConfig(client_rate=0.1, client_burst=4)).start()
    try:
        statuses = [post(server.url, "x", {})[0] for _ in range(10)]
        assert statuses[:4] == [401] * 4 and set(statuses[4:]) == {429}
        assert len(verified) == 4  # no signature work for throttled clients
    finally:
        server.stop()


def test_rate_limit_config_rejects_unknown_fields():
    with pytest.raises(ValueError):
        RateLimitConfig.from_mapping({"requests_per_second": 5})
