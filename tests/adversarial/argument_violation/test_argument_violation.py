"""Test B (policy): arguments are checked against capability constraints."""

import pytest

from harness import ReasonCode
from helpers import SpyTool, make_harness


@pytest.mark.parametrize(
    "url, reason",
    [
        ("https://internal.example/admin", ReasonCode.DOMAIN_NOT_ALLOWED),
        ("https://api.internal.example/", ReasonCode.DOMAIN_NOT_ALLOWED),
        ("http://localhost:8080/", ReasonCode.DOMAIN_NOT_ALLOWED),
        ("http://127.0.0.1/", ReasonCode.DOMAIN_NOT_ALLOWED),
        ("http://2130706433/", ReasonCode.DOMAIN_NOT_ALLOWED),
        ("http://[::1]/", ReasonCode.DOMAIN_NOT_ALLOWED),
        ("http://169.254.169.254/latest/meta-data/", ReasonCode.DOMAIN_NOT_ALLOWED),
        ("http://10.1.2.3/", ReasonCode.DOMAIN_NOT_ALLOWED),
        ("http://db/", ReasonCode.DOMAIN_NOT_ALLOWED),
        ("http://metadata.google.internal/", ReasonCode.DOMAIN_NOT_ALLOWED),
        ("https://public.example.com@internal.example/", ReasonCode.DOMAIN_NOT_ALLOWED),
        ("file:///etc/passwd", ReasonCode.DOMAIN_NOT_ALLOWED),
        ("javascript:alert(1)", ReasonCode.DOMAIN_NOT_ALLOWED),
    ],
)
def test_B_fetch_to_internal_hosts_denied(url, reason):
    spy = SpyTool()
    harness = make_harness(tools={"web.fetch": spy})
    result = harness.authorize(agent="researcher", action="web.fetch", arguments={"url": url})
    assert result.denied, url
    assert result.reason_code is reason
    assert spy.calls == []


def test_public_fetch_allowed():
    result = make_harness().authorize(agent="researcher", action="web.fetch", arguments={"url": "https://arxiv.org/abs/1"})
    assert result.allowed


def test_smuggled_extra_argument_denied():
    result = make_harness().authorize(
        agent="researcher", action="web.fetch",
        arguments={"url": "https://arxiv.org/", "headers": {"Authorization": "Bearer stolen"}},
    )
    assert result.reason_code is ReasonCode.ARGUMENT_NOT_ALLOWED


def test_arguments_cannot_be_swapped_after_authorization():
    """TOCTOU: the grant binds the exact argument hash."""
    from harness import ActionRequest, ExecutionRefused

    spy = SpyTool()
    harness = make_harness(tools={"web.fetch": spy})
    result = harness.authorize(agent="researcher", action="web.fetch", arguments={"url": "https://arxiv.org/"})
    evil = ActionRequest("researcher", "web.fetch", {"url": "http://169.254.169.254/"})
    with pytest.raises(ExecutionRefused) as refused:
        harness.execute_grant(result.grant, evil)
    assert refused.value.reason == "GRANT_ARGUMENTS_MISMATCH"
    assert spy.calls == []
