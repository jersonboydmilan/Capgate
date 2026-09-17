import json

import pytest

from capgate.identity import Keyring, TokenAuthority, TokenError, _b64d, _b64e
from capgate.state import MemoryStateStore


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def authority(**kw):
    return TokenAuthority(Keyring.generate(), clock=kw.pop("clock", Clock()), state=kw.pop("state", MemoryStateStore()), **kw)


def test_issue_and_verify_roundtrip():
    a = authority()
    claims = a.verify(a.issue("researcher", "agent", 600))
    assert (claims.sub, claims.role, claims.exp - claims.iat) == ("researcher", "agent", 600)


def test_expiry_and_not_before():
    clock = Clock()
    a = authority(clock=clock)
    token = a.issue("r", "agent", 60)
    clock.t += 60
    with pytest.raises(TokenError, match="TOKEN_EXPIRED"):
        a.verify(token)
    future = a.issue("r", "agent", 60, issued_at=clock.t + 3600)
    with pytest.raises(TokenError, match="TOKEN_NOT_YET_VALID"):
        a.verify(future)


def test_issuer_and_verifier_both_cap_ttl():
    a = authority(max_ttl_seconds=900)
    with pytest.raises(ValueError):
        a.issue("r", "agent", 901)
    lenient = TokenAuthority(a._keyring, max_ttl_seconds=86_400, clock=a.clock)
    with pytest.raises(TokenError, match="TOKEN_TTL_TOO_LONG"):
        a.verify(lenient.issue("r", "agent", 86_400))


@pytest.mark.parametrize("mutate", ["sub", "role", "exp", "jti"])
def test_any_payload_change_breaks_signature(mutate):
    a = authority()
    prefix, kid, body, sig = a.issue("r", "agent", 600).split(".")
    claims = json.loads(_b64d(body))
    claims[mutate] = {"sub": "admin", "role": "approver", "exp": claims["exp"] + 10**6, "jti": "x"}[mutate]
    with pytest.raises(TokenError, match="TOKEN_BAD_SIGNATURE"):
        a.verify(f"{prefix}.{kid}.{_b64e(json.dumps(claims).encode())}.{sig}")


@pytest.mark.parametrize("token", ["", "garbage", "ah1.k.a.b.c", "Bearer x", "ah2.k.e30.sig", "ah1..e30."])
def test_malformed_tokens(token):
    with pytest.raises(TokenError):
        authority().verify(token)


def test_revocation():
    a = authority()
    token = a.issue("r", "agent", 600)
    a.revoke(token)
    with pytest.raises(TokenError, match="TOKEN_REVOKED"):
        a.verify(token)


def test_keys_from_another_keyring_are_rejected():
    with pytest.raises(TokenError, match="TOKEN_UNKNOWN_KEY|TOKEN_BAD_SIGNATURE"):
        authority().verify(authority().issue("r", "agent", 60))


def test_keyring_rules(tmp_path):
    k = Keyring.generate()
    first = k.active
    with pytest.raises(ValueError):
        k.retire(first)
    second = k.rotate()
    k.retire(first)
    assert list(k.keys) == [second]
    path = tmp_path / "keys.json"
    k.save(path)
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert Keyring.load(path).active == second
    with pytest.raises(ValueError):
        Keyring({"short": b"x" * 8}, "short")
