"""Short-lived, rotatable, revocable credentials for the HTTP boundary.

Token format (all parts base64url, no padding):

    ah1.<kid>.<payload>.<signature>
    payload   = {"sub": principal, "role": "agent"|"approver", "iat": int, "exp": int, "jti": str}
    signature = HMAC-SHA256(key[kid], "ah1.<kid>.<payload>")

* **Short-lived.** Every token expires; the verifier rejects any token whose
  lifetime (exp - iat) exceeds `max_ttl_seconds`, whatever the issuer asked for.
* **Rotatable.** A keyring holds several keys; new tokens use the active key,
  existing tokens stay valid until their key is retired. The server reloads the
  keyring file when it changes, so rotation needs no restart.
* **Revocable.** `jti`s can be revoked in the state store until they expire.

Tokens are issued by the operator or the agent supervisor — never by the
harness to an agent that asks, so a stolen token cannot renew itself.
"""

from __future__ import annotations

import base64
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from .workload import WorkloadBinding, WorkloadIdentity, binding_from_claims, check_binding
from typing import Any, Callable

PREFIX = "ah1"
ROLES = ("agent", "approver")


class TokenError(PermissionError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(text: str) -> bytes:
    if not text or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in text):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@dataclass(frozen=True)
class Claims:
    sub: str
    role: str
    iat: int
    exp: int
    jti: str
    kid: str
    binding: WorkloadBinding | None = None  # set when the token is bound to a workload

    @property
    def bound(self) -> bool:
        return self.binding is not None


class Keyring:
    """{"active": kid, "keys": {kid: base64url-key}} stored as JSON."""

    def __init__(self, keys: dict[str, bytes], active: str) -> None:
        if active not in keys:
            raise ValueError("active key is not in the keyring")
        if any(len(k) < 32 for k in keys.values()):
            raise ValueError("token keys must be at least 32 bytes")
        self.keys = dict(keys)
        self.active = active

    @classmethod
    def generate(cls) -> "Keyring":
        kid = _new_kid()
        return cls({kid: secrets.token_bytes(32)}, kid)

    @classmethod
    def load(cls, path: str | Path) -> "Keyring":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls({kid: _b64d(value) for kid, value in data["keys"].items()}, data["active"])

    def to_json(self) -> str:
        return json.dumps({"active": self.active, "keys": {k: _b64e(v) for k, v in self.keys.items()}}, indent=2)

    def save(self, path: str | Path) -> None:
        path = Path(path)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(self.to_json(), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)  # atomic: a reloading server never sees a partial file

    def rotate(self) -> str:
        kid = _new_kid()
        self.keys[kid] = secrets.token_bytes(32)
        self.active = kid
        return kid

    def retire(self, kid: str) -> None:
        if kid == self.active:
            raise ValueError("cannot retire the active key; rotate first")
        if kid not in self.keys:
            raise ValueError(f"unknown key {kid!r}")
        del self.keys[kid]


def _new_kid() -> str:
    return time.strftime("k%Y%m%d") + "-" + secrets.token_hex(3)


class TokenAuthority:
    def __init__(
        self,
        keyring: Keyring | str | Path,
        *,
        max_ttl_seconds: int = 3600,
        leeway_seconds: int = 30,
        clock: Callable[[], float] = time.time,
        state: Any = None,
    ) -> None:
        self._path = None if isinstance(keyring, Keyring) else Path(keyring)
        self._keyring = keyring if isinstance(keyring, Keyring) else Keyring.load(keyring)
        self._stamp = self._file_stamp()
        self.max_ttl = max_ttl_seconds
        self.leeway = leeway_seconds
        self.clock = clock
        self.state = state
        self._lock = threading.Lock()

    # -- keyring hot reload -------------------------------------------------------

    def _file_stamp(self) -> tuple[int, int] | None:
        if self._path is None:
            return None
        st = self._path.stat()
        return (st.st_mtime_ns, st.st_size)

    def _current_keyring(self) -> Keyring:
        if self._path is not None:
            stamp = self._file_stamp()
            if stamp != self._stamp:
                with self._lock:
                    self._keyring = Keyring.load(self._path)  # a broken file raises: fail closed
                    self._stamp = stamp
        return self._keyring

    # -- issue / verify -------------------------------------------------------------

    def issue(self, sub: str, role: str, ttl_seconds: int, *, issued_at: float | None = None,
              workload: WorkloadBinding | None = None) -> str:
        if role not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")
        if not 0 < ttl_seconds <= self.max_ttl:
            raise ValueError(f"ttl must be between 1 and {self.max_ttl} seconds")
        keyring = self._current_keyring()
        iat = int(self.clock() if issued_at is None else issued_at)
        payload = {"sub": sub, "role": role, "iat": iat, "exp": iat + int(ttl_seconds), "jti": secrets.token_hex(12)}
        if workload is not None:
            payload.update(workload.claims())  # cnf / wl are covered by the signature
        body = _b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
        signing_input = f"{PREFIX}.{keyring.active}.{body}"
        signature = _b64e(hmac.new(keyring.keys[keyring.active], signing_input.encode(), sha256).digest())
        return f"{signing_input}.{signature}"

    def verify(self, token: str, *, workload: WorkloadIdentity | None = None) -> Claims:
        parts = token.split(".") if isinstance(token, str) else []
        if len(parts) != 4 or parts[0] != PREFIX:
            raise TokenError("TOKEN_MALFORMED")
        _, kid, body, signature = parts
        key = self._current_keyring().keys.get(kid)
        if key is None:
            raise TokenError("TOKEN_UNKNOWN_KEY")
        try:
            given = _b64d(signature)
        except ValueError:
            raise TokenError("TOKEN_BAD_SIGNATURE") from None
        expected = hmac.new(key, f"{PREFIX}.{kid}.{body}".encode(), sha256).digest()
        if not hmac.compare_digest(given, expected):
            raise TokenError("TOKEN_BAD_SIGNATURE")
        try:
            payload = json.loads(_b64d(body))
            binding = binding_from_claims(payload)
            claims = Claims(str(payload["sub"]), str(payload["role"]), int(payload["iat"]), int(payload["exp"]), str(payload["jti"]), kid, binding)
        except (ValueError, KeyError, TypeError):
            raise TokenError("TOKEN_MALFORMED") from None
        now = self.clock()
        if claims.role not in ROLES:
            raise TokenError("TOKEN_MALFORMED")
        if claims.iat > now + self.leeway:
            raise TokenError("TOKEN_NOT_YET_VALID")
        if claims.exp <= now:
            raise TokenError("TOKEN_EXPIRED")
        if claims.exp - claims.iat > self.max_ttl:
            raise TokenError("TOKEN_TTL_TOO_LONG")
        if self.state is not None and self.state.is_revoked(claims.jti):
            raise TokenError("TOKEN_REVOKED")
        if claims.binding is not None:
            reason = check_binding(claims.binding, workload)
            if reason is not None:
                raise TokenError(reason)  # token is bound; the presented workload must match
        return claims

    def revoke(self, token: str) -> Claims:
        """Revoke a currently valid token until it would have expired anyway."""
        if self.state is None:
            raise ValueError("revocation requires a state store")
        claims = self.verify(token)
        self.state.revoke(claims.jti, float(claims.exp))
        return claims
