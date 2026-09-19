"""Workload identity: bind a token to the calling workload.

A bearer token, on its own, is a secret anyone who holds it can replay. This
module lets a token be *bound* to the workload it was issued for, so a leaked
token is useless without that workload's client certificate and private key.

Two, independent, both optional bindings on a token:

  * ``cnf["x5t#S256"]`` — the base64url SHA-256 of the client certificate's DER
    (RFC 8705, OAuth 2.0 mutual-TLS certificate-bound access tokens). Proof of
    possession of the cert's private key comes from the mTLS handshake.
  * ``wl`` — a SPIFFE ID (``spiffe://trust-domain/path``) taken from the client
    certificate's URI SAN, the workload's stable name.

The harness core never parses certificates or terminates TLS. A *transport*
does that — either by terminating mTLS itself (the stdlib server, via
``ssl``) or by trusting an mTLS-terminating proxy's forwarded, verified
identity headers — and hands the core a `WorkloadIdentity`. The core only
compares strings, so it needs no crypto library at runtime.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

# SPIFFE: trust domain is a DNS-like name; path is one or more /-separated segments.
_TRUST_DOMAIN = re.compile(r"^[a-z0-9._-]{1,255}$")
_PATH_SEGMENT = re.compile(r"^[A-Za-z0-9._-]+$")
CONFIRMATION_KEY = "x5t#S256"


class WorkloadError(ValueError):
    pass


@dataclass(frozen=True)
class SpiffeId:
    trust_domain: str
    path: str  # begins with "/", or "" for a bare trust-domain id

    def __str__(self) -> str:
        return f"spiffe://{self.trust_domain}{self.path}"

    def in_trust_domain(self, trust_domain: str) -> bool:
        return self.trust_domain == trust_domain


def parse_spiffe_id(value: str) -> SpiffeId:
    if not isinstance(value, str) or not value.startswith("spiffe://"):
        raise WorkloadError(f"not a SPIFFE ID: {value!r}")
    rest = value[len("spiffe://"):]
    if len(value) > 2048 or "#" in value or "?" in value:
        raise WorkloadError(f"invalid SPIFFE ID: {value!r}")
    domain, slash, path = rest.partition("/")
    if not _TRUST_DOMAIN.match(domain):
        raise WorkloadError(f"invalid SPIFFE trust domain: {domain!r}")
    if slash:
        segments = path.split("/")
        if any(not _PATH_SEGMENT.match(seg) or seg in (".", "..") for seg in segments):
            raise WorkloadError(f"invalid SPIFFE path in {value!r}")
        return SpiffeId(domain, "/" + path)
    return SpiffeId(domain, "")


def thumbprint_from_der(der: bytes) -> str:
    """RFC 8705 x5t#S256: base64url(SHA-256(DER cert)), no padding."""
    return base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode()


def spiffe_id_from_san_uris(uris: Iterable[str]) -> str | None:
    """Return the single SPIFFE URI SAN, or None. More than one is an error (ambiguous identity)."""
    spiffe = [u for u in uris if isinstance(u, str) and u.startswith("spiffe://")]
    if not spiffe:
        return None
    if len(spiffe) > 1:
        raise WorkloadError(f"certificate presents multiple SPIFFE IDs: {spiffe}")
    parse_spiffe_id(spiffe[0])  # validate
    return spiffe[0]


def san_uris_from_peercert(peercert: Mapping[str, Any] | None) -> list[str]:
    """Extract URI SANs from ssl.getpeercert() dict form."""
    if not peercert:
        return []
    return [value for kind, value in peercert.get("subjectAltName", ()) if kind == "URI"]


@dataclass(frozen=True)
class WorkloadIdentity:
    """A verified peer identity handed to the core by a transport.

    `verified` is True only when a transport actually authenticated it (an mTLS
    handshake it terminated, or a trusted proxy's forwarded headers). An
    unverified/empty identity never satisfies a token binding.
    """

    spiffe_id: str | None = None
    thumbprint: str | None = None
    verified: bool = False

    @property
    def present(self) -> bool:
        return self.verified and (self.spiffe_id is not None or self.thumbprint is not None)

    @classmethod
    def from_peercert(cls, peercert: Mapping[str, Any] | None, der: bytes | None) -> "WorkloadIdentity":
        if not der:
            return cls()
        spiffe = spiffe_id_from_san_uris(san_uris_from_peercert(peercert))
        return cls(spiffe_id=spiffe, thumbprint=thumbprint_from_der(der), verified=True)


@dataclass(frozen=True)
class WorkloadBinding:
    """What to stamp into a token so only this workload can use it."""

    spiffe_id: str | None = None
    thumbprint: str | None = None

    def __post_init__(self) -> None:
        if self.spiffe_id is None and self.thumbprint is None:
            raise WorkloadError("a workload binding needs a SPIFFE ID, a certificate thumbprint, or both")
        if self.spiffe_id is not None:
            parse_spiffe_id(self.spiffe_id)
        if self.thumbprint is not None and (not isinstance(self.thumbprint, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", self.thumbprint)):
            raise WorkloadError("thumbprint must be a base64url SHA-256 (43 chars, no padding)")

    @classmethod
    def from_cert_der(cls, der: bytes, *, include_spiffe: bool = True) -> "WorkloadBinding":
        spiffe = spiffe_id_from_san_uris(san_uris_from_peercert(_peercert_from_der(der))) if include_spiffe else None
        return cls(spiffe_id=spiffe, thumbprint=thumbprint_from_der(der))

    def claims(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.thumbprint is not None:
            out["cnf"] = {CONFIRMATION_KEY: self.thumbprint}
        if self.spiffe_id is not None:
            out["wl"] = self.spiffe_id
        return out


def binding_from_claims(payload: Mapping[str, Any]) -> WorkloadBinding | None:
    cnf = payload.get("cnf")
    thumbprint = cnf.get(CONFIRMATION_KEY) if isinstance(cnf, Mapping) else None
    spiffe = payload.get("wl")
    if thumbprint is None and spiffe is None:
        return None
    return WorkloadBinding(spiffe_id=spiffe if isinstance(spiffe, str) else None,
                           thumbprint=thumbprint if isinstance(thumbprint, str) else None)


def check_binding(binding: WorkloadBinding, presented: WorkloadIdentity | None) -> str | None:
    """Return a failure reason, or None if the presented identity satisfies the binding."""
    if presented is None or not presented.present:
        return "TOKEN_BINDING_REQUIRED"
    if binding.thumbprint is not None and binding.thumbprint != presented.thumbprint:
        return "TOKEN_BINDING_MISMATCH"
    if binding.spiffe_id is not None and binding.spiffe_id != presented.spiffe_id:
        return "TOKEN_BINDING_MISMATCH"
    return None


def _peercert_from_der(der: bytes) -> dict[str, Any]:
    """Best-effort SAN extraction from a DER cert. Uses `cryptography` if present, else empty SANs."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID
    except ImportError:  # pragma: no cover - core runtime has no cryptography
        return {}
    cert = x509.load_der_x509_certificate(der)
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.ExtensionNotFound:
        return {}
    from cryptography.x509 import UniformResourceIdentifier

    return {"subjectAltName": tuple(("URI", u) for u in san.get_values_for_type(UniformResourceIdentifier))}
