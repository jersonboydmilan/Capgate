# Workload identity (mTLS / SPIFFE)

A bearer token is a secret: whoever holds it can use it. Capgate lets a token be
**bound to the workload it was issued for**, so a leaked or exfiltrated token is
useless without that workload's client certificate and private key.

## The binding

`capgate token issue` can stamp two independent, optional claims into a token:

| Claim | Meaning | Standard |
|---|---|---|
| `cnf.x5t#S256` | base64url SHA-256 of the client cert's DER | RFC 8705 (OAuth 2.0 mutual-TLS certificate-bound tokens) |
| `wl` | a SPIFFE ID (`spiffe://trust-domain/path`) from the cert's URI SAN | SPIFFE |

Both are covered by the token signature. On every request the harness compares
them against the **verified** identity of the workload that presented the token:

- no verified client identity → `TOKEN_BINDING_REQUIRED`;
- thumbprint or SPIFFE ID doesn't match → `TOKEN_BINDING_MISMATCH`.

Possession of the private key is proven by the mTLS handshake, not by anything
in the token — so the token alone, replayed from another machine, fails.
Tokens issued **without** a binding keep working unchanged (opt-in).

```bash
capgate token issue --keyring keys.json --sub researcher --role agent --ttl 15m \
  --bind-cert /run/spiffe/agent.pem        # derive thumbprint + SPIFFE ID from the cert (needs the `mtls` extra)
# or bind explicitly, with no cert on the issuer:
capgate token issue ... --bind-spiffe spiffe://example.org/agent/researcher --bind-thumbprint <x5t#S256>
```

## Where the verified identity comes from

The harness core never parses certificates or terminates TLS. A transport does,
and hands the core a verified `WorkloadIdentity`:

1. **Direct mTLS (stdlib transport).** Configure `TLSConfig(cert, key,
   client_ca=…)`. The stdlib `ssl` module verifies the client chain against the
   CA, and the harness reads the peer's SPIFFE URI SAN and computes the SHA-256
   thumbprint from the peer cert — no third-party library. This is the simplest
   zero-proxy deployment and is what the end-to-end tests exercise.

2. **A trusted mTLS proxy (uvicorn/production).** An mTLS-terminating,
   SPIFFE-aware edge (Envoy, a SPIRE agent, Ghostunnel, …) verifies the client
   cert and forwards the verified identity:

   ```
   X-Client-Spiffe-Id:       spiffe://example.org/agent/researcher
   X-Client-Cert-Thumbprint: <base64url SHA-256 of the client cert DER>
   ```

   Capgate believes these headers **only** from a peer in `trusted_proxies`
   (the same CIDR gate as `X-Real-IP`); from any other source they are ignored,
   so a client cannot forge its own workload identity. This is the integration
   point for a SPIRE/Envoy mesh.

## Threat covered, and not

- **Covered:** a stolen bound token used from a host without the workload's
  client key — the mTLS handshake fails, or the forwarded identity does not
  match, and nothing executes.
- **Not covered:** an attacker who also steals the workload's private key, or
  who runs code inside the workload's own process/container (there the isolated
  deployment's process boundary is the relevant control). Certificate issuance
  and rotation are delegated to your PKI / SPIFFE provider; Capgate consumes the
  identity, it does not mint workload certs.

See `tests/integration/test_workload_identity.py` for the enforced behaviour,
including real mTLS with minted SPIFFE certificates.
