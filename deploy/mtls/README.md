# SPIFFE-aware mTLS edge (overlay)

Demonstrates **workload identity** end to end in containers: an agent presents a
SPIFFE client certificate over mTLS, an edge verifies it and forwards the
verified identity, and the harness enforces the token's workload binding.

```
agent ─(mTLS, SPIFFE client cert)─► mtls-edge ─(http + verified identity)─► harness ─► tools
```

```bash
python deploy/mtls/demo.py        # mint certs, build, run the client-cert agent, report, tear down
```

## What it shows

- The agent's bound token works **only** with the workload's own certificate.
- A denied action is still denied over mTLS.
- The agent cannot forge its identity: an `X-Client-Spiffe-Id` header it sends is
  stripped and overwritten by the edge from the real client cert.
- No client certificate → the TLS handshake is refused; nothing reaches the harness.
- Only authorized `web.search` calls reach the real tool (never `database.write`).

The edge (`capgate.mtlsedge`) is the offline reference terminator; in production
an Envoy/SPIRE or ghostunnel sidecar plays the same role and forwards the same
`X-Client-Spiffe-Id` / `X-Client-Cert-Thumbprint` headers. The harness trusts
those only from the edge's network (`trusted_proxies`).

Certificates are minted on the host by the demo (`cryptography`, the `mtls`
extra); in production your PKI / SPIFFE provider issues and rotates them.

This overlay focuses on the identity path. The full network and process
isolation (internal networks, iptables egress allowlist, unreadable secrets) is
in the base [../README.md](../README.md).

## Files

| File | Purpose |
|---|---|
| `docker-compose.yml` | tools, harness (uvicorn, trusts the edge net), mtls-edge, agent |
| `config/` | contract + harness config (`trusted_proxies_env`) |
| `agent/agent.py` | client-cert agent; also tries a forged header and no cert |
| `demo.py` | mints certs, issues a bound token, runs the agent, prints checks |
