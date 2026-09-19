# Roadmap

Capgate is a **research preview**. The core — contract, proposal, deterministic
decision, enforced execution, audit — works end to end, holds under the tested
attacks (including a compromised agent inside the containerised deployment), and
runs in CI on every push. It is deliberately **not** called production-grade
yet; the items below are what stand between here and that claim, in priority
order. See [docs/threat-model.md](threat-model.md) for exactly what is and is
not enforced today.

## Done

- Deny-by-default policy engine; non-transitive delegation; tamper-evident,
  hash-chained audit.
- Short-lived signed credentials (rotation, revocation); required per-contract
  budgets; per-client and per-principal rate limiting.
- Reference isolated deployment: internal networks + iptables egress allowlist,
  secrets the agent cannot read, an nginx edge in front of uvicorn. Attacked
  from inside the agent sandbox in CI.
- Persistent authority state (SQLite): survives restarts, shared across
  processes on one host.
- MCP gateway (`/mcp`) and upstream MCP tools, exercised with the official SDK.
- Property-based fuzzing of the API, policy engine and both HTTP transports.
- **Multi-host state** on PostgreSQL: budgets, used permits, approvals,
  messages and revocations shared across replicas, serialized by a
  cluster-wide advisory lock. See [state.md](state.md).
- **Workload identity**: tokens bindable to a workload (RFC 8705 cert
  thumbprint + SPIFFE ID), enforced over direct mTLS or a trusted proxy's
  forwarded identity, with a reference SPIFFE-aware mTLS edge (`capgate.mtlsedge`)
  wired into the containerised demo. See [workload-identity.md](workload-identity.md).

## Next

1. **Shared rate limits and audit sink.** Multi-host *state* is done (Postgres);
   the token-bucket rate limiter and the audit trail are still per replica.
   Add a shared limiter for a hard cluster-wide cap and a common audit sink.
2. **Stronger isolation runtime.** A tested gVisor / Kata / Firecracker option,
   and a Kubernetes deployment (NetworkPolicy egress-only-to-harness, secrets
   not mounted into the agent pod, locked-down `securityContext`) with the same
   adversarial tests the Docker deployment has.
3. **Outside security review.** CI and [SECURITY.md](../SECURITY.md) invite it;
   it has not happened yet. Every "the boundary holds" claim so far rests on
   tests the authors wrote. This is the single most important open item for
   credibility — see [SECURITY.md](../SECURITY.md) for the exact claims to break.
4. **More real integrations.** One first-class end-to-end example with an actual
   LLM agent loop (not a scripted client) going through the gateway.

## Explicit non-goals

Capgate stays infrastructure under an existing stack. It will not grow into an
orchestration layer, an agent framework, a prompt/DSL system, a bundled model
provider, vector store, or observability platform. Keeping the surface small is
a feature.
