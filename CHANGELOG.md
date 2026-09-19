# Changelog

All notable changes are recorded here. This project has not cut a numbered
release yet; the sections below track the milestones on `main`.

## Unreleased

### Real agent-loop example
- `examples/agent_loop`: a provider-agnostic, model-driven tool-use loop whose
  tools are Capgate-authorized actions from the MCP gateway. `AnthropicModel`
  drives a real Claude model (Messages API); `ScriptedModel` replays a fixed
  plan so the demo and its tests run offline over the same loop and gateway.
  Denied calls return to the model as tool errors, escalated calls as an
  approval id, and only authorized calls reach a real tool. Tests in
  tests/integration/test_agent_loop.py.

### Multi-host state
- Shared rate limiting: `rate_limit.shared: true` moves the per-client and
  per-principal token buckets (and the auth-failure audit sampler) into the
  state store, so limits hold across replicas. On Postgres each bucket is an
  atomic per-row update — no cluster-wide lock on the hot path.
- Shared audit sink: `PostgresAuditSink` / `open_audit(url)` — every replica
  appends to one `audit` table under its own hash-chained `stream_id`; one
  queryable, tamper-evident trail, verifiable per stream. `serve` `audit:` /
  `audit_env:` accept a postgresql:// URL.
- `PostgresStateStore` and `open_state_store(url)`: choose the state backend
  by URL — `memory://`, `sqlite://`/path, or `postgresql://` for many
  replicas sharing budgets, used permits, approvals, messages and
  revocations, serialized by a cluster-wide advisory lock. `serve` accepts
  `state:` (URL or path) and `state_env:` (DSN from an env var). `postgres`
  extra adds psycopg. Docker test proves two replicas share one budget and a
  permit is single-use across replicas. See docs/state.md.
- Fix: approving an escalation now re-reads the **current** budget and runs
  the take + re-evaluate + record in one transaction, so an approval can no
  longer exceed a budget spent (possibly on another replica) after the
  escalation. Regression tests in tests/adversarial/escalation.

### Workload identity (mTLS / SPIFFE)
- Tokens can be bound to the calling workload: an RFC 8705 `cnf.x5t#S256`
  certificate thumbprint and/or a SPIFFE `wl` id, verified against the mTLS
  peer (stdlib direct-mTLS transport) or a trusted proxy's forwarded
  `X-Client-Spiffe-Id` / `X-Client-Cert-Thumbprint`. A bound token replayed
  without the workload's client cert/key is rejected; unbound tokens are
  unchanged. `capgate token issue --bind-cert/--bind-spiffe/--bind-thumbprint`.
  Runtime stays dependency-free; the `mtls` extra adds `cryptography` for the
  cert-reading tooling only. See docs/workload-identity.md.
- Reference SPIFFE-aware mTLS edge (`capgate.mtlsedge`): terminates the
  agent's mTLS, verifies the client cert, strips client-supplied identity
  headers, and forwards the verified SPIFFE id + thumbprint to the harness.
  Wired into a containerised demo (`deploy/mtls/`, `python deploy/mtls/demo.py`)
  and covered by `pytest -m docker`.

### Boundary and transport
- Production HTTP transport: the API runs under uvicorn/h11 behind an nginx edge
  (sizes, timeouts, path/method allowlist) in the reference deployment; a stdlib
  transport remains for development. One transport-independent core
  (`harness.api`) so they cannot diverge.
- Property-based fuzzing (Hypothesis) of the API, tokens, policy engine, contract
  loader, and both HTTP transports at the socket level. Fixed three crashes it
  found (unhashable action, NaN/Infinity in request JSON, non-string contract
  fields).

### MCP
- MCP gateway (`POST /mcp`): any MCP client's tool calls flow through
  authorize → permit → executor under the caller's contract. Denied/unknown
  calls are audited tool errors; escalations return an approval id.
- Upstream MCP servers can back executor tools (`type: mcp`), with credentials
  held on the harness side.
- `capgate mcp-bridge` adapts stdio-only MCP clients to `/mcp`.

### Isolation and state (earlier milestones)
- Reference isolated deployment (`deploy/`): a compromised agent reaches only the
  proxy; internal networks + iptables allowlist, secrets it cannot read, an edge
  that bounds HTTP. Attacked from inside the sandbox in CI (`pytest -m docker`).
- Persistent authority state (SQLite): budgets, used permits, approvals,
  messages, revocations survive restarts and are shared across processes on a host.
- Short-lived signed credentials with rotation and revocation; required per-contract
  step budgets; per-client and per-principal rate limiting; streaming, hash-chained
  audit trail.

### Tooling
- CI (GitHub Actions): full suite on Python 3.10–3.13 and both transports, the
  Docker isolation job, and a nightly deep-fuzz job.
- SECURITY.md (what we ask you to break), CONTRIBUTING.md, threat model.
