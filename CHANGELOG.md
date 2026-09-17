# Changelog

All notable changes are recorded here. This project has not cut a numbered
release yet; the sections below track the milestones on `main`.

## Unreleased

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
