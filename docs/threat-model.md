# Threat model

## Assets

- **Consequential systems** reached by tools: databases, APIs, infrastructure,
  money, messages to people.
- **Tool credentials**, held by the executor.
- **The grant signing key**, held by the harness process.
- **Contracts** and their binding to agents.
- **The audit trail.**

## Adversary

An agent that is buggy, prompt-injected, or fully compromised. Assume it runs
arbitrary code inside its own process, knows the harness API and the address
of every tool endpoint, can message other agents, and will obey any
instruction it receives from another agent.

Out of scope: a compromised harness host, compromised approvers, or a
malicious contract author.

## Trust boundaries

```
┌────────────── untrusted ──────────────┐     ┌──────────────── trusted ────────────────┐
│ agent process                         │     │ harness process                          │
│   - its own bearer token              │────►│   interceptor → policy → executor        │
│   - no tool credentials               │HTTP │   - grant signing key                    │
│   - no signing key                    │     │   - tool credentials                     │
└───────────────────────────────────────┘     │   - audit log                            │
            │                                  └───────────────┬─────────────────────────┘
            │ direct call (no credential)                      │ Bearer <tool credential>
            ▼                                                  ▼
      ┌──────────────────── tool endpoint (requires the executor's credential) ─────────┐
      └─────────────────────────────────────────────────────────────────────────────────┘
```

## What is enforced today, and how it is tested

| Attack | Control | Status | Test |
|---|---|---|---|
| Propose an action the contract doesn't grant | Deny-by-default policy | Enforced | `adversarial/unauthorized_tool` |
| Smuggle arguments, hit internal hosts | Capability constraints; connect-time address checks with IP pinning in `HttpFetchTool` | Enforced | `adversarial/argument_violation` |
| Execute a denied/escalated action anyway | Signed, single-use, argument-bound grants | Enforced | `adversarial/unauthorized_tool`, `adversarial/bypass_attempt` |
| Swap arguments after authorization | Grant binds argument hash | Enforced | `adversarial/argument_violation` |
| Forge or replay a grant | HMAC signature, single use, expiry | Enforced | `adversarial/scope_expansion`, `bypass_attempt` |
| Call the tool endpoint directly | Network: agent can reach only `harness:8700`. Credentials: held only by executor | Enforced in the reference isolated runtime; credential layer enforced in any separate-process deployment | `adversarial/isolation/`, `bypass/test_process_boundary.py` |
| Open any other socket (internet, host, other containers, raw packets) | Internal networks, iptables allowlist, no capabilities | Enforced in the reference isolated runtime | `adversarial/isolation/` |
| Read harness secrets (tool credential, signing key, tokens) | Secrets mounted only into harness/tools; separate PID namespace; read-only FS | Enforced in the reference isolated runtime | `adversarial/isolation/` (full filesystem, env and `/proc` scan) |
| Impersonate another agent over HTTP | Identity from verified signed token; body identity ignored | Enforced | `bypass`, `adversarial/isolation/` |
| Forge, tamper with, extend or reuse a credential | HMAC-signed claims, verifier TTL cap, expiry, revocation, key rotation | Enforced | `unit/test_identity.py`, `bypass`, `adversarial/isolation/` (`CRED` checks) |
| Pick a more permissive contract | Server-side binding | Enforced | `adversarial/scope_expansion` |
| Edit the contract or grant itself capabilities | Frozen contracts, reserved namespaces | Enforced | `adversarial/contract_tampering`, `scope_expansion` |
| Get another agent to act for it | Non-transitive delegation, messages carry no authority | Enforced | `adversarial/delegation`, `message_injection` |
| Approve its own escalation | Approvers are distinct principals, per contract | Enforced | `adversarial/escalation`, `bypass` |
| Exhaust budgets or flood messages | `max_steps` is required on every contract and counts every proposal; `max_calls` | Enforced | `adversarial/budget_exhaustion` |
| Flood the HTTP boundary (starve other agents, fill the audit trail, hold threads) | Per-client limit before token verification, per-principal limit, sampled auth-failure audit with suppressed counts, 10s socket timeout, strict `Content-Length` | Enforced (per process) | `adversarial/budget_exhaustion/test_rate_limiting.py`, `integration/test_http_sdk.py` |
| Reset budgets or replay grants by forcing a restart | Persistent state store; stable signing key | Enforced with `state:` configured | `integration/test_persistence.py` |
| Use a capability after its window | Contract and capability expiry, rechecked on approval | Enforced | `adversarial/capability_expiration` |
| Erase or rewrite evidence | Hash-chained audit, fail-closed writes | Detects tampering; does not prevent deleting the whole file | `adversarial/audit`, `unit/test_audit.py` |

## Deployment requirements for the boundary to hold

The code enforces the checks above. For **"the agent cannot route around the
harness"** to be true, the deployment must also ensure:

1. **Separate principal.** The agent runs in a different container, VM, or at
   minimum a different OS user than the harness, so it cannot read the harness's
   memory, environment, or files (tool credentials, signing key, audit log).
2. **No credentials in the agent's environment.** Start agents with an explicit,
   minimal environment. `tests/bypass` does this and checks it.
3. **Tools require the executor's credential.** Every consequential endpoint
   must reject requests without it. Tools that authenticate by network location
   alone (for example, an internal service reachable without auth) are not
   protected by this design unless (4) holds.
4. **Egress restricted to the harness.** The agent's network should permit only
   the harness address. This is what protects unauthenticated internal services
   and the open internet. The reference deployment in `deploy/` implements
   this with internal Docker networks plus an iptables allowlist and tests it
   from inside the agent sandbox (`pytest -m docker`); other deployments must
   reproduce it.

A single-process setup (`Harness` used in-process with an agent in the same
Python interpreter) is a **cooperative** integration: useful for simulation,
testing and trusted orchestrators, not a security boundary against a
compromised agent.

## Reference isolated deployment

`deploy/docker-compose.yml` is the deployment these guarantees are tested against
(`pytest -m docker`, `python deploy/demo.py`). Coverage, precisely:

| Property | Mechanism | Covered |
|---|---|---|
| HTTP parsing and slow-client attacks | nginx edge (timeouts, sizes, path/method allowlist) in front of uvicorn/h11; both transports fuzzed with Hypothesis | Yes — `EDGE` checks, `tests/fuzz` (smuggling, oversized, random and mutated bytes) |
| Agent sockets reach only `proxy:8080` | `internal` networks (no gateway) + netguard iptables allowlist (OUTPUT policy DROP) in the agent's namespace; agent has no `NET_ADMIN` | Yes — every other destination probed (tool by name/IP, misattached tool on the agent network, other harness ports, IPv4/IPv6 internet, external DNS, UDP, host gateway, Docker bridge, raw sockets) |
| Each network layer holds on its own | Topology blocks unrouted targets; iptables blocks a reachable misattached tool | Yes — mutation with iptables disabled makes the misattached-tool check fail |
| Agent cannot read harness secrets | Secrets in volumes not mounted into the agent; separate PID namespace; no Docker socket | Yes — path probes plus a full readable-filesystem, environment and `/proc` scan with a positive control |
| Agent credential is short-lived and unforgeable | Signed tokens, 15-minute issuance, verifier TTL cap, revocation | Yes — 9 credential attacks |
| Agent process is unprivileged and immutable | `cap_drop: ALL`, `no-new-privileges`, non-root, read-only root fs, pids limit | Yes |
| Side effects only via authorize → permit → executor | Tool service requires the executor-only credential; ledger as ground truth | Yes — ledger, decoy ledger, audit correlation, harness log |
| Kernel / runtime escape | — | **No.** Use gVisor or a microVM runtime |
| Compromised Docker host or daemon access | — | **No.** The host is trusted |
| Harness process compromise via its own API bugs | Narrow API, strict parsing, fail-closed errors | **Partially** — tested behaviour only |
| Multi-host / Kubernetes deployments | — | **No.** Equivalent controls described in `deploy/README.md`, untested |

## Known limits

- **URL checks happen at two layers.** Policy (pure, no DNS) rejects private and
  internal names, every non-canonical IP spelling (`127.1`, `0x7f.1`,
  `2130706433`), IPv4-mapped/6to4/Teredo wrappers of private addresses,
  embedded credentials, backslashes, whitespace, control characters and
  non-ASCII hostnames. `HttpFetchTool` then resolves once, refuses if *any*
  answer is non-public, connects to the vetted address (defeating DNS
  rebinding), restricts ports, and returns redirects instead of following them,
  so each hop is a new proposal. Other tools that open connections must do the
  same; a hostname that is public at policy time and private at connect time is
  only caught by the tool.
- **Message content is not inspected.** By design, messages carry no authority,
  so content filtering is unnecessary for authorization. It is not a defence
  against a recipient being manipulated into *authorized* but unwise actions;
  narrow the recipient's contract for that.
- **State is per host.** With `state: state.db` (SQLite), budgets, call limits,
  used grants, pending/decided approvals, undelivered messages and revoked
  credentials survive restarts, and harness processes on the same host sharing
  the file make consistent decisions (read–evaluate–increment runs under a
  database write lock). Without `state:`, state is in memory. There is no
  multi-host replication. Grants survive a restart only with a stable
  `signing_key_file`.
- **Rate limits are per process and in memory.** Per-client and per-principal
  token buckets, plus sampled auditing of failed authentication, bound request
  floods and audit growth for one harness process. Several replicas each apply
  their own limits; a shared limiter is not implemented.
- **Audit tamper-evidence is local.** The hash chain detects edits within the
  file. Ship records to append-only storage to protect against deletion.
- **Tokens are bearer tokens.** They are short-lived (verifier-capped TTL),
  signed, rotatable without restart and revocable, but whoever holds a valid
  token can use it until it expires or is revoked. Not yet: mTLS or workload
  identity (SPIFFE) binding a token to the calling workload.

## Open work, in priority order

1. ~~Reference deployment with egress control and process isolation~~ — done: `deploy/`.
2. ~~Persistent state for budgets, approvals and used grants~~ — done (SQLite, single host).
3. ~~Short-lived, rotatable credentials~~ — done (signed tokens).
4. ~~Production HTTP server / proxy and API fuzzing~~ — done (uvicorn behind nginx; Hypothesis fuzz of the API, tokens, policy, contract loader and both transports).
5. ~~A real integration proving the positioning~~ — done (MCP gateway + upstream MCP tools, exercised with the official SDK).
6. CI on every push and a nightly deep-fuzz run — done (`.github/workflows`); outside security review is invited but has not happened yet (`SECURITY.md`).
7. Workload identity (mTLS / SPIFFE) binding a token to the calling workload.
8. Multi-host state and shared rate limits.
9. Stronger isolation runtime (gVisor / Kata / Firecracker) and a tested Kubernetes deployment.
