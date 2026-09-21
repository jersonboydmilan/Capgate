# Capgate — external security reviewer brief

A scoped starting point for an outside auditor. It says what Capgate claims,
where the interesting code and trust boundaries are, how to stand up and attack
the system, and what is explicitly out of scope. It complements — does not
replace — [SECURITY.md](../SECURITY.md) (the claims and disclosure process) and
[docs/threat-model.md](threat-model.md) (the precise enforced/not-enforced list).

**Why this review matters most.** Every "the boundary holds" statement in this
repository currently rests on tests the authors wrote. An independent attempt to
break the claims below is the single highest-value contribution to the project.

---

## 1. The system in one page

Capgate is a runtime **authority boundary** for autonomous agents:

> The agent proposes. The harness authorizes. The executor acts.

Every consequential action (a tool call, a message to another agent, a request
that another agent act) is a structured `ActionRequest` that must pass one
deterministic, deny-by-default decision before anything executes. The executor
is the only component that holds tool credentials, and it will only act on a
single-use, signed permit whose argument hash matches the authorized request.

```
agent ──HTTP──▶ edge (nginx) ──▶ harness API ──▶ decision ──▶ signed permit ──▶ executor ──▶ tool
 (untrusted)                     (authority)                                    (holds creds)
```

**Components** (`src/capgate/`):

| Area | Modules |
|---|---|
| Request primitive & contracts | `request.py`, `contract.py`, `capability.py` |
| Decision core | `policy.py`, `decision.py`, `interceptor.py`, `core.py` |
| Execution | `executor.py`, `tools.py`, `toolservice.py` |
| Audit | `audit.py` |
| Identity / credentials | `identity.py`, `workload.py`, `secretsource.py` |
| Transport | `api.py`, `asgi.py`, `server.py`, `mtlsedge.py`, `netaddr.py` |
| State / limits | `state.py`, `ratelimit.py` |
| MCP gateway | `mcp/` |

**Trust model.** The agent is fully untrusted and assumed compromised — it may
ignore the SDK and craft arbitrary HTTP. The harness, executor, tool service,
signing keys and audit store are trusted. The boundary is the harness API; the
agent must have no other route to a tool, another agent, secrets, or the
network. In-process, cooperative embedding of the harness is **not** a security
boundary (see §6).

---

## 2. The claims to break

These are the seven claims from [SECURITY.md](../SECURITY.md). A compromised
agent within its request budget should **not** be able to:

1. cause any consequential action its contract does not grant;
2. obtain another agent's authority (delegate, message, impersonate, or claim a
   different contract);
3. reach a tool, another agent, secret material, or the network by any route
   other than the harness API;
4. forge, replay, extend, or misuse a credential or an execution permit;
5. execute an escalated action without a designated human approval;
6. erase or rewrite the audit trail undetectably;
7. exhaust or reset budgets, or take the harness down, from within its budget.

They map to the five design invariants in [DESIGN.md](../DESIGN.md):

| Invariant | Claims | Where enforced |
|---|---|---|
| 1. No authority without explicit capability | 1 | `policy.py`, `capability.py` |
| 2. The agent cannot expand its own contract | 1, 2 | `contract.py` (strict load, frozen), `request.py` |
| 3. Delegation does not transfer authority | 2 | `core.py` delegation path, `decision.py` |
| 4. No consequential action without harness authorization | 1, 3, 4 | `executor.py` (permit + arg-hash), `toolservice.py`, isolation |
| 5. Every authorization decision is auditable | 6 | `audit.py` (hash chain) |

Credentials/permits (4), escalation (5) and budgets/DoS (7) cut across identity,
core and rate-limiting.

---

## 3. Attack surface — where to look

**Primary entry point: the HTTP API** (`api.py` → `HarnessAPI.dispatch`). This is
the transport-independent core every deployment funnels through. Everything an
agent can send arrives here. High-value targets:

- **Request parsing & identity binding** — `dispatch` derives the caller's
  principal from the bearer token and (optionally) a verified workload identity;
  the request body must never be able to override that (`agent_id`,
  `contract_id`, reserved actions). See the forged-identity probes in
  `examples/adversarial-agent/malicious_agent.py`.
- **Argument integrity** — arguments are frozen and hashed at construction
  (`request.py`); the signed permit binds the exact argument hash
  (`executor.py`). Look for any gap between the hash that is *authorized* and the
  arguments that are *executed* (a TOCTOU here was found and fixed once —
  `core.approve`).
- **Credentials** — short-lived HMAC tokens `ah1.<kid>.<claims>.<sig>` with a
  keyring, TTL cap, and revocation (`identity.py`). Probe: forgery, replay,
  algorithm/kid confusion, TTL extension, revocation races, clock skew.
- **Workload binding** — `cnf.x5t#S256` (RFC 8705) and `wl` SPIFFE claims
  (`workload.py`); the core only compares strings, a transport supplies the
  verified identity (`server.py` mTLS, `mtlsedge.py`, or a trusted proxy's
  forwarded headers). Probe: forging the forwarded identity headers from outside
  the trusted-proxy CIDR; SPIFFE parsing.
- **Escalation & approval** — an escalated action returns an approval id and must
  wait for a designated human (`core.py`, `decision.py`). Probe self-approval,
  approving via a forged approver identity, approval-id guessing.
- **Delegation** — `/v1/delegations`: A asking B to act makes two independent
  decisions; confirm A never gains B's authority (confused-deputy).
- **Audit** — hash-chained records (`audit.py`); `PostgresAuditSink` uses
  per-replica chains. Probe: truncation, reordering, silent rewrite, chain
  forks; verify `capgate audit --verify` actually catches each.
- **Rate limiting / budgets** — per-client and per-principal token buckets,
  optionally shared via the state store (`ratelimit.py`), plus a required
  per-contract step budget (`state.py`). Probe: budget reset/underflow, limiter
  bypass, cross-replica races, unbounded work before the limiter runs.
- **Edge** — nginx bounds sizes, timeouts and the path/method allowlist
  (`deploy/proxy/nginx.conf`); uvicorn/h11 behind it (`asgi.py`, `server.py`).
  Probe: request smuggling, slowloris, oversized bodies, header injection,
  spoofed `X-Real-IP`/`X-Forwarded-For` from an untrusted source.
- **MCP gateway** (`mcp/`) — the same authorize→permit→executor path reached over
  MCP Streamable HTTP JSON-RPC. Confirm no MCP method bypasses authorization.

**Isolation boundary** (reference deployment): internal Docker networks +
`netguard` iptables egress allowlist + hardened containers; the agent must reach
only the edge. The Kubernetes deployment reproduces this with NetworkPolicy +
securityContext + Pod Security `restricted`.

---

## 4. Stand it up and attack it

Clone, then:

```bash
pip install -e ".[dev]"
pytest -q                       # 307 unit/integration/fuzz/adversarial, no infra
```

**The compromised-agent suite** (Docker; the agent runs inside its sandbox and
attacks from there):

```bash
python deploy/fetch_artifacts.py          # once: offline build inputs
python deploy/demo.py                      # build, attack, report, tear down
pytest -q -m docker                        # the same, as assertions
```

The adversary itself is `examples/adversarial-agent/malicious_agent.py` — the
cleanest place to add a new attack. Its checks are asserted in
`tests/adversarial/isolation/`.

**Kernel isolation under gVisor** (Linux host with `runsc`):

```bash
python deploy/demo.py --gvisor
pytest -q -m gvisor
```

**Kubernetes, live** (kind + Calico; see `deploy/k8s-e2e/`): the `k8s-e2e` CI job
runs the real compromised agent on a cluster and asserts the egress/secret/
side-effect controls with `deploy/k8s-e2e/assert.py`.

**CI** (`.github/workflows/ci.yml`) is the authoritative run matrix:

| Job | What it exercises |
|---|---|
| `test` (3.10–3.13 × stdlib/uvicorn) | 307 unit/integration/fuzz/adversarial |
| `k8s` | manifest schema + static isolation invariants (`deploy/k8s/validate.py`) |
| `docker` | compromised-agent isolation, mTLS edge, multi-host state |
| `gvisor` | the isolation attack with the agent under a user-space kernel |
| `k8s-e2e` | live kind + Calico cluster, real agent Job |

**Test map** (`tests/`): `unit/`, `integration/`, `fuzz/` (Hypothesis over the
API, tokens, policy, contract loader, both transports), `bypass/`, and
`adversarial/{argument_violation, audit, budget_exhaustion, bypass_attempt,
capability_expiration, contract_tampering, delegation, escalation, isolation,
message_injection, scope_expansion, unauthorized_tool}`.

A proof-of-concept is most useful as a **failing test** in the style of
`tests/adversarial/` or `tests/bypass/`.

---

## 5. In scope

- Everything under `src/capgate/` and the documented HTTP + MCP API.
- The reference deployments in `deploy/` (compose, gVisor overlay, Kubernetes).
- Harness API bugs (parsing, auth, decision logic, state, audit) — **in scope**,
  including denial of service from within an agent's request budget.
- Credential, permit, delegation, escalation, and audit-integrity attacks.

## 6. Out of scope

- **Kernel / container-runtime escape** and a **compromised Docker host or
  daemon** — the host is trusted. gVisor and microVM runtimes are offered to
  shrink this surface, not to make the host untrusted.
- **In-process, cooperative embedding** — an "agent" sharing the harness's own
  Python process is not on the other side of the boundary; a finding that only
  affects that mode is a hardening note, not a boundary break.
- Secret *provisioning* — how signing keys and tool credentials get into the
  secret store is deployment-specific; the claim is that the agent cannot read
  them once there.
- Vulnerabilities in third-party dependencies themselves (report upstream), as
  opposed to how Capgate uses them.

## 7. Known limitations & assumptions (please pressure-test these)

- **Self-tested.** No prior external review — treat every claim as unverified.
- **Research preview**, no numbered release; APIs may change.
- The reference `netguard` allowlist and Docker networking are a *reference*;
  production isolation depends on the operator's runtime (gVisor / microVM / a
  NetworkPolicy-enforcing CNI). The Kubernetes `k8s-e2e` uses Calico because the
  default kindnet does not enforce egress — a deployment on a non-enforcing CNI
  silently loses the network claim.
- Audit is tamper-**evident**, not tamper-**proof**: an attacker who can write
  the audit store can break the chain, but not undetectably. Confirm the
  detection actually fires for every mutation.
- Time and clocks: TTLs, revocation, and rate limits depend on wall-clock and,
  on Postgres, on the server clock. Skew and races are worth probing.

## 8. High-value places to start

1. Any divergence between the **authorized** argument hash and the **executed**
   arguments (`request.py` ↔ `executor.py` ↔ `core.py`).
2. Making the **request body** override the **token-derived** principal or
   contract (`api.py` `dispatch`).
3. **Forwarded-identity spoofing**: presenting `X-Real-IP` / SPIFFE / thumbprint
   headers from outside the trusted-proxy CIDR (`netaddr.py`, `server.py`,
   `mtlsedge.py`).
4. **Escalation approval** without a real human decision (self-approval, forged
   approver, id guessing).
5. **Audit chain** truncation/rewrite that `--verify` fails to catch.
6. **Budget / rate-limit** reset, underflow, or cross-replica race on Postgres
   (`state.py`, `ratelimit.py`).
7. **MCP** methods that reach a tool without the full authorize→permit path
   (`mcp/`).

## 9. Reporting

Follow [SECURITY.md](../SECURITY.md): a private GitHub Security Advisory is
preferred; include a PoC as a failing test where possible. Acknowledgement
target is 3 business days; disclosure is coordinated informally (no packaged
release yet), with credit in the advisory and CHANGELOG unless you prefer
otherwise.
