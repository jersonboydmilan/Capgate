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
| Smuggle arguments, hit internal hosts | Capability constraints | Enforced (see limits) | `adversarial/argument_violation` |
| Execute a denied/escalated action anyway | Signed, single-use, argument-bound grants | Enforced | `adversarial/unauthorized_tool`, `adversarial/bypass_attempt` |
| Swap arguments after authorization | Grant binds argument hash | Enforced | `adversarial/argument_violation` |
| Forge or replay a grant | HMAC signature, single use, expiry | Enforced | `adversarial/scope_expansion`, `bypass_attempt` |
| Call the tool endpoint directly | Network: agent can reach only `harness:8700`. Credentials: held only by executor | Enforced in the reference isolated runtime; credential layer enforced in any separate-process deployment | `isolation/`, `bypass/test_process_boundary.py` |
| Open any other socket (internet, host, other containers, raw packets) | Internal networks, iptables allowlist, no capabilities | Enforced in the reference isolated runtime | `isolation/` |
| Read harness secrets (tool credential, signing key, tokens) | Secrets mounted only into harness/tools; separate PID namespace; read-only FS | Enforced in the reference isolated runtime | `isolation/` (full filesystem, env and `/proc` scan) |
| Impersonate another agent over HTTP | Identity from bearer token | Enforced | `bypass` |
| Pick a more permissive contract | Server-side binding | Enforced | `adversarial/scope_expansion` |
| Edit the contract or grant itself capabilities | Frozen contracts, reserved namespaces | Enforced | `adversarial/contract_tampering`, `scope_expansion` |
| Get another agent to act for it | Non-transitive delegation, messages carry no authority | Enforced | `adversarial/delegation`, `message_injection` |
| Approve its own escalation | Approvers are distinct principals, per contract | Enforced | `adversarial/escalation`, `bypass` |
| Exhaust budgets or flood messages | `max_steps` counts every proposal; `max_calls` | Enforced | `adversarial/budget_exhaustion` |
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
   and the open internet. The reference runtime in `deploy/isolated/` implements
   this with internal Docker networks plus an iptables allowlist and tests it
   from inside the agent sandbox (`pytest -m docker`); other deployments must
   reproduce it.

A single-process setup (`Harness` used in-process with an agent in the same
Python interpreter) is a **cooperative** integration: useful for simulation,
testing and trusted orchestrators, not a security boundary against a
compromised agent.

## Known limits

- **URL constraints check the URL string.** DNS rebinding, redirects to private
  addresses, and unusual IP encodings that a resolver accepts but Python's
  `ipaddress` does not (e.g. `0x7f.1`) are not caught by `block_private_hosts`.
  Prefer `allowed_domains`, and put an egress proxy in front of `HttpFetchTool`
  for untrusted destinations.
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
- **Audit tamper-evidence is local.** The hash chain detects edits within the
  file. Ship records to append-only storage to protect against deletion.
- **Tokens are static bearer tokens.** No rotation, mTLS or workload identity
  yet.

## Open work, in priority order

1. ~~Reference deployment with egress control and process isolation~~ — done: `deploy/isolated/`.
   Next: gVisor/microVM runtime option; Kubernetes NetworkPolicy equivalent.
2. ~~Persistent state for budgets, approvals and used grants~~ — done (SQLite, single host). Next: multi-host store.
3. Workload identity (mTLS / SPIFFE) in place of static tokens.
4. Remote append-only audit sink.
5. MCP gateway entry point on the same interception path.
