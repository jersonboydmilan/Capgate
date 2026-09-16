# Design

Agent Harness manages **authority** for autonomous software. Its job is to
answer, for every proposed action, one question — *may this agent, under
this contract, do this, with these arguments, now?* — and to make sure the
answer is binding.

## The five invariants

Changes that weaken any of these need an explicit, written justification in
the pull request that makes them.

### 1. No authority without explicit capability

Deny by default. An action executes only if the acting agent's contract names
it with `effect: allow` (or `escalate`, followed by a human approval) and every
constraint on that capability holds. There are no wildcards, no inheritance
between agents, and no implicit grants.

*Enforced in:* `policy.evaluate` (`default:deny`), `capability.parse_capability`.

### 2. The agent cannot expand its own TaskContract

Contracts are validated strictly, frozen at load time, and identified by a
content hash recorded in every decision. The `contract.*` and `harness.*`
action namespaces are reserved: no contract may grant them, and any proposal
using them is denied. An agent is bound to exactly one contract by the
harness; a request that names a different contract is denied
(`CONTRACT_MISMATCH`). Approvers cannot be agents.

*Enforced in:* `contract.TaskContract`, `contract.build_bindings`, `policy.evaluate`.

### 3. Delegation does not transfer authority

When agent A asks agent B to act, two separate decisions are made:

1. A's request (`agent.delegate`) under A's contract — including
   `allowed_targets` (whom A may ask) and `allowed_actions` (what A may ask for).
2. B's action, as B's own proposal, under B's contract only.

`policy.evaluate` takes no "requester" or "on behalf of" input, and
`ActionRequest` has no such field; that is a structural guarantee, pinned by
`tests/unit/test_policy.py::test_policy_has_no_delegator_input`. Messages
between agents are data: the `Message` envelope carries no authority fields.

*Enforced in:* `core.Harness.delegate`, `request.DelegationRequest`, `policy.evaluate`.

### 4. No consequential action executes without harness authorization

The executor is the only component that holds tool credentials, and it runs a
tool only when presented with a grant that is signed by the harness,
single-use, unexpired, and bound to the exact agent, contract, action and
argument hash of an `allow` decision. The harness mints grants only for `allow`
decisions and never in simulation. Inter-agent message delivery goes through
the same executor path.

*Enforced in:* `executor.Executor`, `core.Harness._result_for`. The deployment
side of this invariant — that the agent has no other route to the tool — is
described in `docs/threat-model.md` and tested in `tests/bypass/`.

### 5. Every authorization decision is auditable

The audit record is written before a decision is returned. If the write fails,
the exception propagates and no grant exists, so nothing executes. Records are
structured (never model reasoning) and hash-chained; `harness audit --verify`
detects edits, deletions and reordering.

*Enforced in:* `interceptor.Interceptor.record`, `audit.AuditLog`.

## One primitive

Everything is an `ActionRequest(agent_id, action, arguments, contract_id)`.
Messages become `agent.message` requests; delegation becomes an
`agent.delegate` request followed by the recipient's own request. There is one
interception point (`Interceptor.decide`) and one execution path
(`Executor.execute`). Simulation and enforcement are two modes of the same
`Harness`, so they cannot drift apart.

## Decisions worth knowing

- **Steps count proposals, not executions.** `max_steps` is consumed by every
  proposal, including denied ones, so probing for permissions spends budget.
  The budget is per contract, shared by all agents bound to it.
- **Approvals re-evaluate.** Approving an escalation re-runs the policy engine
  at approval time; if the contract or capability has expired in the meantime,
  the approval yields a deny. Approving a delegation approves A's *request*;
  B's action is still evaluated under B's contract.
- **Constraints are checked before escalation.** A proposal that violates a
  constraint is denied outright and never reaches a human.
- **Arguments are frozen at proposal time.** `ActionRequest` stores canonical
  JSON; the grant binds its hash. Swapping arguments between authorization and
  execution is refused (`GRANT_ARGUMENTS_MISMATCH`).
- **The in-process API trusts its caller for identity.** `harness.authorize(agent=...)`
  is for orchestrators you control. Untrusted agents must come through the HTTP
  boundary, where identity comes from the token.

## Non-goals

- Generic "AI safety", content moderation, or judging the model's intent.
- Capturing or policing chain-of-thought.
- Being an agent framework, orchestration layer or model client.
