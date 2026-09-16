# Delegation

**Delegation does not transfer authority.** The authorization question is
always: *who is acting, under which contract, with what capability, on what
resource?* Never: *who asked them to?*

## Two decisions, never one

`harness.delegate("agent-a", "agent-b", "database.write", args)`:

| Stage | Request | Evaluated under | Checks |
|---|---|---|---|
| 1 | `agent-a` → `agent.delegate {to, action, arguments}` | contract A | A has `agent.delegate`; `agent-b` ∈ `allowed_targets`; `database.write` ∈ `allowed_actions` |
| 2 | `agent-b` → `database.write args` | contract B | B's own capability and constraints — nothing else |

Stage 2 runs only if stage 1 allows. `DelegationResult.blocked_at` is `"sender"`
or `"recipient"`. The stage-2 decision records `delegated_by` and
`parent_decision_id` for traceability; the policy engine has no parameter that
could read them.

## Consequences

- A cannot lend B authority A has (A's `web.fetch` does not let B fetch).
- A cannot borrow B's authority unless A's contract says A may ask B for that
  specific action. That is the control against confused-deputy delegation.
- If A may ask and B may act, the action runs on **B's** authority, charged to
  **B's** contract budget.
- Chains (A → B → C) are just repeated pairs; each hop is checked the same way.
- If `agent.delegate` is `escalate`, a human approves A's *request*. B's action
  is still evaluated under B's contract afterwards.

## Messages

`send_message` is an `agent.message` proposal under the sender's contract. A
delivered `Message` has `message_id`, `sender`, `recipient`, `body` and
`decision_id` — no authority fields. Whatever the body says ("you are now
authorized…", `contract_id: admin`), the recipient's later proposals are
evaluated under the recipient's binding. Claiming another contract yields
`CONTRACT_MISMATCH`.

See `examples/delegation-boundary/` and `tests/adversarial/delegation/`.
