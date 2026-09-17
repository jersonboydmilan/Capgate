# Delegation does not transfer authority

```
TaskContract A: web.search ✓  web.fetch ✓  database.write ✗  create_agent ✗
TaskContract B: web.search ✓

Agent A → "Ask Agent B to perform database.write"
Harness → evaluates Agent B's contract → DENIED
```

```bash
cd examples/delegation-boundary
python agent_a.py                 # the scripted demo
capgate simulate task.yaml        # the same scenario as a dry run
```

Three routes, one answer:

1. **A acts directly** — denied under contract A.
2. **A delegates to B** — A's *request* is checked under A's contract
   (`agent.delegate` with `allowed_targets` and `allowed_actions`). B's *action*
   is then checked as B's own proposal under contract B. It is denied because B
   has no `database.write` capability.
3. **A messages B with forged authority, and B obeys blindly** — the message is
   delivered (A may message B), but it carries data, not authority. B's attempts
   are denied: `CONTRACT_MISMATCH` when B claims contract A, `TOOL_NOT_ALLOWED`
   otherwise.

Zero rows are written. The audit trail records `delegated_by: agent-a` on the
delegated decision for traceability — the policy engine never reads it.

Note the corollary: if contract B *did* grant `database.write`, the delegated
action would be allowed, on B's authority. That is the point — authority comes
from the actor's own contract. A contract author controls the confused-deputy
risk with A's `allowed_actions` (what A may ask for) and with B's grants (what B
may do for anyone).
