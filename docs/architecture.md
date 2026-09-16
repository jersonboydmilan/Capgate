# Architecture

```
Human intent
     ↓
TaskContract          contract.py      declarative, validated, frozen, content-hashed
     ↓
Capabilities          capability.py    explicit per-agent grants + argument constraints
     ↓
Policy                policy.py        pure function: request + contracts + usage + time → evaluation
     ↓
Agent proposal        request.py       ActionRequest(agent_id, action, arguments, contract_id)
     ↓
Authorization         interceptor.py   the single choke point: decide, count, audit
     ↓
Execution             executor.py      verifies a signed, single-use grant; only holder of credentials
```

## Request lifecycle

```
ActionRequest ──► Interceptor.decide
                    ├─ policy.evaluate
                    │    schema → identity binding → contract match → contract expiry
                    │    → step budget → reserved namespace → capability lookup (default deny)
                    │    → explicit deny → capability expiry → constraints → message/delegation target
                    │    → escalate | allow
                    ├─ increment counters
                    └─ AuditLog.record("decision")      ← fails closed
                 ──► Decision
                    ├─ ALLOW    → ExecutionGrant (HMAC, single-use, bound to argument hash)
                    ├─ ESCALATE → PendingApproval → approve/reject → re-evaluate → Decision
                    └─ DENY     → nothing
                 ──► Executor.execute(grant, request)
                    ├─ verify signature, agent, action, argument hash, expiry, single use
                    ├─ run tool (credentials live here)
                    └─ AuditLog.record("execution" | "execution_refused")
```

## Messages and delegation reuse the same path

```
send_message(A, B, body)      → ActionRequest(A, "agent.message", {to: B, body})  → decide → execute (delivery)
delegate(A, B, action, args)  → ActionRequest(A, "agent.delegate", {...})         → decide under A's contract
                              → ActionRequest(B, action, args)                    → decide under B's contract
```

## Entry points

| Entry | Identity from | Use |
|---|---|---|
| `Harness` (in-process) | the caller | trusted orchestrators, tests, simulation |
| `harness serve` / `HarnessServer` | bearer token | untrusted agents; the enforcement boundary |
| `harness_client.HarnessClient` | bearer token | convenience wrapper over the HTTP API |
| `harness simulate` / `enforce` | task file | contract development and CI |

## Modules

| Module | Responsibility |
|---|---|
| `request.py` | `ActionRequest`, `MessageRequest`, `DelegationRequest`; canonical argument freezing |
| `contract.py` | `TaskContract` schema, YAML loading, agent→contract binding |
| `capability.py` | capability parsing, constraint checks |
| `policy.py` | the pure deny-by-default evaluator |
| `decision.py` | `DecisionType`, `ReasonCode`, `Decision` |
| `interceptor.py` | decide + count + audit |
| `executor.py` | grants, signing, verified execution |
| `core.py` | `Harness` facade: authorize, execute, messages, delegation, approvals |
| `audit.py` | hash-chained JSONL audit log |
| `simulation.py` | task files, simulate/enforce runs, rendering |
| `server.py` | HTTP boundary |
| `tools.py`, `toolservice.py` | built-in tools; reference controlled tool endpoint |
| `cli.py` | `harness` command |
