# Agent Harness

**Authority management for autonomous software agents.**

> The agent proposes. The harness authorizes. The executor acts.

Agent Harness is a runtime enforcement boundary that sits underneath your
existing agent stack. Every consequential action an agent takes — a tool call,
a message to another agent, a request that another agent act — is a structured
proposal that passes through one deterministic, deny-by-default policy engine
before anything executes. Every decision is written to a tamper-evident audit
trail.

It is not an agent framework, a prompt library, or a model wrapper. It does not
ask the model to follow rules; it makes unauthorized actions structurally
unable to reach a tool.

![Agent Harness architecture](docs/assets/agent-harness-diagram.png)

## The boundary, under attack

Run a compromised agent — one that ignores the SDK and tries every route
around the harness — inside the reference isolated runtime:

```bash
python deploy/isolated/demo.py          # needs Docker; builds offline, ~1 minute
```

```
AGENT HARNESS — COMPROMISED AGENT IN ISOLATED RUNTIME

  PASS  HTTP  direct call to tool endpoint (no auth)                        0
  PASS  HTTP  out-of-contract action via harness                            [403, 'TOOL_NOT_ALLOWED']
  PASS  HTTP  impersonate db-admin                                          [403, 'IDENTITY_MISMATCH']
  PASS  HTTP  claim admin contract                                          [403, 'CONTRACT_MISMATCH']
  PASS  HTTP  approve own escalation                                        404
  PASS  HTTP  delegate to privileged agent                                  [403, 'TOOL_NOT_ALLOWED']
  PASS  NET   tcp tools:9100 by IP                                          error:101
  PASS  NET   misattached tool on the agent's own network                   refused
  PASS  NET   internet tcp 1.1.1.1:443                                      error:101
  PASS  NET   resolve example.com                                           dns_failed
  PASS  NET   raw socket                                                    permission_denied
  PASS  PROC  effective capabilities                                        0
  PASS  SEC   filesystem + env + /proc scan for harness secrets             none found
  PASS  PATH  in-contract action via harness                                [200, 'succeeded']
  PASS  PATH  side effects at real tool                                     ['/web.search']
  PASS  PATH  audit hash chain intact                                       True
  …
41/41 checks passed. Side effects at the real tool: 1 (the authorized web.search).
```

What this runtime enforces, precisely: **the agent process cannot open a socket
to anything except the harness API**, and it cannot read the tool credentials,
permit signing key or other principals' tokens. The direct tool calls now fail at
the network (`0` = no connection), not merely with `401`. The only path that
produces a side effect is `authorize → signed permit → executor`. Details, the
two network layers, and what is *not* claimed:
[deploy/isolated/README.md](deploy/isolated/README.md).

## Thirty seconds: simulate a contract

```bash
pip install -e .
harness simulate examples/simulation/task.yaml
```

```
AGENT HARNESS — SIMULATION

Contract: research-v1
Agent: researcher

    ACTION                          DECISION   REASON
─────────────────────────────────────────────────────
01  web.search                      ALLOW      CAPABILITY_GRANTED
02  web.fetch                       ALLOW      CAPABILITY_GRANTED
03  database.read                   DENY       EXPLICITLY_DENIED
04  agent.delegate                  ESCALATE   REQUIRES_APPROVAL
05  web.search                      ALLOW      CAPABILITY_GRANTED

Summary
────────────────
Allowed:      3
Denied:       1
Escalated:    1

No external actions were executed.
```

Simulation needs no infrastructure and uses the exact engine that enforcement
uses. Write a contract, run your agent's proposals through `simulate`, tune
the contract, then switch to `harness enforce`.

## The contract

```yaml
contract_id: research-v1
goal: Research recent work on agent authorization
max_steps: 20
approvers: [alice]
agents:
  researcher:
    capabilities:
      web.search: allow
      web.fetch:
        effect: allow
        constraints:
          allowed_arguments: [url]
          block_private_hosts: true
      database.read: deny
      agent.delegate:
        effect: escalate
        constraints:
          allowed_targets: [writer]
          allowed_actions: [docs.write]
```

Anything not named is denied. Unknown fields are errors, so a typo cannot
quietly widen or drop a rule. See [docs/contracts.md](docs/contracts.md) and
[docs/capabilities.md](docs/capabilities.md).

## The API

```python
from harness import Harness, load_contract

harness = Harness(load_contract("contract.yaml"), tools={"web.search": search})

result = harness.authorize(agent="researcher", action="web.search", arguments={"query": "..."})
if result.allowed:
    output = harness.execute(result).output
else:
    print(result.decision.decision, result.reason_code)   # deny TOOL_NOT_ALLOWED
```

That is most of the surface: `authorize`, `execute`, plus `send_message`,
`delegate` and `approve`/`reject` for multi-agent and human-in-the-loop flows.
No orchestration system, DSL, model provider, vector database or observability
platform is required.

## Delegation does not transfer authority

```
TaskContract A: web.search ✓  web.fetch ✓  database.write ✗  create_agent ✗
TaskContract B: web.search ✓

Agent A → "Ask Agent B to perform database.write"
Harness → evaluates Agent B's contract → DENIED
```

```bash
cd examples/delegation-boundary && python agent_a.py
```

The authorization question is always *who is acting, under which contract,
with what capability, on what resource* — never *who asked*. The policy engine
has no input through which a delegator could influence the answer. See
[docs/delegation.md](docs/delegation.md).

## What is actually enforced

The README claims exactly this: **all consequential execution is mediated by
the harness**, in the following precise sense.

| Layer | Enforced by | Tested in |
|---|---|---|
| Out-of-contract proposals are denied | Pure deny-by-default policy engine | `tests/adversarial/*`, `tests/unit/test_policy.py` |
| A denied or escalated action never reaches a tool | Executor runs only with a harness-signed, single-use grant bound to the exact agent, action and argument hash | `tests/adversarial/unauthorized_tool` (Test C) |
| An agent process cannot reach the real tool directly | **Isolated runtime:** agent's only network route is `harness:8700` (internal networks + iptables allowlist). **Any deployment:** tool credentials exist only in the executor and the tool endpoint requires them | `tests/isolation` (`pytest -m docker`), `tests/bypass/test_process_boundary.py` |
| An agent cannot read harness secrets | Isolated runtime: secrets mounted only into harness/tools, separate PID namespace, no capabilities, read-only filesystem | `tests/isolation` |
| An agent cannot impersonate another agent or pick its contract | Identity comes from the bearer token, contract from the server-side binding | `tests/bypass`, `tests/adversarial/scope_expansion` |
| Every decision is auditable | Audit write happens before a decision is returned; failure blocks execution; records are hash-chained | `tests/adversarial/audit` (Test E) |

The network and secret guarantees hold for the reference runtime in
[`deploy/isolated/`](deploy/isolated/README.md), or a deployment that reproduces
its properties. If an agent instead runs as the same user on the same host as
the harness, it may be able to read the harness's memory, files or environment;
credential custody still stops direct tool calls, but not that. Kernel and
container-runtime escapes are out of scope. The SDK is a convenience, never the
boundary. Full detail: [docs/threat-model.md](docs/threat-model.md).

## Three ways in, one path through

```
Python SDK (in-process Harness) ─┐
HTTP API (harness serve)  ───────┼──► Interceptor ─► Policy ─► Executor ─► Tool / Agent
harness_client / curl  ──────────┘
```

```bash
harness serve server.yaml          # agents authenticate with bearer tokens
```

```python
from harness_client import HarnessClient
client = HarnessClient("http://127.0.0.1:8700", token=os.environ["AGENT_TOKEN"])
client.act("web.search", {"query": "..."})
```

An MCP gateway is a natural fourth entry point onto the same path; it is not
included yet.

## Audit trail

```bash
harness enforce examples/basic/task.yaml --audit audit.jsonl
harness audit audit.jsonl --decision deny
harness audit audit.jsonl --verify
```

Each record states what was proposed, by which agent, under which contract
(id and content hash), which capability and policy rule applied, the decision
and reason code, and the outcome. Nothing from model reasoning is captured.

## Tests

```bash
pip install -e ".[dev]" && pytest     # unit, integration, adversarial, process bypass (~5s)
pytest -m docker                      # isolated runtime acceptance tests (Docker, ~1 min)
```

The adversarial suite is organised by attack category —
`unauthorized_tool`, `argument_violation`, `scope_expansion`, `delegation`,
`capability_expiration`, `contract_tampering`, `message_injection`,
`bypass_attempt`, `budget_exhaustion`, `escalation`, `audit` — plus
`tests/adversarial/test_required_scenarios.py`, which covers the six
acceptance scenarios one test each; `tests/bypass/`, which attacks a live
deployment from a separate OS process; and `tests/isolation/`, which attacks the
containerised reference runtime from inside the agent's sandbox.

## Layout

```
src/harness/      contract, capability, policy, decision, request, interceptor,
                  executor, audit, core (Harness), simulation, server, cli, tools
sdk/python/       harness_client — thin HTTP client
examples/         basic, simulation, delegation-boundary, adversarial-agent
deploy/isolated/  reference isolated runtime: compose, netguard, offline images, attack demo
policies/         reusable contract templates
docs/             architecture, contracts, capabilities, delegation, simulation, threat model
DESIGN.md         the five invariants
```

## Status

The five pieces — contract, proposal, deterministic decision, enforced
execution, audit — work end to end and are tested together
(`tests/integration/test_end_to_end.py`). In the reference isolated runtime the
boundary holds against every tested bypass route, enforced by the network and
process boundary as well as by credential custody (`pytest -m docker`). Open
items are tracked in [docs/threat-model.md](docs/threat-model.md).
