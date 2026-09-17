# Simulation

`capgate simulate` and `capgate enforce` run the same task through the same
`Harness` and policy engine. The only difference is the mode: in simulation no
grants are minted, the executor refuses everything (`SIMULATION_MODE`), messages
are not delivered, and escalations stay pending.

```bash
capgate simulate task.yaml                 # table
capgate simulate task.yaml -v              # with decision details
capgate simulate task.yaml --json          # for tooling
capgate simulate task.yaml --fail-on deny  # CI gate: exit 1 if any step is denied
capgate enforce  task.yaml --audit audit.jsonl --approver alice
```

## Task files

```yaml
name: research-run
contract: contract.yaml          # path (relative to this file) or inline mapping
# contracts: [a.yaml, b.yaml]    # or several
agent: researcher                # default agent for steps
tools:                           # used by `enforce` only
  web.search: {type: echo}
  database.write: {type: endpoint, url: "http://127.0.0.1:9100/db", credential_env: DB_TOOL_TOKEN}
  web.fetch: {type: http_fetch}
steps:
  - action: web.search
    arguments: {query: "..."}
  - message: {to: writer, body: "draft ready"}
  - delegate: {to: writer, action: docs.write, arguments: {title: Summary}}
  - agent: writer
    action: docs.write
    arguments: {title: Summary}
```

## Workflow

1. Write a contract.
2. Record or script the actions your agent proposes as a task file.
3. `capgate simulate` — read which proposals are denied and why.
4. Tighten or widen the contract; repeat.
5. Add `--fail-on deny` to CI so contract changes that break expected behaviour
   are caught.
6. Switch to `capgate enforce` or `capgate serve`.
