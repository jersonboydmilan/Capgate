# Contracts

A `TaskContract` is the source of truth for a run: the goal, which agents act
under it, what each may do, the step budget, the expiry, and who may approve
escalations.

```yaml
contract_id: research-v1        # required; letters, digits, _ . : -
version: "3"                    # optional, recorded in the hash
goal: Research X                # required
max_steps: 20                   # required; proposals (incl. denied) across all agents
expires_at: 2026-12-31T23:59:59Z   # optional; timezone required
approvers: [alice, bob]         # optional; principals allowed to decide escalations
agents:
  researcher:
    capabilities:
      web.search: allow
      database.write: deny
      email.send: escalate
      web.fetch:
        effect: allow
        expires_at: 2026-10-01T00:00:00Z
        constraints:
          allowed_domains: [arxiv.org]
```

Shorthand for a single agent:

```yaml
contract_id: research-v1
goal: research X
agent: researcher
allowed_tools: [web.search, web.fetch]
max_steps: 20
```

## Rules

- **A budget is mandatory.** `max_steps` must be a positive integer. It is what
  bounds a compromised agent's probing, escalation spam and message floods.

- **Strict schema.** Unknown fields at any level are errors.
- **One contract per agent.** An agent id may appear in only one loaded contract.
- **Approvers are not agents.** Any overlap is rejected.
- **Reserved namespaces.** `contract.*` and `harness.*` cannot be granted.
- **Immutable after load.** Editing the YAML file later has no effect on a running
  harness; every decision records the `contract_hash` it was made under.
- **Multiple contracts per file.** Use YAML documents separated by `---`, or a
  top-level `contracts:` list.

```bash
harness validate contract.yaml
```
