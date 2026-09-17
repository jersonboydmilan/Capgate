# Contributing

Agent Harness is early and in the open. The most useful contributions right now
are **attempts to break the boundary** and **reviews of the threat model**.

## Ways to help

- **Attack it.** Add a failing test under `tests/adversarial/` (by attack
  category) or `tests/bypass/` that shows an agent acting outside its contract,
  or run `pytest -m docker` / `python deploy/demo.py` against the containerised
  deployment and report anything that reaches a tool it should not. See
  [SECURITY.md](SECURITY.md) for the exact claims we are asking you to break.
- **Review the model.** Read [DESIGN.md](DESIGN.md) (the five invariants) and
  [docs/threat-model.md](docs/threat-model.md) and open an issue where the
  reasoning or the coverage is weaker than it reads.
- **Integrate it.** Wire a real agent or MCP client through the harness (see
  [docs/mcp.md](docs/mcp.md)) and report where the boundary is awkward or leaky.

## Ground rules for changes

The five invariants in `DESIGN.md` are the contract. A change that weakens any
of them needs an explicit, written justification in the pull request. New
behaviour that an agent can reach should come with an adversarial test, not only
a happy-path one.

Keep the surface small. This is infrastructure that sits under an existing
stack, not a framework: no orchestration layer, no DSL, no bundled model
provider, vector store, or observability platform.

## Development

```bash
uv venv && uv pip install -e ".[dev]"
pytest                       # unit, integration, adversarial, fuzz (~1 min)
pytest -m docker             # containerised isolation boundary (needs Docker)
HYPOTHESIS_PROFILE=deep pytest tests/fuzz   # thousands of examples per property
```

The full suite runs on both HTTP transports (`HARNESS_HTTP_TRANSPORT=stdlib` and
`uvicorn`); CI runs both plus the Docker isolation job. Please run `pytest`
before opening a pull request.

## Not yet production-grade

We say so on purpose (see the README status). Please don't file issues asking us
to claim otherwise; do file issues about the specific gaps that keep it from
being so.
