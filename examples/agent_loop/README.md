# A real agent loop through Capgate

A model-driven tool-use loop where **the model chooses the tool calls** and
Capgate authorizes each one before it runs. This is the positioning end to end:
Capgate is the boundary under a real agent, not a scripted client.

```
model ── tool call ──► Capgate MCP gateway ── authorize ─► permit ─► executor ─► tool
      ◄─ result / denial / approval-id ──┘   (every call, first)
```

```bash
python examples/agent_loop/demo.py                       # deterministic offline model
ANTHROPIC_API_KEY=sk-... python examples/agent_loop/demo.py   # a real Claude model drives it
```

Offline output:

```
  ✓ web-search       ALLOW
  ✓ web-fetch        ALLOW
  ✗ database-write   EXPLICITLY_DENIED     Denied by the agent harness: …
  ⏸ docs-publish     REQUIRES_APPROVAL     Not executed: … approval_id=…
  ✓ web-search       ALLOW
real tool executions: ['web.search', 'web.fetch', 'web.search']
```

The model tried to write to the database and to publish; Capgate denied the
write and held the publish for a human, and the model carried on with what it
was allowed to do. Only the authorized calls reached a real tool.

## How it works

- **The tools are the contract.** The loop lists tools from the gateway
  (`tools/list`) — those are exactly the agent's granted capabilities. A denied
  action isn't even offered; an escalated one is, and returns an approval id.
- **Every call is an authorization.** Each `tools/call` becomes an
  `ActionRequest` under the agent's contract → policy → executor. Denials and
  escalations come back to the model as tool results (`isError`), so the model
  can react instead of crashing.
- **Identity is the token.** The loop connects to `/mcp` with the agent's bearer
  token; nothing in the model's output can change which agent or contract it acts as.

## Provider-agnostic

`loop.py` separates the loop from the model:

- `AnthropicModel` — a real Claude model over the Messages API tool-use loop
  (`ANTHROPIC_API_KEY` or an `ant` profile; `--model`, default `claude-opus-5`).
- `ScriptedModel` — replays a fixed plan so the example and its tests
  (`tests/integration/test_agent_loop.py`) run offline and deterministically
  over the **same** loop and the **same** gateway.

Swapping the model changes nothing about the boundary — that's the point.
