# MCP gateway

Any MCP-speaking agent can talk to the harness, and every tool call it makes is
authorized before it runs. The agent's identity and contract come from its
harness token, not from anything in the MCP messages.

```
MCP client ──/mcp (bearer token)──► harness: authorize ─► permit ─► executor ─► tool
                                       every tools/call is an ActionRequest
```

## Try it

```bash
pip install -e ".[dev]"        # includes the mcp SDK and uvicorn
python examples/mcp/demo.py
```

The demo starts a harness with the `research-v1` contract, mounts `/mcp`, and
drives it with the official MCP SDK client:

- `tools/list` shows only the actions the contract grants (allow or escalate);
  `database.read` (denied) is absent.
- `web.search` runs and returns its result.
- `database.read` comes back as a tool error, `EXPLICITLY_DENIED`.
- `agent.delegate` returns an `approval_id` and does not run; the harness waits
  for a human.

## Point a real client at it

Claude Code / Claude Desktop and other clients that speak MCP over stdio:

```bash
harness token issue --keyring keys.json --sub researcher --role agent --ttl 15m --out agent.token
harness mcp-bridge --url http://127.0.0.1:8080/mcp --token-file agent.token
```

Configure that command as an MCP server in the client. The bridge holds only the
agent's own short-lived token and forwards stdio JSON-RPC to `/mcp`.

Clients that speak MCP Streamable HTTP directly can use `http://127.0.0.1:8080/mcp`
with `Authorization: Bearer <token>`.

## Back a tool with a real MCP server

The executor can call an upstream MCP server, holding its credentials on the
harness side so the agent never sees them:

```yaml
mcp_servers:
  notes:
    command: [python3, -m, notes_server]
    env: {NOTES_TOKEN: {file: /run/secrets/notes_token}}
tools:
  notes.write: {type: mcp, server: notes, tool: write_note}
```

`notes.write` is then an ordinary capability in the contract: allow, deny,
escalate, and constrain its arguments like any other.
