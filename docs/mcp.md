# MCP integration

The harness speaks [MCP](https://modelcontextprotocol.io) on both sides, so it
drops into an existing MCP setup as an authority boundary without either the
agent or the tools becoming harness-specific.

## Gateway: agents call in

`POST /mcp` on the harness API is an MCP server. It speaks MCP Streamable HTTP
in its stateless JSON form (no sessions, no server-initiated streams), handshake
protocol versions `2025-03-26` through `2025-11-25`.

- **Identity is the token, not the payload.** The bearer token that `HarnessAPI`
  verifies decides which agent and contract the call runs under. Nothing in the
  MCP message can change it (`agent_id` in a payload is an identity mismatch).
- **`tools/list`** returns the agent's granted actions (allow or escalate) as MCP
  tools. Action names map to tool names by `.`↔`-` (so `web.search` ↔ `web-search`,
  since clients such as Claude only accept `[A-Za-z0-9_-]`). Input schemas come
  from the capability's argument constraints, or from the upstream MCP tool when
  one backs the action. Descriptions note the contract, whether human approval is
  required, and the visible constraints.
- **`tools/call`** becomes an `ActionRequest` under the agent's contract:
  - allowed → executed, result returned, `_meta.harness` carries the decision id;
  - denied or unknown → `isError` tool result with the reason code (a JSON-RPC
    *success* carrying a tool error, per MCP), audited like any proposal;
  - escalated → `isError` with an `approval_id`; nothing runs until a human
    approves. The `harness-approval_status` tool checks it.
- `agent.message` and `agent.delegate` are offered as tools too, so a
  multi-agent MCP client delegates through the same boundary.

Anything malformed is a proper JSON-RPC error (`-32700/-32600/-32601/-32602`);
batches and server-stream GETs are refused.

## Bridge: stdio-only clients

Many clients (Claude Desktop, Claude Code) launch MCP servers over stdio.
`harness mcp-bridge --url … --token-file …` is a stdio↔HTTP adapter that runs
next to the agent and forwards JSON-RPC to `/mcp` with the agent's own token
(re-read each request, so it can be rotated). It holds no authority itself.

## Upstream: back a tool with a real MCP server

An executor tool of `type: mcp` forwards the authorized call to one tool on an
upstream MCP server that the harness launches over stdio:

```yaml
mcp_servers:
  notes:
    command: [python3, -m, notes_server]
    env: {NOTES_TOKEN: {file: /run/secrets/notes_token}}   # or {env: VAR} / {value: ...}
tools:
  notes.write: {type: mcp, server: notes, tool: write_note}
```

The upstream server's credentials are configured here, on the harness side, and
never reach the agent. The executor calls the upstream tool only with a valid
permit and the exact arguments that were authorized. The upstream tool's own
input schema is surfaced to callers through `tools/list`.

## What this proves

The positioning — *authority boundary, not another framework* — holds against a
real client and a real server: `tests/integration/test_mcp_gateway.py` drives
the gateway with the official MCP SDK client over HTTP and uses an SDK-built MCP
server as an upstream tool, then checks the upstream ledger shows only the
authorized side effects.
