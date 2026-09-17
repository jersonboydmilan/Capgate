"""MCP integration.

  gateway   MCP Streamable HTTP endpoint (`POST /mcp`) on the harness API: an MCP
            client's tool calls become ActionRequests under the caller's contract.
  upstream  executor tools backed by real MCP servers (stdio); they run on the
            harness side, where the credentials live.
  bridge    `harness mcp-bridge`: stdio <-> /mcp for clients that only speak stdio;
            runs next to the agent and holds nothing but the agent's own token.
"""

from .gateway import MCPGateway, action_to_tool_name, tool_name_to_action

__all__ = ["MCPGateway", "action_to_tool_name", "tool_name_to_action"]
