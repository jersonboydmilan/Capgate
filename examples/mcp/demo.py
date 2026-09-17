"""Drive the harness MCP gateway with the official MCP SDK client.

    python examples/mcp/demo.py
"""

import asyncio
from pathlib import Path

from capgate import AuditLog, Harness, load_contracts
from capgate.identity import Keyring, TokenAuthority
from capgate.mcp import MCPGateway
from capgate.server import HarnessServer
from capgate.tools import EchoTool

ROOT = Path(__file__).resolve().parents[2]


async def main() -> None:
    from mcp import Client
    import mcp.client.streamable_http as sh
    from mcp.types import Implementation

    contracts = load_contracts(ROOT / "examples/simulation/contract.yaml")
    tools = {name: EchoTool() for name in ("web.search", "web.fetch")}
    harness = Harness(contracts, tools=tools, audit=AuditLog())
    authority = TokenAuthority(Keyring.generate())
    server = HarnessServer(harness, authority).start()
    MCPGateway(server.api)
    token = authority.issue("researcher", "agent", 600)

    http = sh.create_mcp_http_client(headers={"Authorization": f"Bearer {token}"})
    transport = sh.streamable_http_client(f"{server.url}/mcp", http_client=http)
    try:
        async with Client(server=transport, mode="legacy", client_info=Implementation(name="demo", version="1.0")) as client:
            tools_list = await client.list_tools()
            print("Tools offered to this agent:")
            for t in tools_list.tools:
                print(f"  {t.name}")
            print()
            for name, args in [
                ("web-search", {"query": "capability security"}),
                ("web-fetch", {"url": "https://arxiv.org/abs/2401.00001"}),
                ("database-read", {"table": "customers"}),
                ("agent-delegate", {"to": "writer", "action": "docs.write", "arguments": {"title": "Summary"}}),
            ]:
                result = await client.call_tool(name, args)
                meta = (result.meta or {}).get("capgate", {})
                verdict = "ERROR" if result.is_error else "OK"
                print(f"  {name:<16} {verdict:<6} {(meta.get('reason_code') or meta.get('decision') or ''):<20} {result.content[0].text[:60]}")
    finally:
        server.stop()


if __name__ == "__main__":
    asyncio.run(main())
