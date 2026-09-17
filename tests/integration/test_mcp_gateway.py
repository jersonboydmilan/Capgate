"""The MCP gateway: a real MCP client's tool calls pass through authorize -> permit -> executor.

Uses the official MCP SDK client against the harness /mcp endpoint, and a real
SDK-built MCP server (tests/fixtures/notes_mcp_server.py) as an upstream tool,
so both edges are exercised against a real implementation, not our own encoder.
"""

import asyncio
import json
import secrets
import sys
import threading
from pathlib import Path

import pytest

from harness import AuditLog, Harness, TaskContract
from harness.identity import Keyring, TokenAuthority
from harness.mcp import MCPGateway, action_to_tool_name, tool_name_to_action
from harness.mcp.upstream import MCPStdioClient, MCPTool, build_mcp_clients
from harness.server import HarnessServer
from helpers import SpyTool

ROOT = Path(__file__).resolve().parents[2]
NOTES_SERVER = ROOT / "tests/fixtures/notes_mcp_server.py"


def contracts():
    return [
        TaskContract.from_dict({"contract_id": "writer-v1", "goal": "write notes", "max_steps": 1000, "approvers": ["editor"], "agents": {
            "scribe": {"capabilities": {
                "notes.write": {"effect": "allow", "constraints": {"max_argument_length": 5000}},
                "notes.read": "allow",
                "notes.publish": "escalate",
                "notes.delete": "deny",
            }}}}),
    ]


# ---- gateway unit-level (in-process, no HTTP) -----------------------------------------

@pytest.fixture
def gateway_pair():
    from harness.api import HarnessAPI
    from harness.ratelimit import RateLimitConfig

    calls = {"write": [], "publish": []}
    tools = {
        "notes.write": lambda a: calls["write"].append(a) or {"_mcp": {"content": [{"type": "text", "text": "ok"}], "structuredContent": {"saved": a["title"]}}},
        "notes.read": lambda a: {"_mcp": {"content": [{"type": "text", "text": "note body"}]}},
        "notes.publish": lambda a: calls["publish"].append(a) or "published",
    }
    harness = Harness(contracts(), tools=tools, audit=AuditLog())
    authority = TokenAuthority(Keyring.generate())
    api = HarnessAPI(harness, authority, rate_limit=RateLimitConfig(enabled=False))
    MCPGateway(api)
    return api, authority, harness, calls


def rpc(api, token, method, params=None, request_id=1):
    body = json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}).encode()
    resp = api.dispatch("POST", "/mcp", {"Authorization": f"Bearer {token}"}, body, "10.0.0.1")
    return resp.status, json.loads(resp.encode()) if not resp.empty else None


def test_tool_name_mapping_is_reversible():
    for action in ["web.search", "notes.write", "a.b.c", "agent.delegate"]:
        assert tool_name_to_action(action_to_tool_name(action)) == action
    assert tool_name_to_action("../etc") is None and tool_name_to_action("Web-Search") is None


def test_initialize_and_tools_list_reflect_the_contract(gateway_pair):
    api, authority, _, _ = gateway_pair
    token = authority.issue("scribe", "agent", 600)
    status, reply = rpc(api, token, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "x", "version": "1"}})
    assert status == 200 and reply["result"]["protocolVersion"] == "2025-06-18"
    assert "scribe" in reply["result"]["instructions"]

    _, reply = rpc(api, token, "tools/list")
    tools = {t["name"]: t for t in reply["result"]["tools"]}
    assert "notes-write" in tools and "notes-read" in tools and "notes-publish" in tools
    assert "notes-delete" not in tools  # deny is not offered
    assert "harness-approval_status" in tools
    assert "human approval" in tools["notes-publish"]["description"].lower()


def test_allowed_call_executes_once(gateway_pair):
    api, authority, harness, calls = gateway_pair
    token = authority.issue("scribe", "agent", 600)
    _, reply = rpc(api, token, "tools/call", {"name": "notes-write", "arguments": {"title": "T", "text": "body"}})
    result = reply["result"]
    assert result["isError"] is False
    assert result["structuredContent"]["saved"] == "T"
    assert result["_meta"]["harness"]["decision"] == "allow"
    assert calls["write"] == [{"title": "T", "text": "body"}]


def test_denied_call_is_a_tool_error_not_a_protocol_error(gateway_pair):
    api, authority, harness, calls = gateway_pair
    token = authority.issue("scribe", "agent", 600)
    status, reply = rpc(api, token, "tools/call", {"name": "notes-delete", "arguments": {"title": "T"}})
    assert status == 200 and "error" not in reply           # JSON-RPC success…
    assert reply["result"]["isError"] is True               # …carrying a tool error
    assert reply["result"]["_meta"]["harness"]["reason_code"] == "EXPLICITLY_DENIED"
    assert harness.audit.query(event="decision", action="notes.delete", decision="deny")


def test_unknown_tool_is_denied_by_default_and_audited(gateway_pair):
    api, authority, harness, _ = gateway_pair
    token = authority.issue("scribe", "agent", 600)
    _, reply = rpc(api, token, "tools/call", {"name": "shell-exec", "arguments": {"cmd": "rm -rf /"}})
    assert reply["result"]["isError"] is True
    assert reply["result"]["_meta"]["harness"]["reason_code"] == "TOOL_NOT_ALLOWED"


def test_escalated_call_returns_approval_id_and_does_not_execute(gateway_pair):
    api, authority, harness, calls = gateway_pair
    token = authority.issue("scribe", "agent", 600)
    _, reply = rpc(api, token, "tools/call", {"name": "notes-publish", "arguments": {"title": "T"}})
    meta = reply["result"]["_meta"]["harness"]
    assert reply["result"]["isError"] is True and meta["approval_id"]
    assert calls["publish"] == []
    _, status_reply = rpc(api, token, "tools/call", {"name": "harness-approval_status", "arguments": {"approval_id": meta["approval_id"]}})
    assert json.loads(status_reply["result"]["content"][0]["text"])["status"] == "pending"


def test_protocol_error_handling(gateway_pair):
    api, authority, _, _ = gateway_pair
    token = authority.issue("scribe", "agent", 600)
    # notification (no id) -> 202 no body
    resp = api.dispatch("POST", "/mcp", {"Authorization": f"Bearer {token}"}, b'{"jsonrpc":"2.0","method":"notifications/initialized"}', "1.2.3.4")
    assert resp.status == 202 and resp.empty
    # unknown method
    _, reply = rpc(api, token, "tools/nonexistent")
    assert reply["error"]["code"] == -32601
    # malformed JSON
    resp = api.dispatch("POST", "/mcp", {"Authorization": f"Bearer {token}"}, b"{not json", "1.2.3.4")
    assert json.loads(resp.encode())["error"]["code"] == -32700
    # batch rejected
    resp = api.dispatch("POST", "/mcp", {"Authorization": f"Bearer {token}"}, b'[{"jsonrpc":"2.0","id":1,"method":"ping"}]', "1.2.3.4")
    assert json.loads(resp.encode())["error"]["code"] == -32600
    # bad protocol version header
    resp = api.dispatch("POST", "/mcp", {"Authorization": f"Bearer {token}", "MCP-Protocol-Version": "1999-01-01"}, b'{"jsonrpc":"2.0","id":1,"method":"ping"}', "1.2.3.4")
    assert resp.status == 400


def test_mcp_requires_authentication(gateway_pair):
    api, _, _, _ = gateway_pair
    resp = api.dispatch("POST", "/mcp", {}, b'{"jsonrpc":"2.0","id":1,"method":"initialize"}', "1.2.3.4")
    assert resp.status == 401
    resp = api.dispatch("POST", "/mcp", {"Authorization": "Bearer garbage"}, b'{"jsonrpc":"2.0","id":1,"method":"ping"}', "1.2.3.4")
    assert resp.status == 401


# ---- upstream MCP server (real SDK server over stdio) --------------------------------

@pytest.fixture
def notes_client(tmp_path):
    ledger = tmp_path / "notes.jsonl"
    client = MCPStdioClient([sys.executable, str(NOTES_SERVER)], env={"NOTES_TOKEN": "s3cret", "NOTES_LEDGER": str(ledger)}, name="notes")
    yield client, ledger
    client.close()


def test_upstream_mcp_tool_executes_and_exposes_schema(notes_client):
    client, ledger = notes_client
    tool = MCPTool(client, "write_note")
    meta = tool.metadata()
    assert meta and meta["name"] == "write_note" and "title" in meta["inputSchema"]["properties"]
    out = tool({"title": "hello", "text": "world"})
    assert "_mcp" in out and out["_mcp"]["content"][0]["text"] == "saved hello"
    assert [json.loads(l) for l in ledger.read_text().splitlines()] == [{"op": "write", "title": "hello", "text": "world"}]


def test_end_to_end_denied_upstream_call_leaves_no_side_effect(tmp_path):
    ledger = tmp_path / "notes.jsonl"
    clients = build_mcp_clients({"notes": {"command": [sys.executable, str(NOTES_SERVER)], "env": {"NOTES_TOKEN": {"value": "s3cret"}, "NOTES_LEDGER": {"value": str(ledger)}}}})
    from harness.tools import build_tools
    tools = build_tools({"notes.write": {"type": "mcp", "server": "notes", "tool": "write_note"}, "notes.delete": {"type": "mcp", "server": "notes", "tool": "delete_note"}},
                        mcp_servers={"notes": {"command": [sys.executable, str(NOTES_SERVER)], "env": {"NOTES_TOKEN": {"value": "s3cret"}, "NOTES_LEDGER": {"value": str(ledger)}}}})
    try:
        harness = Harness(contracts(), tools=tools, audit=AuditLog())
        ok = harness.run("scribe", "notes.write", {"title": "kept", "text": "body"})
        denied = harness.authorize("scribe", "notes.delete", {"title": "kept"})
        assert ok[1].ok and denied.denied
        effects = [json.loads(l) for l in ledger.read_text().splitlines()]
        assert effects == [{"op": "write", "title": "kept", "text": "body"}]  # the deny never reached the server
    finally:
        for c in tools.values():
            getattr(c, "client", None) and c.client.close()


# ---- over real HTTP with the official MCP SDK client ---------------------------------

def test_official_mcp_client_over_http(tmp_path):
    ledger = tmp_path / "notes.jsonl"
    server_cfg = {"notes": {"command": [sys.executable, str(NOTES_SERVER)], "env": {"NOTES_TOKEN": {"value": "s3cret"}, "NOTES_LEDGER": {"value": str(ledger)}}}}
    from harness.tools import build_tools
    tools = build_tools(
        {"notes.write": {"type": "mcp", "server": "notes", "tool": "write_note"}, "notes.publish": {"type": "mcp", "server": "notes", "tool": "publish_note"}},
        mcp_servers=server_cfg,
    )
    # publish is escalate in the contract; map it onto the upstream tool
    cs = contracts()
    harness = Harness(cs, tools=tools, audit=AuditLog())
    authority = TokenAuthority(Keyring.generate())
    server = HarnessServer(harness, authority).start()
    MCPGateway(server.api)
    token = authority.issue("scribe", "agent", 600)

    async def drive():
        from mcp import Client
        import mcp.client.streamable_http as sh

        http_client = sh.create_mcp_http_client(headers={"Authorization": f"Bearer {token}"})
        transport = sh.streamable_http_client(f"{server.url}/mcp", http_client=http_client)
        async with Client(server=transport, mode="legacy", client_info=_impl()) as client:
            listed = await client.list_tools()
            names = {t.name for t in listed.tools}
            assert {"notes-write", "notes-publish", "harness-approval_status"} <= names
            good = await client.call_tool("notes-write", {"title": "T", "text": "hello"})
            assert good.is_error is False
            denied = await client.call_tool("notes-delete", {"title": "T"})
            assert denied.is_error is True and "DENIED" in denied.content[0].text.upper()
            escalated = await client.call_tool("notes-publish", {"title": "T"})
            assert escalated.is_error is True and "approval" in escalated.content[0].text.lower()
        return names

    try:
        names = asyncio.run(drive())
    finally:
        server.stop()
        for c in tools.values():
            getattr(c, "client", None) and c.client.close()
    effects = [json.loads(l) for l in ledger.read_text().splitlines()]
    assert effects == [{"op": "write", "title": "T", "text": "hello"}]  # only the allowed call; publish waited for approval


def _impl():
    from mcp.types import Implementation

    return Implementation(name="test-client", version="1.0")


def test_stdio_bridge_forwards_to_the_gateway(tmp_path):
    """harness mcp-bridge: a stdio-only client reaches /mcp with the agent's own token."""
    import io

    from harness.mcp.bridge import run_bridge

    harness = Harness(contracts(), tools={"notes.write": SpyTool({"_mcp": {"content": [{"type": "text", "text": "ok"}]}})}, audit=AuditLog())
    authority = TokenAuthority(Keyring.generate())
    server = HarnessServer(harness, authority).start()
    MCPGateway(server.api)
    token_path = tmp_path / "agent.token"
    token_path.write_text(authority.issue("scribe", "agent", 600))

    stdin = io.StringIO(
        '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}\n'
        '{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
        '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"notes-write","arguments":{"title":"T","text":"b"}}}\n'
        '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"notes-delete","arguments":{"title":"T"}}}\n'
    )
    stdout = io.StringIO()
    try:
        from harness.mcp.bridge import token_from_file

        run_bridge(f"{server.url}/mcp", token_from_file(str(token_path)), stdin=stdin, stdout=stdout)
    finally:
        server.stop()
    replies = [json.loads(line) for line in stdout.getvalue().splitlines()]
    assert replies[0]["result"]["protocolVersion"] == "2025-11-25"       # initialize
    assert replies[1]["result"]["isError"] is False                       # write allowed
    assert replies[2]["result"]["_meta"]["harness"]["reason_code"] == "EXPLICITLY_DENIED"  # delete denied
    # the notification produced no reply line
    assert len(replies) == 3
