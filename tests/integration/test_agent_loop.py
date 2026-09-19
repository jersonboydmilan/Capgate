"""A model-driven agent loop runs through Capgate: every tool call is authorized.

Uses the deterministic ScriptedModel over the real loop and a real MCP gateway,
so it proves the integration (model -> gateway -> authorize -> permit -> executor)
without a network model. The AnthropicModel path is the same loop with a real
Claude model swapped in.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

from capgate import AuditLog, Harness, TaskContract
from capgate.identity import Keyring, TokenAuthority
from capgate.mcp import MCPGateway
from capgate.server import HarnessServer
from helpers import SpyTool

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("capgate_agent_loop", ROOT / "examples/agent_loop/loop.py")
loop = importlib.util.module_from_spec(_spec)
sys.modules["capgate_agent_loop"] = loop
_spec.loader.exec_module(loop)


def contract():
    return TaskContract.from_dict({
        "contract_id": "research-v1", "goal": "g", "max_steps": 50, "approvers": ["editor"],
        "agents": {"researcher": {"capabilities": {
            "web.search": "allow",
            "docs.publish": "escalate",
            "database.write": "deny",
        }}},
    })


@pytest.fixture
def stack():
    spies = {n: SpyTool({"ok": n}) for n in ("web.search", "docs.publish", "database.write")}
    harness = Harness(contract(), tools=spies, audit=AuditLog())
    authority = TokenAuthority(Keyring.generate())
    server = HarnessServer(harness, authority).start()
    MCPGateway(server.api)
    token = authority.issue("researcher", "agent", 300)
    yield harness, server, token, spies
    server.stop()


def test_loop_lists_only_granted_tools(stack):
    harness, server, token, _ = stack
    gw = loop.GatewayClient(f"{server.url}/mcp", token)
    gw.connect()
    names = {t["name"] for t in gw.list_tools()}
    assert {"web-search", "docs-publish"} <= names   # allow + escalate offered
    assert "database-write" not in names             # deny is not offered


def test_agent_loop_authorizes_every_tool_call(stack):
    harness, server, token, spies = stack
    gw = loop.GatewayClient(f"{server.url}/mcp", token)
    model = loop.ScriptedModel([
        [("web-search", {"query": "x"})],                              # allowed
        [("database-write", {"table": "t"})],                          # denied (model still tried it)
        [("docs-publish", {"title": "F"})],                            # escalated
        [("web-search", {"query": "y"})],                              # allowed
    ])
    transcript = run = loop.run_agent_loop(model, gw, system="s", goal="g", max_turns=8)
    tools = [s for s in transcript if s.kind == "tool"]

    outcomes = {s.call.name: s.outcome for s in tools}
    assert outcomes["web-search"].is_error is False and outcomes["web-search"].harness["decision"] == "allow"
    assert outcomes["database-write"].is_error is True and outcomes["database-write"].harness["reason_code"] == "EXPLICITLY_DENIED"
    assert outcomes["docs-publish"].is_error is True and outcomes["docs-publish"].harness["approval_id"]

    # ground truth: only the allowed action reached the real tool
    assert spies["web.search"].calls == [{"query": "x"}, {"query": "y"}]
    assert spies["database.write"].calls == []
    assert spies["docs.publish"].calls == []
    # and the harness recorded a decision for each proposal, denied included
    decisions = {(r["action"], r["decision"]) for r in harness.audit.query(event="decision")}
    assert ("web.search", "allow") in decisions
    assert ("database.write", "deny") in decisions
    assert ("docs.publish", "escalate") in decisions


def test_denied_tool_call_is_reported_to_the_model_not_executed(stack):
    """The model receives the denial as a tool error it can react to, and nothing runs."""
    harness, server, token, spies = stack
    gw = loop.GatewayClient(f"{server.url}/mcp", token)

    class Reactor:
        """Tries a denied call; only proceeds to an allowed call after seeing the error."""
        def __init__(self):
            self.saw_denial = False

        def start(self, system, tools, goal):
            return loop.Turn("try the db", [loop.ToolCall("c1", "database-write", {"table": "t"})])

        def step(self, outcomes):
            if outcomes and outcomes[0].is_error and outcomes[0].harness.get("reason_code") == "EXPLICITLY_DENIED":
                self.saw_denial = True
                return loop.Turn("ok, search instead", [loop.ToolCall("c2", "web-search", {"query": "z"})])
            return loop.Turn("done", [])

    model = Reactor()
    loop.run_agent_loop(model, gw, system="s", goal="g")
    assert model.saw_denial
    assert spies["database.write"].calls == [] and spies["web.search"].calls == [{"query": "z"}]
