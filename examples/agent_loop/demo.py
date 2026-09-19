"""A real agent loop running through Capgate.

    python examples/agent_loop/demo.py            # deterministic offline model
    ANTHROPIC_API_KEY=... python examples/agent_loop/demo.py --model claude-opus-5   # a real Claude model

Stands up a harness + MCP gateway with a research contract, then runs a
model-driven tool-use loop. Every tool call the model makes is authorized by
Capgate first: allowed calls execute, denied calls come back to the model as a
tool error, and escalated calls come back as an approval id — the model keeps
going with what it's allowed to do. Prints the transcript and the audit trail.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from capgate import AuditLog, Harness, load_contracts
from capgate.identity import Keyring, TokenAuthority
from capgate.mcp import MCPGateway
from capgate.server import HarnessServer
from capgate.tools import EchoTool

from loop import AnthropicModel, GatewayClient, ScriptedModel, run_agent_loop

ROOT = Path(__file__).resolve().parents[2]
SYSTEM = (
    "You are a research agent. Use the available tools to gather information. "
    "Every tool call is authorized by a security harness before it runs; if a call is denied or "
    "needs human approval, do not retry it — continue with what you are allowed to do, then finish."
)
GOAL = ("Research capability-based security for AI agents: search for it and fetch one source. "
        "Also try to write a summary row to the database, and to publish your findings.")

# Offline plan: an allowed search + fetch, a denied db write, an escalated publish, a final search.
OFFLINE_PLAN = [
    [("web-search", {"query": "capability-based security for AI agents"})],
    [("web-fetch", {"url": "https://arxiv.org/abs/2401.00001"})],
    [("database-write", {"table": "summaries", "row": {"topic": "capgate"}})],   # denied
    [("docs-publish", {"title": "Findings"})],                                    # escalated
    [("web-search", {"query": "confused deputy problem"})],
]


def build_stack():
    contracts = load_contracts(ROOT / "examples/agent_loop/contract.yaml")
    tools = {
        "web.search": EchoTool(),
        "web.fetch": EchoTool(),
        "docs.publish": EchoTool(),
        "database.write": EchoTool(),
    }
    harness = Harness(contracts, tools=tools, audit=AuditLog())
    authority = TokenAuthority(Keyring.generate())
    server = HarnessServer(harness, authority).start()
    MCPGateway(server.api)
    token = authority.issue("researcher", "agent", 900)
    return harness, server, token


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default=os.environ.get("CAPGATE_AGENT_MODEL", "claude-opus-5"))
    parser.add_argument("--max-turns", type=int, default=8)
    args = parser.parse_args()

    harness, server, token = build_stack()
    gateway = GatewayClient(f"{server.url}/mcp", token)
    have_key = bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))
    if have_key:
        model = AnthropicModel(model=args.model)
        print(f"model: {args.model} (real)\n")
    else:
        model = ScriptedModel(OFFLINE_PLAN)
        print("model: scripted offline plan (set ANTHROPIC_API_KEY to drive a real Claude model)\n")

    try:
        transcript = run_agent_loop(model, gateway, system=SYSTEM, goal=GOAL, max_turns=args.max_turns)
    finally:
        server.stop()

    for step in transcript:
        if step.kind == "text":
            if step.text and step.text not in ("working", "done"):
                print(f"  model: {step.text}")
        else:
            m = step.outcome.harness
            if not step.outcome.is_error:
                mark, verdict = "\u2713", "ALLOW"
            elif m.get("approval_id"):
                mark, verdict = "\u23f8", (m.get("reason_code") or "REQUIRES_APPROVAL")
            else:
                mark, verdict = "\u2717", (m.get("reason_code") or "DENIED")
            print(f"  {mark} {step.call.name:<16} {verdict:<20} {step.outcome.text[:70]}")

    executed = [r for r in harness.audit.query(event="execution") if r.get("outcome") == "succeeded"]
    print(f"\nreal tool executions: {[r['action'] for r in executed]}")
    print(f"audit records: {len(harness.audit)} (chain intact: {harness.audit.verify()})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
