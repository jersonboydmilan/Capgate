"""A real, model-driven agent loop whose tools are Capgate-authorized actions.

The model chooses tool calls; the loop runs each one through Capgate's MCP
gateway, so every action is authorized (allow), refused (deny -> the model gets a
tool error), or held (escalate -> the model gets an approval id) before anything
executes. The loop is provider-agnostic:

  * `AnthropicModel` drives a real Claude model (Messages API tool use) when
    ANTHROPIC_API_KEY / an `ant` profile is available.
  * `ScriptedModel` replays a fixed plan, so the example and its tests run
    offline and deterministically over the *same* loop and the *same* gateway.

The gateway is spoken over MCP Streamable HTTP (JSON-RPC), the same endpoint any
MCP client uses; identity is the bearer token, never anything in the payload.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict[str, Any]


@dataclass
class ToolOutcome:
    id: str
    name: str
    text: str
    is_error: bool
    harness: dict[str, Any] = field(default_factory=dict)  # decision, reason_code, approval_id, …


@dataclass
class Turn:
    text: str
    tool_calls: list[ToolCall]


class Model(Protocol):
    def start(self, system: str, tools: list[dict[str, Any]], goal: str) -> Turn: ...
    def step(self, outcomes: list[ToolOutcome]) -> Turn: ...


# ---- the gateway seen as an MCP tool surface (sync JSON-RPC over HTTP) ----------------

class GatewayClient:
    def __init__(self, mcp_url: str, token: str | Callable[[], str], *, timeout: float = 30.0) -> None:
        self.mcp_url = mcp_url
        self._token = token
        self.timeout = timeout
        self._id = 0
        self._protocol: str | None = None

    def _rpc(self, method: str, params: dict | None = None, *, notify: bool = False) -> dict:
        token = self._token() if callable(self._token) else self._token
        msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        if not notify:
            self._id += 1
            msg["id"] = self._id
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream"}
        if self._protocol and method != "initialize":
            headers["MCP-Protocol-Version"] = self._protocol
        req = urllib.request.Request(self.mcp_url, data=json.dumps(msg).encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"gateway HTTP {exc.code}: {exc.read()[:200]!r}") from None
        if notify or not raw.strip():
            return {}
        reply = json.loads(raw)
        if "error" in reply:
            raise RuntimeError(f"gateway JSON-RPC error: {reply['error']}")
        return reply.get("result", {})

    def connect(self) -> None:
        result = self._rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                          "clientInfo": {"name": "capgate-agent-loop", "version": "1.0"}})
        self._protocol = result.get("protocolVersion")
        self._rpc("notifications/initialized", {}, notify=True)

    def list_tools(self) -> list[dict[str, Any]]:
        tools = self._rpc("tools/list").get("tools", [])
        return [{"name": t["name"], "description": t.get("description", ""), "input_schema": t.get("inputSchema", {"type": "object"})} for t in tools]

    def call_tool(self, call: ToolCall) -> ToolOutcome:
        result = self._rpc("tools/call", {"name": call.name, "arguments": call.input})
        blocks = result.get("content", [])
        text = "\n".join(b.get("text", "") for b in blocks if b.get("type") == "text") or json.dumps(result)
        meta = (result.get("_meta") or {}).get("capgate", {})
        return ToolOutcome(call.id, call.name, text, bool(result.get("isError")), meta)


# ---- models -------------------------------------------------------------------------

class AnthropicModel:
    """Drives a real Claude model over the Messages API tool-use loop."""

    def __init__(self, *, model: str = "claude-opus-5", max_tokens: int = 4096, client: Any = None) -> None:
        import anthropic

        self.client = client or anthropic.Anthropic()
        self.model = model
        self.max_tokens = max_tokens
        self._system = ""
        self._tools: list[dict[str, Any]] = []
        self._messages: list[dict[str, Any]] = []

    def start(self, system: str, tools: list[dict[str, Any]], goal: str) -> Turn:
        self._system = system
        self._tools = [{"name": t["name"], "description": t["description"], "input_schema": t["input_schema"]} for t in tools]
        self._messages = [{"role": "user", "content": goal}]
        return self._respond()

    def step(self, outcomes: list[ToolOutcome]) -> Turn:
        if outcomes:
            self._messages.append({"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": o.id, "content": o.text, "is_error": o.is_error} for o in outcomes
            ]})
        return self._respond()

    def _respond(self) -> Turn:
        resp = self.client.messages.create(model=self.model, max_tokens=self.max_tokens, system=self._system,
                                           tools=self._tools, messages=self._messages)
        self._messages.append({"role": "assistant", "content": resp.content})
        text = "".join(b.text for b in resp.content if b.type == "text")
        calls = [ToolCall(b.id, b.name, dict(b.input)) for b in resp.content if b.type == "tool_use"]
        return Turn(text, calls)


class ScriptedModel:
    """Replays a fixed plan so the loop runs deterministically offline.

    `plan` is a list of turns; each turn is a list of (tool_name, arguments).
    An empty turn (or running past the end) stops the loop.
    """

    def __init__(self, plan: list[list[tuple[str, dict[str, Any]]]], *, narrate: str = "working") -> None:
        self._plan = list(plan)
        self._narrate = narrate
        self._n = 0

    def start(self, system: str, tools: list[dict[str, Any]], goal: str) -> Turn:
        self._available = {t["name"] for t in tools}
        return self._next()

    def step(self, outcomes: list[ToolOutcome]) -> Turn:
        return self._next()

    def _next(self) -> Turn:
        if self._n >= len(self._plan):
            return Turn("done", [])
        turn = self._plan[self._n]
        self._n += 1
        calls = [ToolCall(f"call-{self._n}-{i}", name, args) for i, (name, args) in enumerate(turn)]
        return Turn(self._narrate, calls)


# ---- the loop ------------------------------------------------------------------------

@dataclass
class Step:
    kind: str          # "text" | "tool"
    text: str = ""
    call: ToolCall | None = None
    outcome: ToolOutcome | None = None


def run_agent_loop(model: Model, gateway: GatewayClient, *, system: str, goal: str, max_turns: int = 8) -> list[Step]:
    """Run the model↔gateway loop to completion. Returns the transcript."""
    gateway.connect()
    tools = gateway.list_tools()
    transcript: list[Step] = []
    turn = model.start(system, tools, goal)
    for _ in range(max_turns):
        if turn.text:
            transcript.append(Step("text", text=turn.text))
        if not turn.tool_calls:
            break
        outcomes = []
        for call in turn.tool_calls:
            outcome = gateway.call_tool(call)
            outcomes.append(outcome)
            transcript.append(Step("tool", call=call, outcome=outcome))
        turn = model.step(outcomes)
    return transcript
