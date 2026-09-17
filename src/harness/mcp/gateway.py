"""MCP gateway: tool calls from any MCP client pass through authorize → permit → executor.

Speaks the MCP Streamable HTTP transport in its stateless, JSON-response form
(no sessions, no server-initiated streams), handshake protocol versions
2025-03-26 through 2025-11-25.

    initialize / notifications/initialized / ping
    tools/list   the caller's granted actions (allow or escalate) as MCP tools
    tools/call   → ActionRequest under the caller's own contract → policy → executor

The MCP client never chooses its identity or contract: both come from the
bearer token checked by HarnessAPI before this code runs. A tool that is not
granted is still accepted as a call and denied by policy, so the attempt is
audited like any other proposal.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

from ..capability import Effect
from ..request import DELEGATE_ACTION, MESSAGE_ACTION
from ..api import Response

if TYPE_CHECKING:
    from ..api import HarnessAPI

SUPPORTED_VERSIONS = ("2025-03-26", "2025-06-18", "2025-11-25")
LATEST_VERSION = SUPPORTED_VERSIONS[-1]
APPROVAL_STATUS_TOOL = "harness-approval_status"
_TOOL_NAME = re.compile(r"^[a-z][a-z0-9_]*(-[a-z][a-z0-9_]*)*$")

PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS = -32700, -32600, -32601, -32602


def action_to_tool_name(action: str) -> str:
    """`web.search` → `web-search`: MCP clients such as Claude only accept [A-Za-z0-9_-] names."""
    return action.replace(".", "-")


def tool_name_to_action(name: str) -> str | None:
    if not isinstance(name, str) or not _TOOL_NAME.match(name):
        return None
    return name.replace("-", ".")  # reversible: action names never contain '-'


class MCPGateway:
    def __init__(self, api: "HarnessAPI", *, server_name: str = "agent-harness", server_version: str = "0.1.0") -> None:
        self.api = api
        self.harness = api.harness
        self.server_info = {"name": server_name, "version": server_version}
        api.add_route("POST", "/mcp", self.handle_post)
        api.add_route("GET", "/mcp", lambda agent, body, headers: Response(405, {"error": "this MCP server does not offer a server-to-client stream"}, {"Allow": "POST"}))

    # -- transport --------------------------------------------------------------------

    def handle_post(self, agent: str, body: bytes, headers: dict[str, str]) -> Response:
        version = headers.get("mcp-protocol-version")
        if version is not None and version not in SUPPORTED_VERSIONS:
            return Response(400, _error(None, INVALID_REQUEST, f"unsupported MCP-Protocol-Version {version!r}"))
        try:
            message = json.loads(body or b"", parse_constant=_reject_constant)
        except (ValueError, UnicodeDecodeError, RecursionError):
            return Response(400, _error(None, PARSE_ERROR, "invalid JSON"))
        if isinstance(message, list):
            return Response(400, _error(None, INVALID_REQUEST, "JSON-RPC batches are not supported"))
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
            if isinstance(message, dict) and message.get("jsonrpc") == "2.0" and ("result" in message or "error" in message):
                return Response(202, None, empty=True)  # a response to a server request we never sent: ignore
            return Response(400, _error(_id(message), INVALID_REQUEST, "expected a JSON-RPC 2.0 request or notification"))

        method, params = message["method"], message.get("params") or {}
        if "id" not in message:  # notification
            return Response(202, None, empty=True)
        request_id = message["id"]
        if not isinstance(request_id, (str, int)) or isinstance(request_id, bool):
            return Response(400, _error(None, INVALID_REQUEST, "id must be a string or integer"))
        if not isinstance(params, dict):
            return Response(200, _error(request_id, INVALID_PARAMS, "params must be an object"))

        handler = {
            "initialize": self._initialize,
            "ping": lambda a, p: {},
            "tools/list": self._tools_list,
            "tools/call": self._tools_call,
        }.get(method)
        if handler is None:
            return Response(200, _error(request_id, METHOD_NOT_FOUND, f"method not found: {method}"))
        try:
            result = handler(agent, params)
        except _ParamsError as exc:
            return Response(200, _error(request_id, INVALID_PARAMS, str(exc)))
        return Response(200, {"jsonrpc": "2.0", "id": request_id, "result": result})

    # -- methods -------------------------------------------------------------------------

    def _initialize(self, agent: str, params: dict) -> dict:
        requested = params.get("protocolVersion")
        contract = self.harness.contract_for(agent)
        return {
            "protocolVersion": requested if requested in SUPPORTED_VERSIONS else LATEST_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": self.server_info,
            "instructions": (
                f"You are '{agent}' acting under contract '{contract.contract_id if contract else '?'}'. "
                "Every tool call is authorized by the agent harness before anything executes. Denied calls return "
                "isError with a reason code; calls that need human approval return an approval_id you can check "
                f"with {APPROVAL_STATUS_TOOL}. Arguments are checked exactly as given."
            ),
        }

    def _tools_list(self, agent: str, params: dict) -> dict:
        contract = self.harness.contract_for(agent)
        tools = []
        if contract:
            for action, cap in sorted(contract.capabilities_for(agent).items()):
                if cap.effect is Effect.DENY:
                    continue
                tools.append(self._describe(contract.contract_id, action, cap))
        tools.append({
            "name": APPROVAL_STATUS_TOOL,
            "description": "Check a pending human approval you received from an escalated tool call.",
            "inputSchema": {"type": "object", "properties": {"approval_id": {"type": "string"}}, "required": ["approval_id"], "additionalProperties": False},
            "annotations": {"readOnlyHint": True, "openWorldHint": False},
        })
        return {"tools": tools}

    def _describe(self, contract_id: str, action: str, cap: Any) -> dict:
        constraints = dict(cap.constraints)
        upstream = self.harness.tool_metadata(action)
        if action == MESSAGE_ACTION:
            schema = {"type": "object", "properties": {"to": {"type": "string", "enum": list(constraints.get("allowed_targets", ()))}, "body": {}}, "required": ["to", "body"]}
            description = "Send a message to another agent. Messages carry data, never authority."
        elif action == DELEGATE_ACTION:
            schema = {"type": "object", "properties": {
                "to": {"type": "string", "enum": list(constraints.get("allowed_targets", ()))},
                "action": {"type": "string", "enum": list(constraints.get("allowed_actions", ()))},
                "arguments": {"type": "object"},
            }, "required": ["to", "action"]}
            description = "Ask another agent to perform an action. It is authorized under that agent's own contract, not yours."
        elif upstream and upstream.get("inputSchema"):
            schema = upstream["inputSchema"]
            description = upstream.get("description") or action
        else:
            allowed = constraints.get("allowed_arguments")
            schema = {"type": "object", "properties": {name: {} for name in (allowed or ())}}
            if allowed is not None:
                schema["additionalProperties"] = False
            if constraints.get("required_arguments"):
                schema["required"] = list(constraints["required_arguments"])
            description = action
        notes = [f"Authorized by harness contract '{contract_id}'."]
        if cap.effect is Effect.ESCALATE:
            notes.append("Requires human approval before it runs.")
        visible = {k: list(v) if isinstance(v, tuple) else v for k, v in constraints.items() if k not in ("allowed_targets", "allowed_actions")}
        if visible:
            notes.append(f"Constraints: {json.dumps(visible, sort_keys=True)}.")
        return {"name": action_to_tool_name(action), "description": f"{description}\n\n{' '.join(notes)}", "inputSchema": schema}

    def _tools_call(self, agent: str, params: dict) -> dict:
        name = params.get("name")
        arguments = params.get("arguments")
        if arguments is None:
            arguments = {}
        if not isinstance(name, str):
            raise _ParamsError("tools/call requires a string 'name'")
        if not isinstance(arguments, dict):
            raise _ParamsError("tools/call 'arguments' must be an object")

        if name == APPROVAL_STATUS_TOOL:
            status, body = self.api.approval_status(agent, str(arguments.get("approval_id", "")))
            return _text_result(body, is_error=status != 200)

        action = tool_name_to_action(name)
        if action is None:
            # still a proposal: record it as malformed rather than silently dropping it
            status, payload = self.api.handle_action(agent, {"action": name, "arguments": arguments})
            return _decision_result(status, payload)
        if action == MESSAGE_ACTION:
            status, payload = self.api.handle_message(agent, {"to": arguments.get("to"), "body": arguments.get("body")})
            return _decision_result(status, payload)
        if action == DELEGATE_ACTION:
            status, payload = self.api.handle_delegation(agent, {"to": arguments.get("to"), "action": arguments.get("action"), "arguments": arguments.get("arguments")})
            return _decision_result(status, payload)
        status, payload = self.api.handle_action(agent, {"action": action, "arguments": arguments})
        return _decision_result(status, payload)


class _ParamsError(ValueError):
    pass


def _decision_result(status: int, payload: dict) -> dict:
    final = payload.get("action") or payload if "delegation" in payload else payload
    harness_meta = {
        "decision": final.get("decision"),
        "reason_code": final.get("reason_code"),
        "decision_id": final.get("decision_id"),
        "contract_id": final.get("contract_id"),
        "approval_id": payload.get("approval_id") or (payload.get("delegation") or {}).get("approval_id"),
    }
    if "delegation" in payload and payload.get("blocked_at"):
        harness_meta["blocked_at"] = payload["blocked_at"]

    if status == 200:
        execution = final.get("execution") or {}
        output = execution.get("output")
        if execution.get("status") == "failed":
            return {"content": [{"type": "text", "text": f"Tool failed after authorization: {execution.get('error')}"}], "isError": True, "_meta": {"harness": harness_meta}}
        if isinstance(output, dict) and "_mcp" in output:  # upstream MCP result: pass through
            result = dict(output["_mcp"])
            result.setdefault("isError", False)  # MCP defaults absent isError to false; make it explicit
            result["_meta"] = {**(result.get("_meta") or {}), "harness": harness_meta}
            return result
        if execution == {} and final.get("decision") == "allow":  # message delivery
            return _text_result({"delivered": True, "decision_id": final.get("decision_id")}, meta=harness_meta)
        return _text_result(output, meta=harness_meta)
    if status == 202:
        approval_id = harness_meta["approval_id"]
        return {
            "content": [{"type": "text", "text": f"Not executed: this call requires human approval. approval_id={approval_id}. Check it with {APPROVAL_STATUS_TOOL}; do not retry the call."}],
            "isError": True,
            "_meta": {"harness": harness_meta},
        }
    reason = harness_meta["reason_code"] or payload.get("error") or "DENIED"
    detail = final.get("detail") or (payload.get("execution") or {}).get("reason") or ""
    where = f" (blocked at {harness_meta['blocked_at']})" if harness_meta.get("blocked_at") else ""
    return {"content": [{"type": "text", "text": f"Denied by the agent harness: {reason}{where}. {detail}".strip()}], "isError": True, "_meta": {"harness": harness_meta}}


def _text_result(value: Any, *, is_error: bool = False, meta: dict | None = None) -> dict:
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    result: dict[str, Any] = {"content": [{"type": "text", "text": text}], "isError": is_error}
    if isinstance(value, dict) and not is_error:
        result["structuredContent"] = value
    if meta:
        result["_meta"] = {"harness": meta}
    return result


def _error(request_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _id(message: Any) -> Any:
    return message.get("id") if isinstance(message, dict) and isinstance(message.get("id"), (str, int)) else None


def _reject_constant(name: str) -> Any:
    raise ValueError(name)
