"""Property-based fuzzing of the agent-facing API, below HTTP framing.

Properties, for any method, path, headers and body an agent can send:
  * no unhandled exception (no 500, no server_error audit record);
  * status is one the API documents;
  * a real tool runs only for an authenticated agent whose own contract grants
    that exact action — never for garbage, forged identity or approvers;
  * the audit chain stays valid.
"""

import json

from hypothesis import assume, example, given, strategies as st

from capgate import AuditLog, Harness, TaskContract
from capgate.api import HarnessAPI
from capgate.identity import Keyring, TokenAuthority
from capgate.ratelimit import RateLimitConfig

ALLOWED_STATUSES = {200, 202, 400, 401, 403, 404, 405, 429, 502}
KEYS = ["action", "arguments", "to", "body", "agent_id", "contract_id", "verdict", "note", "jsonrpc", "method", "params", "id"]
ACTIONS = ["web.search", "db.write", "agent.message", "agent.delegate", "harness.approve", "contract.update", "", "Web.Search", "web..search"]
PATHS = ["/v1/actions", "/v1/messages", "/v1/delegations", "/v1/approvals", "/v1/approvals/abc", "/v1/approvals/../../v1/actions",
         "/v1/health", "/mcp", "/", "/v1/actions?x=1", "//v1/actions", "/V1/ACTIONS", "/v1/actions/"]

json_leaf = st.one_of(st.none(), st.booleans(), st.integers(), st.floats(allow_nan=False), st.text(max_size=30),
                      st.sampled_from(ACTIONS), st.sampled_from(["worker", "helper", "alice", "ghost"]))
json_value = st.recursive(json_leaf, lambda c: st.one_of(st.lists(c, max_size=4), st.dictionaries(st.text(max_size=10), c, max_size=4)), max_leaves=12)
json_body = st.dictionaries(st.sampled_from(KEYS), json_value, max_size=6).map(lambda d: json.dumps(d).encode())
raw_body = st.one_of(json_body, st.binary(max_size=200), st.just(b"[]"), st.just(b'{"a":' * 50), st.just(b"\xff\xfe"),
                     st.just(b'{"action": NaN}'), st.just(b'{"action": "web.search", "arguments": {"q": -Infinity}}'), st.just(b'{"a":1}' * 3))


def build():
    calls = []

    def tool(args):
        calls.append(args)
        return "ok"

    contracts = [
        TaskContract.from_dict({"contract_id": "c-worker", "goal": "g", "max_steps": 100_000, "approvers": ["alice"], "agents": {"worker": {"capabilities": {
            "web.search": "allow",
            "db.write": "escalate",
            "agent.message": {"effect": "allow", "constraints": {"allowed_targets": ["helper"]}},
            "agent.delegate": {"effect": "allow", "constraints": {"allowed_targets": ["helper"], "allowed_actions": ["web.search", "db.write"]}},
        }}}}),
        TaskContract.from_dict({"contract_id": "c-helper", "goal": "g", "max_steps": 100_000, "agents": {"helper": {"capabilities": {"web.search": "deny"}}}}),
    ]
    harness = Harness(contracts, tools={"web.search": tool, "db.write": tool}, audit=AuditLog())
    authority = TokenAuthority(Keyring.generate())
    api = HarnessAPI(harness, authority, rate_limit=RateLimitConfig(enabled=False))
    tokens = {
        "worker": authority.issue("worker", "agent", 600),
        "helper": authority.issue("helper", "agent", 600),
        "alice": authority.issue("alice", "approver", 600),
        "ghost": authority.issue("ghost", "agent", 600),
    }
    return api, tokens, calls


API, TOKENS, CALLS = build()


def auth_header(choice, garbage):
    if choice == "none":
        return {}
    if choice == "garbage":
        return {"Authorization": garbage}
    if choice == "mutated":
        t = TOKENS["worker"]
        return {"Authorization": "Bearer " + t[:-3] + garbage[:3]}
    return {"Authorization": f"Bearer {TOKENS[choice]}"}


AGENTS = ["worker", "helper", "alice", "ghost", "admin"]
plausible_args = st.one_of(
    st.dictionaries(st.sampled_from(["q", "url", "table", "row", "to", "action", "arguments"]), json_value, max_size=3),
    json_value,
)
GRANTED_ACTIONS = ["web.search", "web.search", "db.write", "db.write", "agent.message", "agent.delegate"]
structured_body = st.fixed_dictionaries(
    {"action": st.one_of(st.sampled_from(GRANTED_ACTIONS), st.sampled_from(GRANTED_ACTIONS), st.sampled_from(ACTIONS), json_value)},
    optional={
        "arguments": plausible_args,
        "to": st.one_of(st.sampled_from(AGENTS), json_value),
        "body": json_value,
        "agent_id": st.one_of(st.sampled_from(AGENTS), json_value),
        "contract_id": st.one_of(st.sampled_from(["c-worker", "c-helper", "nope"]), json_value),
        "verdict": st.sampled_from(["approve", "reject", "maybe", None]),
        "note": json_value,
    },
).map(lambda d: json.dumps(d).encode())

structured = st.tuples(
    st.just("POST"),
    st.sampled_from(["/v1/actions", "/v1/actions", "/v1/actions", "/v1/messages", "/v1/delegations", "/v1/approvals/PENDING"]),
    st.sampled_from(["worker", "worker", "worker", "helper", "alice", "ghost", "mutated"]),
    st.text(max_size=10),
    structured_body,
    st.just({}),
)
chaotic = st.tuples(
    st.sampled_from(["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "get", "PoSt"]),
    st.one_of(st.sampled_from(PATHS), st.text(max_size=40).map(lambda t: "/" + t)),
    st.sampled_from(["worker", "helper", "alice", "ghost", "none", "garbage", "mutated"]),
    st.text(max_size=60),
    raw_body,
    st.dictionaries(st.sampled_from(["X-Real-IP", "Content-Type", "Mcp-Session-Id", "authorization"]), st.text(max_size=30), max_size=2),
)


@given(request=st.one_of(structured, structured, structured, chaotic))
@example(("POST", "/v1/actions", "worker", "", b'{"action": "web.search", "arguments": {"q": 1}}', {}))
@example(("POST", "/v1/actions", "worker", "", b'{"action": "db.write", "arguments": {"row": 1}}', {}))
@example(("POST", "/v1/approvals/PENDING", "alice", "", b'{"verdict": "approve", "note": "ok"}', {}))
@example(("POST", "/v1/actions", "worker", "", b'{"action": "db.write", "arguments": {"row": 2}}', {}))
@example(("POST", "/v1/approvals/PENDING", "worker", "", b'{"verdict": "approve"}', {}))
@example(("POST", "/v1/actions", "helper", "", b'{"action": "web.search", "agent_id": "worker"}', {}))
@example(("POST", "/v1/delegations", "worker", "", b'{"to": "helper", "action": "web.search", "arguments": {}}', {}))
@example(("POST", "/v1/actions", "ghost", "", b'{"action": "web.search"}', {}))
@example(("POST", "/v1/actions", "mutated", "abc", b'{"action": "web.search"}', {}))
def test_dispatch_never_crashes_and_only_authorized_agents_cause_side_effects(request):
    method, path, who, garbage, body, extra = request
    if "PENDING" in path:
        pending = API.harness.pending_approvals()
        path = f"/v1/approvals/{pending[0].approval_id}" if pending else "/v1/approvals/none"
    headers = {**extra, **auth_header(who, garbage)}
    before_calls = len(CALLS)
    before_errors = len(API.harness.audit.query(event="server_error"))
    response = API.dispatch(method, path, headers, body if method.upper() == "POST" else None, "10.0.0.1")

    assert response.status in ALLOWED_STATUSES, (response.status, response.body)
    assert len(API.harness.audit.query(event="server_error")) == before_errors
    json.dumps(response.body, default=str)

    new_calls = len(CALLS) - before_calls
    if new_calls:
        executions = API.harness.audit.query(event="execution")[-new_calls:]
        for record in executions:
            decision = API.harness.audit.query(event="decision", decision_id=record["decision_id"])[-1]
            granted = {("worker", "web.search"): "allow", ("worker", "db.write"): "escalate"}
            assert (record["agent_id"], record["action"]) in granted, record
            if granted[(record["agent_id"], record["action"])] == "escalate":
                assert decision["reason_code"] == "APPROVED_BY_HUMAN" and decision["approved_by"] == "alice", decision
            assert who in ("worker", "alice"), (who, path)


def test_fuzzing_reached_every_outcome():
    """Guard against a vacuous fuzz run: the properties above must have been exercised."""
    audit = API.harness.audit
    assert len(CALLS) >= 2  # direct web.search and the human-approved db.write
    assert audit.query(event="decision", decision="allow")
    assert audit.query(event="decision", decision="deny")
    assert audit.query(event="decision", decision="escalate")
    assert audit.query(event="authentication_failed")
    assert audit.query(event="decision", reason_code="IDENTITY_MISMATCH")


@given(token=st.text(max_size=300))
def test_arbitrary_tokens_never_authenticate(token):
    assume(token not in TOKENS.values())
    agent, approver, failure = API.identify(f"Bearer {token}")
    assert agent is None and approver is None and failure


@given(position=st.integers(min_value=0, max_value=10_000), replacement=st.characters(codec="ascii"))
def test_single_character_token_mutations_never_authenticate(position, replacement):
    token = TOKENS["worker"]
    i = position % len(token)
    assume(token[i] != replacement)
    mutated = token[:i] + replacement + token[i + 1:]
    agent, _, failure = API.identify(f"Bearer {mutated}")
    # base64url padding bits: a change in the last char of a segment can decode identically; that is not a forgery
    if agent is not None:
        import base64
        prefix, kid, body, sig = token.split(".")
        mp = mutated.split(".")
        assert len(mp) == 4 and base64.urlsafe_b64decode(mp[3] + "==") == base64.urlsafe_b64decode(sig + "==")
        assert base64.urlsafe_b64decode(mp[2] + "==") == base64.urlsafe_b64decode(body + "==")
    else:
        assert failure


def test_audit_chain_survives_the_fuzzing():
    assert API.harness.audit.verify()
