"""capgate — command-line interface.

    capgate validate contract.yaml
    capgate simulate task.yaml
    capgate enforce task.yaml [--audit audit.jsonl] [--approver alice]
    capgate audit audit.jsonl [--agent ID] [--decision deny] [--verify]
    capgate serve server.yaml
    capgate token keygen  --keyring keys.json            # create, or rotate to a new active key
    capgate token retire  --keyring keys.json --kid KID
    capgate token issue   --keyring keys.json --sub researcher --role agent --ttl 15m
    capgate token revoke  --keyring keys.json --state state.db --token TOKEN
    capgate inspect [--task task.yaml ...] [--audit audit.jsonl] [--harness-url URL --approver-token-file F]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from .audit import AuditIntegrityError, AuditLog, load_audit
from .contract import ContractError, load_contracts
from .core import Harness, Mode
from .identity import Keyring, TokenAuthority, TokenError
from .secretsource import read_secret
from .simulation import TaskError, load_task, render, run_task


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="capgate", description="Authority management for autonomous software agents.")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("validate", help="validate one or more contract files")
    p.add_argument("contracts", nargs="+")

    for name, help_text in (("simulate", "dry-run a task: decisions only, nothing executes"), ("enforce", "run a task with real enforcement and execution")):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("task")
        p.add_argument("--audit", help="write the audit trail to this JSONL file")
        p.add_argument("--json", action="store_true", help="machine-readable output")
        p.add_argument("-v", "--verbose", action="store_true", help="show decision details")
        p.add_argument("--fail-on", default="", help="comma list of decisions that make the exit code 1 (deny,escalate)")
        if name == "enforce":
            p.add_argument("--approver", help="approver id; prompts interactively for escalations")

    p = sub.add_parser("audit", help="inspect an audit trail")
    p.add_argument("path")
    p.add_argument("--agent")
    p.add_argument("--decision", choices=["allow", "deny", "escalate"])
    p.add_argument("--event")
    p.add_argument("--verify", action="store_true", help="only verify the hash chain")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("serve", help="run the harness HTTP boundary")
    p.add_argument("config")
    p.add_argument("--host", help="override listen.host")
    p.add_argument("--port", type=int, help="override listen.port")
    p.add_argument("--transport", choices=["uvicorn", "stdlib"], help="HTTP transport (default: uvicorn if installed)")

    p = sub.add_parser("inspect", help="local web UI: simulation, audit trail, escalations, policy")
    p.add_argument("--task", action="append", default=[], help="task file to offer in the simulation viewer (repeatable)")
    p.add_argument("--audit", help="audit trail to open in the audit browser")
    p.add_argument("--harness-url", help="running harness HTTP API, for the escalations view")
    token_source = p.add_mutually_exclusive_group()
    token_source.add_argument("--approver-token-file", help="file holding an approver token (re-read on every request)")
    token_source.add_argument("--approver-token-env", help="environment variable holding an approver token")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--no-open", action="store_true", help="do not open a browser")

    p = sub.add_parser("mcp-bridge", help="stdio <-> harness /mcp, for MCP clients that only speak stdio")
    p.add_argument("--url", required=True, help="e.g. http://proxy:8080/mcp")
    bridge_token = p.add_mutually_exclusive_group(required=True)
    bridge_token.add_argument("--token-file", help="the agent's token (re-read per request)")
    bridge_token.add_argument("--token-env", help="environment variable holding the agent's token")

    p = sub.add_parser("bootstrap", help="create missing deployment secrets (idempotent)")
    p.add_argument("--secrets-dir", required=True, help="harness-only secrets: signing_key, token_keyring")
    p.add_argument("--tool-credential", required=True, help="file shared by harness and tool service")

    p = sub.add_parser("token", help="manage short-lived credentials")
    tsub = p.add_subparsers(dest="token_command", required=True)
    t = tsub.add_parser("keygen", help="create a keyring, or add a new active key to an existing one")
    t.add_argument("--keyring", required=True)
    t = tsub.add_parser("retire", help="remove a non-active key; its tokens stop verifying")
    t.add_argument("--keyring", required=True)
    t.add_argument("--kid", required=True)
    t = tsub.add_parser("issue", help="issue a token (print to stdout)")
    t.add_argument("--keyring", required=True)
    t.add_argument("--sub", required=True)
    t.add_argument("--role", choices=["agent", "approver"], required=True)
    t.add_argument("--ttl", default="15m", help="e.g. 90s, 15m, 1h (max --max-ttl)")
    t.add_argument("--max-ttl", default="1h")
    t.add_argument("--issued-at", type=float, help=argparse.SUPPRESS)  # tests: mint already-expired tokens
    t.add_argument("--out", help="write the token to this file (mode 0444) instead of stdout")
    t = tsub.add_parser("revoke", help="revoke a token until it expires")
    t.add_argument("--keyring", required=True)
    t.add_argument("--state", required=True)
    t.add_argument("--token", required=True)

    args = parser.parse_args(argv)
    try:
        return {"validate": _validate, "simulate": _run, "enforce": _run, "audit": _audit, "serve": _serve, "token": _token, "bootstrap": _bootstrap, "inspect": _inspect, "mcp-bridge": _mcp_bridge}[args.command](args)
    except (ContractError, TaskError, AuditIntegrityError, ValueError, FileNotFoundError, TokenError) as exc:
        print(f"harness: error: {exc}", file=sys.stderr)
        return 2


def _validate(args) -> int:
    for path in args.contracts:
        for contract in load_contracts(path):
            agents = ", ".join(f"{a} ({len(g.capabilities)} capabilities)" for a, g in contract.agents.items())
            print(f"ok  {contract.contract_id}  {contract.content_hash[:19]}  agents: {agents}")
    return 0


def _run(args) -> int:
    task = load_task(args.task)
    mode = Mode(args.command)
    audit = AuditLog(args.audit) if args.audit else AuditLog()
    approve = None
    approver_id = getattr(args, "approver", None)
    if approver_id and sys.stdin.isatty():
        def approve(result):
            req = result.request
            print(f"\nESCALATION  {req.agent_id} → {req.action} {json.dumps(req.arguments_copy())}")
            print(f"            {result.decision.detail}")
            answer = input(f"Approve as {approver_id}? [y/N] ").strip().lower()
            return (answer in ("y", "yes"), "via CLI")
    report = run_task(task, mode, audit=audit, approve=approve, approver_id=approver_id)

    if args.json:
        print(json.dumps({"mode": mode.value, "task": task.name, "rows": [r.__dict__ for r in report.rows], "summary": dict(report.counts())}, indent=2))
    else:
        print(render(report, stream=sys.stdout, verbose=args.verbose))
        if args.audit:
            print(f"Audit trail: {args.audit}")

    fail_on = {s.strip().upper() for s in args.fail_on.split(",") if s.strip()}
    return 1 if fail_on & set(report.counts()) else 0


def _audit(args) -> int:
    records = load_audit(args.path, verify=True)
    if args.verify:
        print(f"ok  {len(records)} records, hash chain intact")
        return 0
    rows = records
    if args.agent:
        rows = [r for r in rows if r.get("agent_id") == args.agent]
    if args.decision:
        rows = [r for r in rows if r.get("decision") == args.decision]
    if args.event:
        rows = [r for r in rows if r.get("event") == args.event]
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0

    executions = {r["decision_id"]: r.get("outcome") for r in records if r.get("event") in ("execution", "execution_refused") and r.get("decision_id")}
    header = f"{'TIMESTAMP':<27}{'AGENT':<14}{'CONTRACT':<16}{'ACTION':<18}{'POLICY':<30}{'DECISION':<10}{'REASON':<28}OUTCOME"
    print(header)
    print("─" * len(header))
    for r in rows:
        if r.get("event") != "decision":
            continue
        outcome = executions.get(r["decision_id"], r.get("outcome"))
        print(f"{r['timestamp'][:26]:<27}{str(r.get('agent_id'))[:13]:<14}{str(r.get('contract_id'))[:15]:<16}{r.get('action', '')[:17]:<18}{str(r.get('policy_rule'))[:29]:<30}{r.get('decision', ''):<10}{r.get('reason_code', ''):<28}{outcome}")
    return 0


def _serve(args) -> int:
    from .server import HarnessServer
    from .state import SQLiteStateStore
    from .tools import build_tools

    path = Path(args.config)
    cfg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    contracts = [c for source in cfg.get("contracts", []) for c in load_contracts(path.parent / source)]

    audit_path = cfg.get("audit")
    echo = sys.stdout if cfg.get("audit_echo") else None
    signing_key = None
    if cfg.get("signing_key_file") or cfg.get("signing_key_env"):
        signing_key = read_secret(cfg, "signing_key", "signing_key", base=path.parent).encode()
    harness = Harness(
        contracts,
        tools=build_tools(cfg.get("tools"), base=path.parent, mcp_servers=cfg.get("mcp_servers")),
        audit=AuditLog(path.parent / audit_path if audit_path else None, fsync=True, echo=echo),
        signing_key=signing_key,
        state=SQLiteStateStore(path.parent / cfg["state"]) if cfg.get("state") else None,
    )
    identity = cfg.get("identity") or {}
    if not identity.get("keyring_file"):
        raise ValueError("serve config needs identity.keyring_file (see `capgate token keygen`)")
    keyring_path = Path(identity["keyring_file"])
    authority = TokenAuthority(
        keyring_path if keyring_path.is_absolute() else path.parent / keyring_path,
        max_ttl_seconds=int(identity.get("max_ttl_seconds", 3600)),
        state=harness.state,
    )
    listen = cfg.get("listen") or {}
    enable_mcp = cfg.get("mcp", True)
    host = args.host or listen.get("host", "127.0.0.1")
    port = args.port or int(listen.get("port", 8700))
    from .ratelimit import RateLimitConfig

    server = HarnessServer(
        harness, authority, host=host, port=port,
        rate_limit=RateLimitConfig.from_mapping(cfg.get("rate_limit")),
        transport=args.transport or cfg.get("transport"),
        trusted_proxies=_trusted_proxies(cfg),
    )
    if enable_mcp:
        from .mcp import MCPGateway

        MCPGateway(server.api)
    print(f"capgate listening on {server.url} ({len(contracts)} contracts, transport={server.transport}{', mcp=/mcp' if enable_mcp else ''})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def _trusted_proxies(cfg: dict) -> list[str] | None:
    import os

    proxies = list(cfg.get("trusted_proxies") or [])
    env = cfg.get("trusted_proxies_env")
    if env and os.environ.get(env):
        proxies.extend(p.strip() for p in os.environ[env].split(",") if p.strip())
    return proxies or None


def _duration(text: str) -> int:
    units = {"s": 1, "m": 60, "h": 3600}
    if text[-1:] in units:
        return int(text[:-1]) * units[text[-1]]
    return int(text)


def _mcp_bridge(args) -> int:
    import os

    from .mcp.bridge import run_bridge, token_from_file

    token = token_from_file(args.token_file) if args.token_file else (lambda: os.environ.get(args.token_env, ""))
    return run_bridge(args.url, token)


def _inspect(args) -> int:
    import os
    import webbrowser

    from .inspect import InspectServer

    token = None
    if args.approver_token_file:
        token_path = Path(args.approver_token_file)
        token = lambda: token_path.read_text(encoding="utf-8").strip()
    elif args.approver_token_env:
        env = args.approver_token_env
        token = lambda: os.environ.get(env, "")
    if bool(args.harness_url) != bool(token):
        raise ValueError("--harness-url and an approver token must be given together")
    server = InspectServer(tasks=args.task, audit_path=args.audit, harness_url=args.harness_url, approver_token=token, port=args.port)
    print(f"capgate inspect on {server.url}  (local only; Ctrl-C to stop)", flush=True)
    if not args.no_open:
        webbrowser.open(server.url)
    try:
        server.server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def _bootstrap(args) -> int:
    import secrets as _secrets

    secrets_dir = Path(args.secrets_dir)
    secrets_dir.mkdir(parents=True, exist_ok=True)
    wanted = {
        secrets_dir / "signing_key": lambda: _secrets.token_urlsafe(32),
        secrets_dir / "token_keyring": lambda: Keyring.generate().to_json(),
        Path(args.tool_credential): lambda: _secrets.token_urlsafe(32),
    }
    for target, make in wanted.items():
        if target.exists():
            print(f"exists   {target}")
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(target.name + ".tmp")
        tmp.write_text(make())
        tmp.chmod(0o400)
        tmp.replace(target)
        print(f"created  {target}")
    return 0


def _token(args) -> int:
    from .state import SQLiteStateStore

    path = Path(args.keyring)
    if args.token_command == "keygen":
        if path.exists():
            keyring = Keyring.load(path)
            kid = keyring.rotate()
        else:
            keyring = Keyring.generate()
            kid = keyring.active
        keyring.save(path)
        print(kid)
    elif args.token_command == "retire":
        keyring = Keyring.load(path)
        keyring.retire(args.kid)
        keyring.save(path)
        print(f"retired {args.kid}")
    elif args.token_command == "issue":
        authority = TokenAuthority(path, max_ttl_seconds=_duration(args.max_ttl))
        token = authority.issue(args.sub, args.role, _duration(args.ttl), issued_at=args.issued_at)
        if args.out:
            out = Path(args.out)
            tmp = out.with_name(out.name + ".tmp")
            tmp.write_text(token)
            tmp.chmod(0o444)
            tmp.replace(out)
            print(f"issued {args.role} token for {args.sub} -> {out}")
        else:
            print(token)
    elif args.token_command == "revoke":
        authority = TokenAuthority(path, state=SQLiteStateStore(args.state))
        claims = authority.revoke(args.token)
        print(f"revoked {claims.jti} ({claims.role} {claims.sub}) until {claims.exp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
