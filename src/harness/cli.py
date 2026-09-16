"""harness — command-line interface.

    harness validate contract.yaml
    harness simulate task.yaml
    harness enforce task.yaml [--audit audit.jsonl] [--approver alice]
    harness audit audit.jsonl [--agent ID] [--decision deny] [--verify]
    harness serve server.yaml
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
from .secretsource import read_secret
from .simulation import TaskError, load_task, render, run_task


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="harness", description="Authority management for autonomous software agents.")
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

    args = parser.parse_args(argv)
    try:
        return {"validate": _validate, "simulate": _run, "enforce": _run, "audit": _audit, "serve": _serve}[args.command](args)
    except (ContractError, TaskError, AuditIntegrityError, ValueError, FileNotFoundError) as exc:
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

    def tokens(section: str) -> dict[str, str]:
        return {p: read_secret(spec or {}, "token", f"{section}.{p}", base=path.parent) for p, spec in (cfg.get(section) or {}).items()}

    audit_path = cfg.get("audit")
    signing_key = None
    if cfg.get("signing_key_file") or cfg.get("signing_key_env"):
        signing_key = read_secret(cfg, "signing_key", "signing_key", base=path.parent).encode()
    harness = Harness(
        contracts,
        tools=build_tools(cfg.get("tools"), base=path.parent),
        audit=AuditLog(path.parent / audit_path if audit_path else None, fsync=True),
        signing_key=signing_key,
        state=SQLiteStateStore(path.parent / cfg["state"]) if cfg.get("state") else None,
    )
    listen = cfg.get("listen") or {}
    server = HarnessServer(harness, tokens("agents"), tokens("approvers"), host=listen.get("host", "127.0.0.1"), port=int(listen.get("port", 8700)))
    print(f"agent harness listening on {server.url} ({len(contracts)} contracts)", flush=True)
    try:
        server.server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
