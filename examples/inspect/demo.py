"""A live local stack for `capgate inspect`: harness API, some agent traffic, pending escalations.

    python examples/inspect/demo.py            # then open the printed URL

Starts, in one process:
  * a harness HTTP API on a free port, using examples/simulation/contract.yaml
  * agent traffic through it: allowed, denied, escalated and forged-credential requests
  * capgate inspect, wired to that harness with an approver token for `alice`

Everything lives in a temporary directory printed at start-up.
"""

from __future__ import annotations

import argparse
import json
import tempfile
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

from capgate import AuditLog, Harness, load_contracts
from capgate.identity import Keyring, TokenAuthority
from capgate.inspect import InspectServer
from capgate.server import HarnessServer
from capgate.state import SQLiteStateStore
from capgate.tools import EchoTool

ROOT = Path(__file__).resolve().parents[2]


def call(url: str, token: str, path: str, body: dict) -> tuple[int, dict]:
    req = urllib.request.Request(url + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-open", action="store_true")
    args = parser.parse_args()

    work = Path(tempfile.mkdtemp(prefix="capgate-inspect-"))
    contracts = load_contracts(ROOT / "examples/simulation/contract.yaml")
    tools = {name: EchoTool() for name in ("web.search", "web.fetch", "docs.write")}
    harness = Harness(contracts, tools=tools, audit=AuditLog(work / "audit.jsonl"), state=SQLiteStateStore(work / "state.db"))
    keyring = Keyring.generate()
    keyring.save(work / "keys.json")
    authority = TokenAuthority(work / "keys.json", max_ttl_seconds=3600)
    api = HarnessServer(harness, authority).start()

    researcher = authority.issue("researcher", "agent", 3600)
    (work / "alice.token").write_text(authority.issue("alice", "approver", 3600))

    traffic = [
        ("/v1/actions", {"action": "web.search", "arguments": {"query": "capability-based security"}}),
        ("/v1/actions", {"action": "web.fetch", "arguments": {"url": "https://arxiv.org/abs/2401.00001"}}),
        ("/v1/actions", {"action": "web.fetch", "arguments": {"url": "http://169.254.169.254/latest/meta-data/"}}),
        ("/v1/actions", {"action": "database.read", "arguments": {"table": "customers"}}),
        ("/v1/actions", {"agent_id": "writer", "action": "docs.write", "arguments": {"title": "impersonated"}}),
        ("/v1/delegations", {"to": "writer", "action": "docs.write", "arguments": {"title": "Summary of findings"}}),
        ("/v1/delegations", {"to": "writer", "action": "docs.write", "arguments": {"title": "Draft press release"}}),
    ]
    for path, body in traffic:
        call(api.url, researcher, path, body)
    call(api.url, researcher[:-4] + "AAAA", "/v1/actions", {"action": "web.search", "arguments": {}})  # tampered token

    inspect = InspectServer(
        tasks=[ROOT / "examples/simulation/task.yaml", ROOT / "examples/delegation-boundary/task.yaml", ROOT / "examples/basic/task.yaml"],
        audit_path=work / "audit.jsonl",
        harness_url=api.url,
        approver_token=lambda: (work / "alice.token").read_text().strip(),
        port=args.port,
    )
    print(f"harness API      {api.url}")
    print(f"working dir      {work}")
    print(f"capgate inspect  {inspect.url}   (Ctrl-C to stop)", flush=True)
    if not args.no_open:
        webbrowser.open(inspect.url)
    try:
        inspect.server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        api.stop()


if __name__ == "__main__":
    main()
