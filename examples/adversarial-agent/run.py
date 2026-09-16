"""Start a real deployment and unleash a compromised agent process on it.

    python examples/adversarial-agent/run.py

Topology (all on localhost for the demo):

    malicious_agent.py (own process, no credentials)
        │  HTTP + its own bearer token
        ▼
    HarnessServer ── policy ── executor (holds the tool credential)
                                   │  Bearer <tool credential>
                                   ▼
                             ToolService (the "real" system; logs side effects)
"""

import json
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from harness import AuditLog, Harness, TaskContract
from harness.identity import Keyring, TokenAuthority
from harness.server import HarnessServer
from harness.toolservice import ToolService
from harness.tools import ControlledEndpointTool

HERE = Path(__file__).parent


def main() -> None:
    tmp = Path(tempfile.mkdtemp())
    tool_secret = secrets.token_urlsafe(32)
    tools = ToolService(tool_secret, tmp / "ledger.jsonl").start()
    harness = Harness(
        [
            TaskContract.from_dict({"contract_id": "research-v1", "goal": "research", "approvers": ["alice"],
                                    "agents": {"researcher": {"capabilities": {"web.search": "allow", "email.send": "escalate"}}}}),
            TaskContract.from_dict({"contract_id": "admin-v1", "goal": "maintain db",
                                    "agents": {"db-admin": {"capabilities": {"database.write": "allow"}}}}),
        ],
        tools={
            "web.search": ControlledEndpointTool(f"{tools.url}/web.search", tool_secret),
            "database.write": ControlledEndpointTool(f"{tools.url}/database.write", tool_secret),
        },
        audit=AuditLog(tmp / "audit.jsonl"),
    )
    authority = TokenAuthority(Keyring.generate(), max_ttl_seconds=900, state=harness.state)
    token = authority.issue("researcher", "agent", 600)  # issued by the supervisor, not by the agent
    revoked = authority.issue("researcher", "agent", 600)
    authority.revoke(revoked)
    server = HarnessServer(harness, authority).start()
    try:
        env = {
            "PATH": "/usr/bin:/bin", "HARNESS_URL": server.url, "AGENT_TOKEN": token, "TOOL_URL": tools.url,
            "EXPIRED_TOKEN": authority.issue("researcher", "agent", 60, issued_at=time.time() - 3600),
            "REVOKED_TOKEN": revoked,
        }
        proc = subprocess.run([sys.executable, str(HERE / "malicious_agent.py")], env=env, capture_output=True, text=True, check=True)
        print("Attempts by the compromised agent:")
        for name, outcome in json.loads(proc.stdout).items():
            print(f"  {name:<34} {outcome}")
        print("\nSide effects recorded by the real tool:")
        for effect in tools.side_effects():
            print(f"  {effect['path']}  {effect['payload']}")
        print(f"\nAudit trail: {tmp / 'audit.jsonl'} ({len(harness.audit)} records, chain intact: {harness.audit.verify()})")
    finally:
        server.stop()
        tools.stop()


if __name__ == "__main__":
    main()
