"""Run the SPIFFE-aware mTLS edge demo: a client-cert agent through the edge to the harness.

    python deploy/mtls/demo.py            # mint certs, build, run the agent, report, tear down
    python deploy/mtls/demo.py --json
    python deploy/mtls/demo.py --keep

Mints a CA + edge server cert + agent client cert (SPIFFE URI SAN) on the host
with `cryptography` (the `mtls` extra), issues the agent a workload-bound token,
and drives deploy/mtls/docker-compose.yml. Requires Docker with Compose v2.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
COMPOSE = HERE / "docker-compose.yml"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

SPIFFE_ID = "spiffe://capgate.test/agent/researcher"


def docker_available() -> bool:
    try:
        subprocess.run(["docker", "info"], capture_output=True, check=True, timeout=20)
        subprocess.run(["docker", "compose", "version"], capture_output=True, check=True, timeout=20)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def mint_certs(certs_dir: Path) -> str:
    """CA + edge server cert + agent client cert (SPIFFE SAN). Returns the agent thumbprint."""
    from certs import make_ca, make_workload  # tests/certs.py
    from capgate.workload import thumbprint_from_der

    ca_key, ca_cert, ca_pem = make_ca(certs_dir, "capgate-mtls-ca")
    make_workload(certs_dir, ca_key, ca_cert, spiffe_id=None, filename="edge")
    _, _, agent_der = make_workload(certs_dir, ca_key, ca_cert, spiffe_id=SPIFFE_ID, filename="agent")
    # the compose mounts one dir; name files as each service expects
    (certs_dir / "ca.pem").write_bytes(Path(ca_pem).read_bytes())
    for src, dst in [("agent.pem", "agent.pem"), ("agent.key", "agent.key")]:
        pass  # make_workload already wrote agent.pem/agent.key and edge.pem/edge.key
    for f in certs_dir.iterdir():
        f.chmod(0o444)
    return thumbprint_from_der(agent_der)


def run(project: str, certs_dir: Path, thumbprint: str) -> dict:
    env = {
        **os.environ,
        "CAPGATE_PREFIX": project,
        "CAPGATE_CERTS_DIR": str(certs_dir),
        "CAPGATE_EDGE_SUBNET": f"172.30.{__import__('random').randint(1, 240)}.0/24",
        "AGENT_SPIFFE_ID": SPIFFE_ID,
        "AGENT_THUMBPRINT": thumbprint,
    }

    def compose(*args, check=True, timeout=900):
        proc = subprocess.run(["docker", "compose", "-p", project, "-f", str(COMPOSE), *args],
                              cwd=HERE, env=env, capture_output=True, text=True, timeout=timeout)
        if check and proc.returncode != 0:
            raise RuntimeError(f"{' '.join(args)} failed:\n{proc.stdout}\n{proc.stderr}")
        return proc

    try:
        compose("--profile", "agent", "build")
    except RuntimeError:
        compose("--profile", "agent", "build")
    compose("up", "-d", "--wait", "mtls-edge")
    # issue the bound token to stdout and write it into the shared certs dir on the host
    # (avoids a container writing to a host-owned bind mount)
    token = compose("run", "--rm", "--no-deps", "-T", "harness", "python3", "-m", "capgate.cli",
                    "token", "issue", "--keyring", "/secrets/token_keyring", "--sub", "researcher",
                    "--role", "agent", "--ttl", "15m", "--max-ttl", "15m",
                    "--bind-spiffe", SPIFFE_ID, "--bind-thumbprint", thumbprint).stdout.strip().splitlines()[-1]
    token_file = certs_dir / "token"
    token_file.write_text(token)
    token_file.chmod(0o444)
    proc = compose("--profile", "agent", "run", "--rm", "-T", "agent", timeout=300)
    agent = json.loads(proc.stdout.strip().splitlines()[-1])
    ledger = compose("exec", "-T", "tools", "sh", "-c", "cat /data/ledger.jsonl 2>/dev/null || true").stdout
    return {"agent": agent, "side_effects": [json.loads(l) for l in ledger.splitlines() if l.strip()],
            "harness_logs": compose("logs", "--no-log-prefix", "harness").stdout, "compose": compose}


def checks(result: dict) -> list[tuple[str, str, bool]]:
    a, effects = result["agent"], result["side_effects"]
    return [
        ("agent with its SPIFFE cert + bound token -> allowed", str(a["authorized_call"]), a["authorized_call"] == [200, "succeeded"]),
        ("denied action still denied over mTLS", str(a["denied_action"]), a["denied_action"][0] == 403),
        ("forged X-Client-Spiffe-Id header ignored (edge overwrites)", str(a["forged_identity_header"]), a["forged_identity_header"][0] == 200),
        ("no client certificate -> cannot connect", str(a["no_client_cert"]), a["no_client_cert"][0] in ("tls_error", "conn_error")),
        ("only authorized web.search reached the tool (never database.write)", str([e["path"] for e in effects]),
         effects != [] and all(e["path"] == "/web.search" for e in effects)),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    if not docker_available():
        print("docker with compose v2 is required", file=sys.stderr)
        return 2

    project = f"capgate-mtls-{uuid.uuid4().hex[:8]}"
    certs_dir = Path(tempfile.mkdtemp(prefix="capgate-mtls-", dir="/tmp" if sys.platform == "darwin" else None))
    certs_dir.chmod(0o755)
    thumbprint = mint_certs(certs_dir)
    result = None
    try:
        print(f"building and starting the mTLS edge demo ({project})…", file=sys.stderr)
        result = run(project, certs_dir, thumbprint)
    finally:
        if result and not args.keep:
            result["compose"]("--profile", "agent", "down", "-v", "--remove-orphans", check=False)

    rows = checks(result)
    if args.json:
        print(json.dumps({"checks": [{"check": c, "observed": o, "pass": p} for c, o, p in rows], "agent": result["agent"], "side_effects": result["side_effects"]}, indent=2))
    else:
        print("\nCAPGATE — SPIFFE mTLS EDGE\n")
        width = max(len(c) for c, _, _ in rows) + 2
        for c, o, ok in rows:
            print(f"  {'PASS' if ok else 'FAIL'}  {c:<{width}}{o}")
        print(f"\n{sum(ok for _, _, ok in rows)}/{len(rows)} checks passed.")
    return 0 if all(ok for _, _, ok in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
