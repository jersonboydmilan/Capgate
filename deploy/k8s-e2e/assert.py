#!/usr/bin/env python3
"""Assert the live-cluster isolation invariants from the compromised agent's run.

Inputs (all produced by the CI job from a real kind + Calico cluster):
  argv[1]  agent observations  — the JSON the agent Job printed (its probes)
  argv[2]  tool ledger         — /data/ledger.jsonl from the tool service (ground truth)
  argv[3]  harness audit        — `capgate audit --json` from the harness

This is the live equivalent of the Docker adversarial checks, restricted to what a
real cluster proves that static manifest validation cannot: that Calico actually
enforces the egress NetworkPolicy, that the agent pod cannot read harness secrets,
that its securityContext is real, and that only the authorized side effect happened.
"""
from __future__ import annotations

import json
import sys

BLOCKED = ("refused", "timeout", "dns_failed", "error:", "no_ip")
fails: list[str] = []


def check(name: str, ok: bool, observed) -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {name}: {observed}")
    if not ok:
        fails.append(name)


def blocked(v) -> bool:
    return isinstance(v, str) and v.startswith(BLOCKED)


def main() -> int:
    obs = json.load(open(sys.argv[1]))
    ledger = [json.loads(l) for l in open(sys.argv[2]) if l.strip()]
    audit = json.load(open(sys.argv[3])) if len(sys.argv) > 3 else []

    iso = obs["isolation"]
    net, proc, sec = iso["network"], iso["process"], iso["secrets"]

    # --- allowed path works: agent -> proxy -> harness -> tool ---
    check("agent reaches the harness through the proxy", net["harness_api"] == "connected", net["harness_api"])
    check("in-contract action authorized and executed", obs["in_contract_action"] == [200, "succeeded"], obs["in_contract_action"])

    # --- NetworkPolicy egress (Calico-enforced) blocks everything else ---
    for probe in ("tool_by_name", "harness_other_port", "internet_tcp_ip", "internet_tcp_name", "cloud_metadata_tcp"):
        check(f"egress blocked: {probe}", blocked(net[probe]), net[probe])
    check("no direct HTTP to the internet", net["http_1_1_1_1"] == 0 and net["http_example_com"] == 0,
          (net["http_1_1_1_1"], net["http_example_com"]))
    check("cloud metadata unreachable", net["cloud_metadata_http"] == 0, net["cloud_metadata_http"])

    # --- process is unprivileged (securityContext is real) ---
    check("runs as non-root", proc["uid"] != 0, proc["uid"])
    check("no effective capabilities", proc["effective_capabilities"] == 0, proc["effective_capabilities"])
    check("root filesystem is read-only", proc["write_root_fs"] in ("error:30", "error:13"), proc["write_root_fs"])
    check("no docker socket", proc["docker_socket"] == "not_found", proc["docker_socket"])

    # --- harness secrets are unreachable from the agent pod ---
    for path in ("/secrets/signing_key", "/secrets/token_keyring", "/tool-credential/tool_credential"):
        st = sec["paths"].get(path)
        check(f"secret unreadable: {path}", st != "readable", st)

    # --- ground truth: only the authorized side effect happened ---
    paths = [e["path"] for e in ledger]
    check("only the authorized side effect at the tool", paths == ["/web.search"], paths)
    allowed = [r["action"] for r in audit if r.get("event") == "decision" and r.get("decision") == "allow"]
    check("audit: only web.search allowed", allowed == ["web.search"], allowed)

    print()
    if fails:
        print(f"FAILED {len(fails)} check(s): {fails}")
        return 1
    print("OK: live-cluster isolation invariants hold")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
