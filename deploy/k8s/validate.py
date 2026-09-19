#!/usr/bin/env python3
"""Static invariant checks for the Kubernetes deployment.

Renders (via `kubectl kustomize deploy/k8s`) are schema-validated by kubeconform;
this script asserts the *security* properties that schema validation cannot — the
same guarantees the Docker adversarial suite enforces at runtime, checked here on
the manifests so a regression (e.g. someone mounting a harness secret into the
agent pod) fails CI before anything is deployed:

  * the agent pod runs under the gVisor RuntimeClass;
  * the agent mounts no Secret other than its own short-lived token;
  * the agent pod/container securityContext is fully locked down;
  * the agent does not auto-mount a service-account token;
  * a default-deny NetworkPolicy exists and the agent's egress is restricted to
    the proxy alone.

Usage: python deploy/k8s/validate.py <rendered-manifests.yaml>
"""

from __future__ import annotations

import sys

import yaml

AGENT_TOKEN_SECRET = "agent-token"
HARNESS_SECRETS = {"harness-signing-key", "harness-token-keyring", "tool-credential"}


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def load(path: str) -> list[dict]:
    with open(path) as fh:
        return [d for d in yaml.safe_load_all(fh) if d]


def pod_template(doc: dict) -> dict:
    return doc["spec"]["template"]["spec"]


def check_agent(docs: list[dict]) -> None:
    jobs = [d for d in docs if d.get("kind") == "Job" and d["metadata"]["name"] == "agent"]
    if not jobs:
        fail("no agent Job found")
    spec = pod_template(jobs[0])

    if spec.get("runtimeClassName") != "gvisor":
        fail(f"agent must set runtimeClassName: gvisor (got {spec.get('runtimeClassName')!r})")

    if spec.get("automountServiceAccountToken") is not False:
        fail("agent must set automountServiceAccountToken: false")

    # Only the agent-token Secret may be mounted; never a harness secret.
    secret_vols = {v["name"]: v["secret"]["secretName"] for v in spec.get("volumes", []) if "secret" in v}
    mounted = set(secret_vols.values())
    if mounted != {AGENT_TOKEN_SECRET}:
        fail(f"agent may mount only the {AGENT_TOKEN_SECRET!r} Secret, got {sorted(mounted)}")
    if mounted & HARNESS_SECRETS:
        fail(f"agent mounts harness secret(s): {sorted(mounted & HARNESS_SECRETS)}")

    pod_sc = spec.get("securityContext", {})
    if pod_sc.get("runAsNonRoot") is not True:
        fail("agent pod securityContext must set runAsNonRoot: true")
    if pod_sc.get("seccompProfile", {}).get("type") != "RuntimeDefault":
        fail("agent pod must use the RuntimeDefault seccomp profile")

    for c in spec["containers"]:
        sc = c.get("securityContext", {})
        if sc.get("allowPrivilegeEscalation") is not False:
            fail(f"agent container {c['name']} must set allowPrivilegeEscalation: false")
        if sc.get("readOnlyRootFilesystem") is not True:
            fail(f"agent container {c['name']} must set readOnlyRootFilesystem: true")
        if sc.get("capabilities", {}).get("drop") != ["ALL"]:
            fail(f"agent container {c['name']} must drop ALL capabilities")


def check_network(docs: list[dict]) -> None:
    nps = {d["metadata"]["name"]: d for d in docs if d.get("kind") == "NetworkPolicy"}
    deny = nps.get("default-deny-all")
    if not deny or set(deny["spec"].get("policyTypes", [])) != {"Ingress", "Egress"}:
        fail("a default-deny-all NetworkPolicy (Ingress+Egress, empty podSelector) is required")
    if deny["spec"].get("podSelector") not in ({}, None):
        fail("default-deny-all must select all pods (empty podSelector)")

    agent = nps.get("agent-egress-proxy-only")
    if not agent:
        fail("NetworkPolicy 'agent-egress-proxy-only' is required")
    if agent["spec"]["podSelector"].get("matchLabels", {}).get("app") != "agent":
        fail("agent NetworkPolicy must select app: agent")
    egress = agent["spec"].get("egress", [])
    # every egress peer must be the proxy, and every port 8080
    for rule in egress:
        for peer in rule.get("to", []):
            if peer.get("podSelector", {}).get("matchLabels", {}).get("app") != "proxy":
                fail(f"agent egress allows a non-proxy peer: {peer}")
        for port in rule.get("ports", []):
            if port.get("port") != 8080:
                fail(f"agent egress allows a non-8080 port: {port}")
    if not egress:
        fail("agent NetworkPolicy must define an egress rule (to the proxy)")


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: validate.py <rendered-manifests.yaml>")
    docs = load(sys.argv[1])
    check_agent(docs)
    check_network(docs)
    print(f"OK: {len(docs)} objects; agent isolation invariants hold")


if __name__ == "__main__":
    main()
