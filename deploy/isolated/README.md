# Reference isolated runtime

A compromised agent that ignores the SDK can open a TCP connection to exactly
one place: `harness:8700`. It holds no tool credentials and cannot read the
harness's secrets. The only way anything happens in the world is
`authorize → signed permit → executor`.

```bash
python deploy/isolated/demo.py        # build, attack, report, tear down (~1 min)
pytest -m docker                      # the same, as acceptance tests
```

## Topology

```
                 agent_net (internal)                    tool_net (internal)
┌──────────────────────────────────────────┐    ┌────────────────────────────────────┐
│  netguard ─ owns agent netns, iptables   │    │                                    │
│    └ agent (shares netns, 0 capabilities)│    │                                    │
│         │ tcp :8700 only                 │    │                                    │
│         ▼                                │    │                                    │
│      harness ───────────────────────────────────► tools  (requires tool credential) │
│   secrets: tool credential, signing key, │    │  secrets: tool credential          │
│            agent/approver tokens         │    │                                    │
│   volume: audit log                      │    │  volume: side-effect ledger        │
│                                          │    │                                    │
│   misattached-tool (decoy, see below)    │    │                                    │
└──────────────────────────────────────────┘    └────────────────────────────────────┘
          no ports published to the host; neither network has a route out
```

## What is enforced, and by what

| Claim | Mechanism | Evidence (check in `demo.py`) |
|---|---|---|
| The agent can open a socket only to `harness:8700` | (1) agent attached only to `agent_net`, which is `internal` (no gateway); (2) `netguard` installs `iptables`/`ip6tables` OUTPUT policy DROP with a single ACCEPT for `harness:8700`; agent joins that namespace with all capabilities dropped, so it cannot change the rules | `NET *` — tools by name and IP, internet by IP/name/IPv6, UDP DNS, host gateway, Docker bridge, other harness ports, and a tool **misattached to the agent's own network** all fail; only `harness_api` connects |
| The second layer is not decorative | `misattached-tool` sits on `agent_net`, reachable by topology; only netguard blocks it. With netguard's rules disabled, that check fails (verified) | `NET misattached tool…` |
| No raw packets, no privilege | `cap_drop: [ALL]`, `no-new-privileges`, non-root UID, seccomp (Docker default) | `NET raw socket`, `PROC effective capabilities`, `PROC runs as non-root` |
| The agent cannot read secret material | Secrets mounted only into `harness`/`tools`; separate PID namespace; no Docker socket; read-only root filesystem | `SEC read …` for each secret path; a scan of every readable file, the environment and `/proc/*/{environ,cmdline}` for any of the protected secrets (by SHA-256) finds nothing; its positive control finds the agent's own token |
| Side effects happen only through the harness | Tool service requires the executor's credential and records every side effect | `PATH side effects at real tool == ['/web.search']`, decoy ledger empty, audit chain verified, every successful execution correlates to an `allow` decision |

In the network-isolated runtime, the three "direct call to tool endpoint" attempts
fail at the connection (`0`), not with HTTP `401`: the boundary is now the
network, with credential secrecy as a second layer behind it.

## What is not claimed

- **Kernel or container-runtime escape.** A kernel exploit defeats namespaces and
  seccomp. For stronger isolation use gVisor (`runtime: runsc`) or a microVM
  runtime; the compose file needs no other change.
- **The Docker host is trusted.** Anyone with access to the Docker daemon can read
  the secrets.
- **DNS inside the agent namespace.** Docker's embedded resolver answers on
  loopback for container names on `agent_net`. External names do not resolve
  (checked), so it is not an exfiltration path in this configuration.
- **The harness API is the attack surface.** Anything the harness itself does
  wrong (a policy bug, an HTTP parser bug) is reachable by the agent.
- **Deployments other than this one.** Kubernetes equivalents are a
  NetworkPolicy allowing egress only to the harness Service, a separate
  namespace/ServiceAccount without secret access, and `securityContext` with all
  capabilities dropped. Those are not tested here.

## Offline builds

Images are built from the local `alpine` image with no network access at build
time. `fetch_artifacts.py` (run automatically by `demo.py`) downloads on the host:

- CPython from python-build-standalone (musl), checked against the release's `SHA256SUMS`
- PyYAML sdist (pure-Python part), checked against PyPI's SHA-256
- the `iptables` Alpine packages, whose signatures `apk` verifies against the
  base image's keys during the build

This also works where container egress is blocked (a host firewall, a proxy,
air-gapped CI). Set `BASE_IMAGE` to pin a digest.

## Files

| File | Purpose |
|---|---|
| `compose.yaml` | networks, services, secrets, hardening |
| `netguard.sh` | the egress allowlist |
| `Dockerfile.harness` | harness + tool service image |
| `Dockerfile.agent` | agent image: Python and the agent script, nothing else |
| `Dockerfile.netguard` | iptables image |
| `config/` | contracts and server config, mounted read-only into the harness only |
| `demo.py` | generates secrets, runs the attack, prints the checks |
| `fetch_artifacts.py` | host-side, verified download of build inputs |
