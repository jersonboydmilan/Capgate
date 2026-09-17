# Reference isolated deployment

A compromised agent that ignores the SDK can open a TCP connection to exactly
one place: the edge proxy, `proxy:8080`, which forwards only the documented API
to the harness. It holds one short-lived token and cannot read the
harness's secrets. The only way anything happens in the world is
`authorize → signed permit → executor`.

```
deploy/
  docker-compose.yml     services, networks, volumes, hardening
  harness/Dockerfile     harness + tool-service image
  agent/Dockerfile       agent image: Python, harness_client, malicious_agent.py — nothing else
  agent/malicious_agent.py → examples/adversarial-agent/malicious_agent.py
  network/               netguard: iptables egress allowlist for the agent
  proxy/                 nginx edge: sizes, timeouts, allowed paths/methods, X-Real-IP
  config/                contracts + server config, mounted read-only into the harness only
  demo.py                automated attack + 69 checks
  fetch_artifacts.py     verified, host-side download of offline build inputs
```

## Run it by hand

```bash
cd deploy
python fetch_artifacts.py                   # once
docker compose --profile agent build        # all images — `up --build harness` would NOT rebuild netguard/agent
docker compose up -d harness                # bootstrap secrets, tool service, harness
docker compose run --rm agent               # compromised agent with a fresh 15-minute token
docker compose logs harness                 # one audit line per decision / execution
docker compose exec tools cat /data/ledger.jsonl   # ground truth: side effects at the real tool
curl http://127.0.0.1:8080/v1/health        # inspection port, host loopback only
docker compose --profile agent down -v
```

Rebuild all images after changing anything under `deploy/` or `src/`: a stale
netguard image (for example one built during a mutation test) silently runs
without its rules. The agent's log reports that as `UNEXPECTED SUCCESS` and the
automated tests always rebuild every image, but a hand run only uses what you built.

The agent writes a readable `[malicious] … → blocked as expected / UNEXPECTED SUCCESS`
log to stderr and its structured results to stdout.

Expected: every bypass attempt fails, with a connection error (the network) or
a 401/403/404 (the harness). `logs harness` shows one `execution … outcome=succeeded`
line (`web.search`), and the ledger holds exactly that one side effect.

## Run it as tests

```bash
python deploy/demo.py                        # build, attack, print 69 checks, tear down
pytest -m docker                             # tests/adversarial/isolation/test_network_boundary.py
```

## Topology

```
 agent_net (internal)          api_net (internal)         tool_net (internal)
┌───────────────────────┐    ┌──────────────────────┐    ┌──────────────────────┐
│ netguard + agent ─────┼─► proxy (nginx) ──────────┼─► harness (uvicorn) ───┼─► tools
│   tcp proxy:8080 only │    │  sizes, timeouts,     │    │  policy, executor,   │  (tool credential)
│ misattached-tool      │    │  allowed paths only   │    │  secrets, state      │
└───────────────────────┘    └──────────────────────┘    └──────────┬───────────┘
                                                                     └─ edge (harness only): 127.0.0.1:8080 on the host
```

- **nginx** terminates agent connections: 10s header/body timeouts, 1MB body,
  8KB header lines, per-address request and connection limits, `GET`/`POST` on
  the documented paths only, `X-Real-IP` overwritten with the real peer.
- **uvicorn** (h11) serves the harness API behind it and believes `X-Real-IP`
  only from `api_net` (`MANDATE_API_SUBNET`), for per-client limits and audit.

## What the agent can and cannot reach

| Destination | Agent | Harness | Enforced by |
|---|---|---|---|
| `proxy:8080` (documented API only) | ✅ | — | the one iptables ACCEPT rule; nginx path/method allowlist |
| The harness directly | ❌ | — | not on `agent_net` (name does not resolve) |
| Other proxy ports | ❌ | — | iptables |
| Tool service (by name or IP) | ❌ | ✅ | agent not on `tool_net`: no route (and iptables) |
| A tool wrongly attached to the agent's network | ❌ | — | iptables (topology alone would allow it) |
| Public internet, IPv4/IPv6, external DNS | ❌ | ✅ via `edge` | `internal` network: no gateway (and iptables) |
| Host, `host.docker.internal`, Docker bridge | ❌ | loopback port only | `internal` network (and iptables) |
| Raw sockets | ❌ | — | all capabilities dropped |
| Harness secrets, audit log, state DB | ❌ | ✅ | volumes never mounted into the agent; separate PID namespace |
| Docker socket | ❌ | ❌ | not mounted anywhere |

## Where secrets live

| Secret | Created by | Mounted into | Never in |
|---|---|---|---|
| permit signing key, token keyring | `bootstrap` (inside the `harness-secrets` volume, mode 0400) | harness (ro), agent-token issuer (ro) | agent, tools, environment variables |
| tool credential | `bootstrap` (`tool-credential` volume) | harness (ro), tools (ro) | agent, environment variables |
| agent token (15 min) | `agent-token` issuer, before each `run agent` | agent (ro, `/run/agent/token`) | — it is the agent's own |

Secrets are files in volumes, not environment variables: environment variables are
inherited by child processes and shown by `docker inspect`. Nothing secret is
baked into an image or generated on the host.

## What is enforced, and the evidence

| Claim | Evidence (`demo.py` check / test) |
|---|---|
| The agent can open a socket only to `harness:8080` | `NET *`; `test_agent_can_only_talk_to_harness` lists every probe that connected: only `harness_api` |
| The iptables layer does work of its own | `NET misattached tool…` is `refused`; with netguard's rules disabled it becomes `connected` (verified by mutation) |
| Direct tool calls fail at the network, not just at auth | `HTTP direct call…` = `0` (no connection), `test_agent_cannot_reach_real_tool_directly` |
| The agent cannot read secret material | `SEC *`: every secret path is `not_found`; a scan of all readable files, the environment and `/proc/*/{environ,cmdline}` finds none of the protected secrets by SHA-256; its positive control finds the agent's own token |
| The agent's credential is limited | `CRED *`: tampered, forged, expired, revoked and over-long tokens → 401 |
| No privilege, read-only filesystem | `PROC *`: 0 capabilities, UID 20001, only its own PID visible, write → `EROFS` |
| The HTTP edge bounds and normalises requests | `EDGE *`: slow headers cut at 10s, 1.5MB body → 413 at the proxy, unknown path → 404, `TRACE` → 405, spoofed `X-Real-IP` ignored (audit records the agent's real address), harness served by uvicorn |
| Side effects happen only through the harness | `PATH *`: tool ledger == `["/web.search"]`, decoy ledger empty, audit chain intact, the harness log's only successful execution is `web.search`, and it correlates to the single `allow` decision |

## Not claimed

- **Kernel or container-runtime escape.** Namespaces and seccomp don't stop a kernel
  exploit. Use gVisor (`runtime: runsc`) or a microVM runtime (Kata, Firecracker) for
  that; nothing else in the compose file needs to change.
- **A trusted Docker host.** Anyone with access to the Docker daemon can read every volume.
- **Harness bugs.** The harness API is the agent's attack surface; a policy or parser
  bug there is reachable.
- **Other orchestrators.** A Kubernetes equivalent is a NetworkPolicy allowing egress only
  to the harness Service, secrets not mounted into the agent pod, and a `securityContext`
  with all capabilities dropped and a read-only root filesystem. That is not tested here.

## Offline builds

Images build from the local `alpine` image with no network access at build time
(this host's firewall blocks Docker's egress). `fetch_artifacts.py` downloads on the host:

- CPython from python-build-standalone (musl), checked against the release `SHA256SUMS`
- PyYAML sdist (pure-Python part), checked against PyPI's SHA-256
- the `iptables` Alpine packages; `apk` verifies their signatures against the base image's keys

Pin the base image with `BASE_IMAGE=alpine@sha256:…`.
