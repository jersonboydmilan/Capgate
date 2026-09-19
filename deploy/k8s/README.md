# Kubernetes deployment

The same authority boundary and isolation as the Docker deployment
(`deploy/docker-compose.yml`), expressed in Kubernetes:

| Docker deployment | Kubernetes equivalent |
|---|---|
| `internal` networks + netguard iptables allowlist | `NetworkPolicy` (default-deny + per-component edges) |
| agent under gVisor (`runtime: runsc`) | agent pod `runtimeClassName: gvisor` |
| secrets in volumes the agent never mounts | `Secret`s mounted only into harness/tools; agent mounts only its token |
| `cap_drop: ALL`, `no-new-privileges`, read-only rootfs, non-root | pod/container `securityContext` + namespace Pod Security "restricted" |
| nginx edge in front of uvicorn | `proxy` Deployment + Service |
| one-shot `compose run agent` | agent `Job` |

```
agent (gVisor) ──► proxy:8080 ──► harness:8080 ──► tools:9100
   mounts only its token        holds the signing key + keyring   holds the tool credential
```

## Files

- `namespace.yaml` — namespace with Pod Security Admission `enforce: restricted`.
- `runtimeclass.yaml` — `RuntimeClass gvisor` (handler `runsc`).
- `harness.yaml`, `tools.yaml`, `proxy.yaml` — Deployments + Services.
- `agent.yaml` — the untrusted agent as a `Job` (gVisor, no secret mounts).
- `networkpolicies.yaml` — default-deny plus the four documented edges.
- `kustomization.yaml` — assembles the above and builds the harness/nginx
  ConfigMaps from the Docker deployment's real config files (one source of truth).
- `bootstrap.sh` — generates the secrets and the agent token into the cluster.
- `validate.py` — static invariant checks (see CI, below).

## Prerequisites

- A cluster whose CNI **enforces NetworkPolicy egress** — Calico, Cilium, etc.
  kindnet (kind's default) and some managed defaults do **not**; without
  enforcement the agent's egress restriction is not applied.
- gVisor on the nodes: `runsc` installed and a containerd `runsc` runtime handler
  configured, so `runtimeClassName: gvisor` schedules. See
  <https://gvisor.dev/docs/user_guide/containerd/quick_start/>. (On GKE, use a
  gVisor node pool — `--sandbox type=gvisor` — and the `gvisor` RuntimeClass is
  provided for you.)
- The images available to the cluster: `capgate-harness:local`,
  `capgate-proxy:local`, `capgate-agent:local`. Build them from the Docker
  deployment's Dockerfiles and load/push them (e.g. `kind load docker-image …`,
  or push to a registry and edit the image names).

## Deploy

Because the ConfigMaps are built from files a directory up
(`deploy/config`, `deploy/proxy`), render with the permissive load restrictor and
pipe to apply (`kubectl apply -k` does not accept the flag):

```bash
kubectl kustomize --load-restrictor LoadRestrictionsNone deploy/k8s | kubectl apply -f -
sh deploy/k8s/bootstrap.sh            # create the Secrets + agent token
kubectl -n capgate rollout status deploy/harness
kubectl -n capgate logs job/agent -f  # the compromised agent, contained
kubectl -n capgate logs deploy/harness # one audit line per decision/execution
```

The agent `Job` runs the same compromised agent as the Docker demo. It reaches
only the proxy, cannot read any harness secret, runs under gVisor, and every
side effect it attempts is authorized (or denied) by the harness first.

## Validation (CI)

`validate.py` asserts the security-critical invariants on the rendered manifests —
the static equivalent of the Docker adversarial suite:

- the agent pod runs under the `gvisor` RuntimeClass;
- the agent mounts **only** its own token Secret, never a harness secret;
- the agent's pod/container `securityContext` is fully locked down and it does
  not auto-mount a service-account token;
- a default-deny `NetworkPolicy` exists and the agent's egress is restricted to
  the proxy on 8080.

```bash
kubectl kustomize --load-restrictor LoadRestrictionsNone deploy/k8s > /tmp/capgate-k8s.yaml
kubeconform -strict -summary /tmp/capgate-k8s.yaml   # schema validation
python deploy/k8s/validate.py /tmp/capgate-k8s.yaml  # invariant checks
```

The `k8s` CI job runs exactly this on every dispatch/nightly. A **live**
end-to-end run (kind + a NetworkPolicy-enforcing CNI + gVisor, running the agent
Job and asserting the same ground truth) is the next step; the manifests and
`validate.py` are the foundation for it. Until then, the runtime adversarial
guarantee is demonstrated by the gVisor Docker job (`pytest -m gvisor`), and the
Kubernetes manifests are schema- and invariant-checked here.
