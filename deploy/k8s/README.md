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

The `k8s` CI job runs exactly this on every push.

## Live end-to-end test

`deploy/k8s-e2e/` runs the stack on a real cluster and attacks it. The `k8s-e2e`
CI job (on demand and nightly):

1. creates a **kind** cluster with the default CNI disabled and installs
   **Calico**, which actually *enforces* NetworkPolicy egress (kindnet does not);
2. builds the images and loads them into kind;
3. deploys this base via the `deploy/k8s-e2e` overlay (agent Job suspended),
   bootstraps the Secrets, and waits for harness/tools/proxy;
4. unsuspends the agent Job — the real compromised agent from the Docker demo —
   and, once it finishes, asserts (`deploy/k8s-e2e/assert.py`) on its
   observations plus ground truth (the tool ledger, the harness audit) that:
   the agent reached **only** the proxy (Calico blocked the harness, the tool
   service, the internet and cloud metadata), could not read any harness secret,
   ran unprivileged, and produced exactly one authorized side effect.

This is the live equivalent of `validate.py`'s static checks. The overlay drops
the gVisor `runtimeClassName` because kind is not a gVisor node — kernel
isolation is proven separately by the Docker `gvisor` job; on a real cluster use
a gVisor node pool (e.g. GKE Sandbox), for which the base already carries the
`RuntimeClass` and the agent's `runtimeClassName: gvisor`.

```bash
kind create cluster --config deploy/k8s-e2e/kind.yaml
# install Calico, build+load images (see .github/workflows/ci.yml), then:
kubectl kustomize --load-restrictor LoadRestrictionsNone deploy/k8s-e2e | kubectl apply -f -
sh deploy/k8s/bootstrap.sh capgate
kubectl -n capgate patch job/agent --type=merge -p '{"spec":{"suspend":false}}'
```
