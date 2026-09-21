# Isolation runtime

Capgate is an *authority* boundary: the agent proposes, the harness authorizes,
the executor acts. That boundary is only as trustworthy as the isolation under
the container that runs untrusted agent code — a kernel escape there sidesteps
every capability check above it. This page describes the isolation the reference
deployment provides and how to strengthen the runtime under it.

## Layers, from the base deployment up

The reference deployment (`deploy/docker-compose.yml`) confines the untrusted
agent with, in order:

1. **Network topology.** Three `internal` Docker networks with no gateway, so the
   agent has no route to the host, the internet, or cloud metadata at layer 3 at
   all. The agent is attached only to `agent_net`, alongside the proxy.
2. **An egress allowlist.** `netguard` owns the agent's network namespace and
   installs an iptables policy of `DROP`, permitting only TCP to `proxy:8080`.
   The agent joins that namespace with every capability dropped, so it cannot
   change the rules.
3. **An HTTP edge.** nginx in front of uvicorn bounds request sizes and timeouts
   and forwards only the documented API paths.
4. **Process hardening.** `cap_drop: ALL`, `no-new-privileges`, a read-only root
   filesystem, a `noexec,nosuid` tmpfs, a pids limit, and a non-root user.
5. **Secret partitioning.** Harness signing keys and tool credentials live in
   volumes the agent never mounts; the agent holds only one short-lived token.

Every one of those is asserted from *inside* a compromised agent by the
adversarial suite (`tests/adversarial/isolation/`, `pytest -m docker`).

## The gap layers 1–5 leave: the shared kernel

All of the above still runs on **one host kernel**, shared with the agent. runc
hardening shrinks what the agent may *ask* the kernel to do, but a kernel-level
exploit in code the agent runs executes against the host kernel directly. For a
multi-tenant host, that is the difference between "an agent exceeded its
contract" (contained, audited) and "an agent owns the box".

## Closing it: a user-space or virtualized kernel

`deploy/gvisor/docker-compose.gvisor.yml` runs the agent under
**[gVisor](https://gvisor.dev)** (`runsc`), an application kernel in user space
that intercepts the container's syscalls. The agent then talks to gVisor's
re-implementation of the Linux ABI, not the host kernel; the host-kernel surface
exposed to the agent shrinks from all of Linux to the narrow set gVisor makes for
itself.

runsc is registered with host-network passthrough (`--network=host`): gVisor
keeps its syscall sandbox while the network path uses the container's real
network namespace — the one netguard owns — so the iptables egress allowlist and
Docker's embedded DNS apply exactly as on runc. The layer gVisor adds is **kernel
isolation**; **network isolation stays with netguard**.

```bash
python deploy/demo.py --gvisor        # build, attack under gVisor, report
```

See [`deploy/gvisor/README.md`](../deploy/gvisor/README.md) to install `runsc`
and for the compose invocation.

### What is tested

The gVisor variant runs the **same** adversarial suite, plus
`tests/adversarial/isolation/test_gvisor_runtime.py`, which additionally asserts:

- the agent container's OCI runtime really is `runsc` — so a silent fall back to
  runc can never pass as "gVisor tested"; and
- netguard's egress allowlist still governs the gVisor container: joined to
  netguard's (runc-owned) network namespace with host-network passthrough, the
  agent still reaches only `proxy:8080` — internet, cloud metadata, the real
  tool, the decoy tool on its own network, and other harness ports all stay
  blocked.

The `gvisor` CI job (on demand and nightly) installs `runsc` and runs
`pytest -m gvisor` on a Linux runner.

### Kata / Firecracker

gVisor is the runtime CI tests because it installs on ordinary Linux runners
without nested virtualization. For hardware-level isolation, the same overlay
pattern points at a VM-based runtime — **Kata Containers** (`runtime:
kata-runtime`) or **Firecracker** (via Kata's Firecracker backend or
`firecracker-containerd`). Both need `/dev/kvm`, which GitHub-hosted runners do
not provide, so they are documented rather than wired into CI. The authority
boundary and the adversarial tests are runtime-independent.

## Kubernetes

`deploy/k8s/` is a kustomize base that mirrors this topology in Kubernetes:

- **`NetworkPolicy`** — default-deny plus the four documented edges
  (`agent → proxy → harness → tools`), the native equivalent of the internal
  networks + netguard allowlist. Needs a CNI that enforces egress (Calico,
  Cilium).
- **`RuntimeClass: gvisor`** on the agent pod — the same kernel isolation as the
  Docker overlay.
- **Secrets** mounted only into harness/tools; the agent pod mounts **only** its
  own short-lived token.
- A locked-down `securityContext` on every pod, plus namespace Pod Security
  Admission `enforce: restricted`.

`deploy/k8s/validate.py` asserts these security invariants on the rendered
manifests — the static equivalent of the Docker adversarial suite: the agent runs
under gVisor, mounts no harness secret, is fully unprivileged, and its egress is
restricted to the proxy. The `k8s` CI job runs `kubeconform` (schema) and that
validator on every push. See [`deploy/k8s/README.md`](../deploy/k8s/README.md).

A **live** end-to-end run backs the static checks: `deploy/k8s-e2e/` and the
`k8s-e2e` CI job stand up a kind cluster with **Calico** (which enforces
NetworkPolicy egress), deploy the stack, and run the real compromised-agent
`Job`, asserting live that the agent reaches only the proxy, reads no harness
secret, runs unprivileged, and produces exactly one authorized side effect. kind
is not a gVisor node, so the overlay drops the gVisor `runtimeClassName`; kernel
isolation stays proven by the Docker `gvisor` job, and on a real cluster you use
a gVisor node pool (e.g. GKE Sandbox), for which the base carries the
`RuntimeClass` and the agent's `runtimeClassName: gvisor`.
