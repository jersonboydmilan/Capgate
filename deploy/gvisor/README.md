# gVisor (runsc) runtime option

The base deployment (`deploy/docker-compose.yml`) confines the untrusted agent
with the standard runc hardening: every capability dropped, `no-new-privileges`,
a read-only root filesystem, a pids limit, a `noexec` tmpfs, a non-root user, and
an iptables egress allowlist it cannot change. All of that still shares **one
host kernel** with the agent. A kernel-level exploit in code the agent runs would
land on the host.

This overlay closes that gap for the one container that runs untrusted code: it
runs the agent under **[gVisor](https://gvisor.dev)** (`runsc`). gVisor is an
application kernel written in Go that runs in user space and intercepts the
container's syscalls, so the agent talks to gVisor's re-implementation of the
Linux ABI instead of the host kernel. The host-kernel syscall surface exposed to
the agent shrinks from "all of Linux" to the narrow set gVisor itself makes.

**Networking: host-network passthrough.** runsc is registered with
`--network=host`, so gVisor keeps its syscall/kernel sandbox (the Sentry still
intercepts every syscall) while the network path uses the container's real
network namespace — the one netguard owns. netguard's iptables egress allowlist
and Docker's embedded DNS therefore apply to the gVisor container exactly as they
do on runc. The isolation gVisor adds here is **kernel isolation**; **network
isolation stays with netguard**. (gVisor's default user-space netstack does not
proxy Docker's embedded resolver at 127.0.0.11 from a shared netns, so
passthrough is the correct mode for this topology; it does not weaken the
firewall, which lives in the netns, not in gVisor.)

## What still holds (and is tested)

Nothing else about the deployment changes, so the whole adversarial suite runs
against the gVisor variant unchanged, plus one extra module
(`tests/adversarial/isolation/test_gvisor_runtime.py`) that additionally asserts:

- the agent container's OCI runtime really is `runsc` (no silent fall back to
  runc — a fallback would be a false "gVisor tested" claim), and
- the netguard egress allowlist still governs the gVisor container's traffic:
  the agent, now under gVisor, still reaches **only** `proxy:8080` and nothing
  else — internet, cloud metadata, the real tool, the decoy tool on its own
  network, other harness ports all stay blocked.

That second point is the one genuinely new question gVisor raises here: the agent
runs under gVisor's own network stack while joining netguard's (runc-owned)
network namespace. The test is what proves the firewall and the sandboxed
netstack compose correctly.

## Install runsc

gVisor is Linux/amd64 (and arm64) only — it cannot run on macOS or Windows
Docker Desktop. On a Linux host, install from the official GPG-signed APT
repository (see <https://gvisor.dev/docs/user_guide/install/> for the current
instructions and non-APT alternatives):

```bash
# Add gVisor's signed APT repository and install runsc.
curl -fsSL https://gvisor.dev/archive.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
  | sudo tee /etc/apt/sources.list.d/gvisor.list > /dev/null
sudo apt-get update && sudo apt-get install -y runsc

# Register it with the Docker daemon, with host-network passthrough (see below).
sudo runsc install -- --network=host
sudo systemctl reload docker   # or: sudo service docker restart

# Confirm.
docker info --format '{{json .Runtimes}}'    # must contain "runsc"
```

## Run

```bash
cd deploy
python demo.py --gvisor          # build, attack under gVisor, report, tear down
python demo.py --gvisor --keep   # leave the stack running
```

or drive compose directly with both files (see the header of
`docker-compose.gvisor.yml`).

## Other runtimes (Kata, Firecracker)

gVisor is the runtime this repository **tests** because it installs and runs on
ordinary Linux CI runners without nested virtualization. The same overlay pattern
applies to a hardware-virtualized runtime:

- **Kata Containers** — set `runtime: kata-runtime` (or the containerd
  `RuntimeClass`). Each container gets its own lightweight VM and guest kernel.
- **Firecracker** — via Kata's Firecracker backend, or `firecracker-containerd`.

Both need `/dev/kvm` (a bare-metal or nested-virt host); GitHub-hosted runners do
not provide KVM, so they are documented here rather than wired into CI. The
authority boundary and the adversarial tests are runtime-independent: point the
overlay at whichever runtime your hosts provide.
