"""Download build inputs on the host so image builds need no network.

Some hosts block container egress (corporate proxies, Little Snitch, air-gapped
CI). The isolated runtime is therefore built offline from the local `alpine`
base image plus artifacts fetched here and verified:

  * CPython (python-build-standalone, musl) — SHA-256 checked against the release's SHA256SUMS
  * PyYAML (sdist from PyPI)               — SHA-256 checked against PyPI metadata
  * uvicorn, h11, click (wheels from PyPI) — SHA-256 checked against PyPI metadata
  * iptables and nginx .apk packages       — signature checked by `apk` inside the build

    python deploy/fetch_artifacts.py
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
CACHE = HERE / ".cache"

PBS_RELEASE = "20260901"
PYTHON_VERSION = "3.12.14"
PYYAML_VERSION = "6.0.2"
# Pure-Python wheels for the production HTTP transport (verified against PyPI SHA-256).
WHEELS = {"uvicorn": "0.53.0", "h11": "0.16.0", "click": "8.5.0"}
# Alpine packages per image; `apk` verifies signatures during the build.
APK_SETS = {"apk": ("iptables", "ip6tables"), "apk-proxy": ("nginx",)}


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "capgate-fetch"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


def docker(*args: str) -> str:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=True).stdout.strip()


def machine() -> str:
    arch = docker("version", "-f", "{{.Server.Arch}}")
    return {"arm64": "aarch64", "amd64": "x86_64"}.get(arch, arch)


def fetch_python(arch: str) -> None:
    target = CACHE / "python.tar.gz"
    name = f"cpython-{PYTHON_VERSION}+{PBS_RELEASE}-{arch}-unknown-linux-musl-install_only_stripped.tar.gz"
    base = f"https://github.com/astral-sh/python-build-standalone/releases/download/{PBS_RELEASE}"
    sums = dict(line.split()[::-1] for line in fetch(f"{base}/SHA256SUMS").decode().splitlines() if line.strip())
    expected = sums[name]
    if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest() == expected:
        print(f"python    cached  {name}")
        return
    data = fetch(f"{base}/{name.replace('+', '%2B')}")
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise SystemExit(f"python: checksum mismatch ({actual} != {expected})")
    target.write_bytes(data)
    print(f"python    ok      {name}")


def fetch_pyyaml() -> None:
    target = CACHE / "yaml"
    if (target / "__init__.py").exists():
        print("pyyaml    cached")
        return
    meta = json.loads(fetch(f"https://pypi.org/pypi/PyYAML/{PYYAML_VERSION}/json"))
    sdist = next(u for u in meta["urls"] if u["packagetype"] == "sdist")
    data = fetch(sdist["url"])
    if hashlib.sha256(data).hexdigest() != sdist["digests"]["sha256"]:
        raise SystemExit("pyyaml: checksum mismatch")
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        prefix = f"{sdist['filename'][:-len('.tar.gz')]}/lib/yaml/"
        shutil.rmtree(target, ignore_errors=True)
        target.mkdir(parents=True)
        for member in tar.getmembers():
            if member.name.startswith(prefix) and member.isfile():
                (target / member.name[len(prefix):]).write_bytes(tar.extractfile(member).read())
    print(f"pyyaml    ok      {PYYAML_VERSION} (pure Python)")


def fetch_wheels() -> None:
    import zipfile

    target = CACHE / "pylibs"
    stamp = target / ".versions"
    wanted = json.dumps(WHEELS, sort_keys=True)
    if stamp.exists() and stamp.read_text() == wanted:
        print("wheels    cached")
        return
    shutil.rmtree(target, ignore_errors=True)
    target.mkdir(parents=True)
    for name, version in WHEELS.items():
        meta = json.loads(fetch(f"https://pypi.org/pypi/{name}/{version}/json"))
        wheel = next(u for u in meta["urls"] if u["packagetype"] == "bdist_wheel" and u["filename"].endswith("py3-none-any.whl"))
        data = fetch(wheel["url"])
        if hashlib.sha256(data).hexdigest() != wheel["digests"]["sha256"]:
            raise SystemExit(f"{name}: checksum mismatch")
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for member in zf.namelist():
                if ".dist-info/" in member.split("/", 1)[0] + "/" and not member.endswith(("METADATA", "entry_points.txt")):
                    continue
                zf.extract(member, target)
    stamp.write_text(wanted)
    print(f"wheels    ok      {', '.join(f'{k} {v}' for k, v in WHEELS.items())}")


def parse_apkindex(data: bytes) -> dict[str, dict]:
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        text = tar.extractfile("APKINDEX").read().decode()
    packages: dict[str, dict] = {}
    for block in text.split("\n\n"):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if len(line) > 2 and line[1] == ":":
                fields[line[0]] = line[2:]
        if "P" in fields:
            packages[fields["P"]] = fields
    return packages


def fetch_apks(arch: str, directory: str, packages: tuple[str, ...]) -> None:
    target = CACHE / directory
    release = docker("run", "--rm", "alpine:latest", "cat", "/etc/alpine-release")
    installed = set(docker("run", "--rm", "alpine:latest", "sh", "-c", "apk info 2>/dev/null").split())
    branch = "v" + ".".join(release.split(".")[:2])
    repo = f"https://dl-cdn.alpinelinux.org/alpine/{branch}/main/{arch}"
    index = parse_apkindex(fetch(f"{repo}/APKINDEX.tar.gz"))

    providers: dict[str, list[str]] = {}
    for name, fields in index.items():
        providers.setdefault(name, []).append(name)
        for token in fields.get("p", "").split():
            providers.setdefault(token.split("=")[0], []).append(name)

    wanted: list[str] = []
    queue = [p for p in packages if p in index]
    while queue:
        name = queue.pop()
        if name in wanted or name in installed:
            continue
        wanted.append(name)
        for dep in index[name].get("D", "").split():
            if dep.startswith("!"):
                continue
            dep_name = dep.split("=")[0].split(">")[0].split("<")[0].split("~")[0]
            candidates = providers.get(dep_name, [])
            if not candidates or any(c in installed or c in wanted for c in candidates):
                continue  # already satisfied by the base image (e.g. /bin/sh from busybox)
            queue.append(candidates[0])

    shutil.rmtree(target, ignore_errors=True)
    target.mkdir(parents=True)
    for name in sorted(wanted):
        filename = f"{name}-{index[name]['V']}.apk"
        (target / filename).write_bytes(fetch(f"{repo}/{filename}"))
    (target / "RELEASE").write_text(release)
    print(f"{directory:<9} ok      alpine {release}: {', '.join(sorted(wanted))}")


def main() -> int:
    CACHE.mkdir(exist_ok=True)
    arch = machine()
    fetch_python(arch)
    fetch_pyyaml()
    fetch_wheels()
    for directory, packages in APK_SETS.items():
        fetch_apks(arch, directory, packages)
    return 0


if __name__ == "__main__":
    sys.exit(main())
