"""Load secret material from a file (preferred) or an environment variable.

Files let a deployment mount secrets into exactly the containers that need
them (e.g. Docker/Kubernetes secrets) instead of passing them through
environments that child processes inherit.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping


def read_secret(spec: Mapping[str, Any], prefix: str, label: str, *, base: Path | None = None) -> str:
    """Read `<prefix>_file` or `<prefix>_env` from a config mapping."""
    file_key, env_key = f"{prefix}_file", f"{prefix}_env"
    if spec.get(file_key):
        path = Path(spec[file_key])
        if base is not None and not path.is_absolute():
            path = base / path
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ValueError(f"{label}: cannot read {file_key} ({exc.strerror})") from None
    elif spec.get(env_key):
        value = os.environ.get(spec[env_key], "").strip()
    else:
        raise ValueError(f"{label}: set {file_key} or {env_key}")
    if not value:
        raise ValueError(f"{label}: secret is empty")
    return value
