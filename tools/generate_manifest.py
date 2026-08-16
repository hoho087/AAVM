#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def git_revision(path: Path) -> str | None:
    git_dir = path / ".git"
    try:
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
        if not head.startswith("ref: "):
            return head
        reference = head.removeprefix("ref: ")
        loose = git_dir / reference
        if loose.exists():
            return loose.read_text(encoding="utf-8").strip()
        for line in (git_dir / "packed-refs").read_text(encoding="utf-8").splitlines():
            if line and not line.startswith("#") and line.endswith(" " + reference):
                return line.split()[0]
    except OSError:
        return None
    return None


def main() -> int:
    root = Path(sys.argv[1]).resolve()
    files = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "manifest.json":
            files.append({"path": str(path.relative_to(root)), "size": path.stat().st_size, "sha256": digest(path)})
    sources = {}
    for name in ("qemu", "edk2", "linux-tkg", "linux"):
        revision = git_revision(root / "sources" / name)
        if revision:
            sources[name] = revision
    manifest = {
        "format": 1, "distribution": "ubuntu", "release": "24.04", "architecture": "amd64",
        "created_at": datetime.now(timezone.utc).isoformat(), "sources": sources, "files": files,
    }
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
