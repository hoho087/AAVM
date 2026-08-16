#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    root = Path(sys.argv[1]).resolve()
    records = []
    for path in sorted(root.glob("*.deb")):
        control = subprocess.run(
            ["dpkg-deb", "-f", str(path)], text=True, capture_output=True, check=True
        ).stdout.rstrip()
        records.append(
            f"{control}\nFilename: {path.name}\nSize: {path.stat().st_size}\nSHA256: {sha256(path)}\n"
        )
    (root / "Packages").write_text("\n".join(records), encoding="utf-8")
    print(f"Indexed {len(records)} DEB packages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
