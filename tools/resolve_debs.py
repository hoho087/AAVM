#!/usr/bin/env python3
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


def dependencies(packages: list[str]) -> list[str]:
    command = [
        "apt-cache", "depends", "--recurse", "--no-recommends", "--no-suggests",
        "--no-conflicts", "--no-breaks", "--no-replaces", "--no-enhances", *packages,
    ]
    result = subprocess.run(command, text=True, capture_output=True, check=True)
    found = set(packages)
    for line in result.stdout.splitlines():
        match = re.match(r"^\s*(?:Pre)?Depends:\s+([^\s]+)", line)
        if match:
            package = match.group(1).strip("<>").split(":", 1)[0]
            if package and not package.startswith("<"):
                found.add(package)
        elif line and not line[0].isspace() and re.fullmatch(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?", line):
            found.add(line.split(":", 1)[0])
    available = []
    for package in sorted(found):
        policy = subprocess.run(["apt-cache", "policy", package], text=True, capture_output=True)
        if re.search(r"Candidate:\s+(?!\(none\))\S+", policy.stdout):
            available.append(package)
    return available


def main() -> int:
    destination = Path(sys.argv[1]).resolve()
    packages = sys.argv[2:]
    destination.mkdir(parents=True, exist_ok=True)
    resolved = dependencies(packages)
    (destination / "packages.txt").write_text("\n".join(resolved) + "\n", encoding="utf-8")
    print(f"Downloading {len(resolved)} DEB packages...")
    # apt-get download is rootless and accepts a batch of package names.
    subprocess.run(["apt-get", "download", *resolved], cwd=destination, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
