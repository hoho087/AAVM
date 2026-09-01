#!/usr/bin/env python3
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


def repository_candidate(package: str) -> str | None:
    """Return the newest version available from an APT repository.

    ``apt-cache policy`` can select a locally installed package with no
    downloadable source, such as a locally built kernel header package.
    ``madison`` lists repository versions only, which is what an offline
    bundle for a clean host must contain.
    """
    result = subprocess.run(
        ["apt-cache", "madison", package], text=True, capture_output=True,
    )
    for line in result.stdout.splitlines():
        fields = [field.strip() for field in line.split("|", 2)]
        if len(fields) == 3 and fields[0].split(":", 1)[0] == package:
            return fields[1]
    return None


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
    unavailable = []
    for package in sorted(found):
        version = repository_candidate(package)
        if version:
            available.append(f"{package}={version}")
        else:
            unavailable.append(package)
    if unavailable:
        print(
            "Skipping locally installed packages without an APT repository "
            f"candidate: {', '.join(unavailable)}",
            file=sys.stderr,
        )
    return available


def main() -> int:
    destination = Path(sys.argv[1]).resolve()
    packages = sys.argv[2:]
    destination.mkdir(parents=True, exist_ok=True)
    resolved = dependencies(packages)
    (destination / "packages.txt").write_text("\n".join(resolved) + "\n", encoding="utf-8")
    if not resolved:
        raise SystemExit(
            "No downloadable APT packages were resolved. "
            "Run 'sudo apt-get update' on this Ubuntu 24.04 preparation host, "
            "then run tools/prepare_offline.sh again."
        )
    print(f"Downloading {len(resolved)} DEB packages...")
    # apt-get download is rootless and accepts a batch of package names.
    subprocess.run(["apt-get", "download", *resolved], cwd=destination, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
