#!/usr/bin/env python3
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


PATTERN = re.compile(r"^nvidia-dkms-[0-9]+(?:-[a-z0-9]+)*$")


def main() -> int:
    destination = Path(sys.argv[1]).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    names = subprocess.run(
        ["apt-cache", "pkgnames"],
        check=True, text=True, capture_output=True,
    ).stdout.splitlines()
    candidates: list[str] = []
    for package in sorted({name for name in names if PATTERN.fullmatch(name)}):
        policy = subprocess.run(
            ["apt-cache", "policy", package],
            check=False, text=True, capture_output=True,
        ).stdout
        if re.search(r"^\s*Candidate:\s*(?!\(none\))\S+", policy, re.MULTILINE):
            candidates.append(package)
    if not candidates:
        print("No optional NVIDIA DKMS companion packages are available.")
        return 0
    subprocess.run(["apt-get", "download", *candidates], cwd=destination, check=True)
    print(f"Downloaded {len(candidates)} optional NVIDIA DKMS companion packages.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
