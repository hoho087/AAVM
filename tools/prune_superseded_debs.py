#!/usr/bin/env python3
"""Remove superseded DEBs so an offline APT repository has one candidate.

Re-running the bundle builder in-place used to retain older security-update
revisions.  APT normally selects the newest revision, but the stale packages
made it easy to publish an internally mixed curl/OpenSSL closure.  Compare
versions with dpkg itself so Debian epochs and revisions keep their native
ordering semantics.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def metadata(path: Path) -> tuple[str, str, str]:
    result = subprocess.run(
        [
            "dpkg-deb", "-W",
            "--showformat=${Package}\\n${Version}\\n${Architecture}\\n",
            str(path),
        ],
        check=True,
        text=True,
        capture_output=True,
    )
    fields = result.stdout.splitlines()
    if len(fields) != 3 or not all(fields):
        raise RuntimeError(f"Cannot read DEB identity: {path}")
    return fields[0], fields[1], fields[2]


def version_is_newer(left: str, right: str) -> bool:
    return subprocess.run(
        ["dpkg", "--compare-versions", left, "gt", right],
        check=False,
    ).returncode == 0


def prune(directory: Path) -> list[Path]:
    newest: dict[tuple[str, str], tuple[str, Path]] = {}
    superseded: list[Path] = []
    for path in sorted(directory.glob("*.deb")):
        package, version, architecture = metadata(path)
        key = package, architecture
        current = newest.get(key)
        if current is None:
            newest[key] = version, path
        elif version_is_newer(version, current[0]):
            superseded.append(current[1])
            newest[key] = version, path
        elif version == current[0]:
            # A previous interrupted download can leave the same package
            # version under two filenames. Keep the lexicographically first
            # artifact so the local repository has one unambiguous candidate.
            superseded.append(path)
        else:
            superseded.append(path)
    for path in sorted(set(superseded)):
        path.unlink()
        print(f"Removed superseded DEB: {path.name}")
    return sorted(set(superseded))


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: prune_superseded_debs.py DEB_DIRECTORY")
    directory = Path(sys.argv[1]).resolve()
    if not directory.is_dir():
        raise SystemExit(f"DEB directory does not exist: {directory}")
    prune(directory)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
