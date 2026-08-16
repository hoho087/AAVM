from __future__ import annotations

import errno
import json
import os
import platform
import pwd
import shutil
import stat
import tempfile
from pathlib import Path

from .paths import OFFLINE_DIR
from .state import update_host_state
from .util import AppError, Runner, require_root, sha256


def load_manifest() -> dict:
    path = OFFLINE_DIR / "manifest.json"
    if not path.exists():
        raise AppError(f"Offline manifest is missing: {path}\nRun tools/prepare_offline.sh on an online Ubuntu 24.04 amd64 machine.")
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def validate(strict: bool = True) -> list[str]:
    errors: list[str] = []
    try:
        manifest = load_manifest()
    except AppError as exc:
        return [str(exc)]
    os_release = platform.freedesktop_os_release()
    if os_release.get("ID") != "ubuntu" or os_release.get("VERSION_ID") != "24.04":
        errors.append(
            f"Unsupported host: {os_release.get('PRETTY_NAME', 'unknown')}; "
            "this bundle is fixed to Ubuntu 24.04 amd64"
        )
    if platform.machine() != manifest.get("architecture", "amd64").replace("amd64", "x86_64"):
        errors.append(f"Architecture mismatch: host={platform.machine()} bundle={manifest.get('architecture')}")
    for item in manifest.get("files", []):
        path = OFFLINE_DIR / item["path"]
        if not path.is_file():
            errors.append(f"Missing: {item['path']}")
            continue
        if strict and item.get("sha256") and sha256(path) != item["sha256"]:
            errors.append(f"Checksum mismatch: {item['path']}")
    required_dirs = ["debs", "sources/qemu", "sources/edk2", "sources/linux-tkg", "sources/linux"]
    for relative in required_dirs:
        if not (OFFLINE_DIR / relative).exists():
            errors.append(f"Missing offline resource directory: {relative}")
    return errors


def install_packages(runner: Runner) -> None:
    require_root()
    errors = validate(strict=True)
    if errors:
        raise AppError("Offline bundle validation failed:\n- " + "\n- ".join(errors))
    deb_dir = OFFLINE_DIR / "debs"
    roots_path = OFFLINE_DIR / "roots.txt"
    if not (deb_dir / "Packages").is_file() or not roots_path.is_file():
        raise AppError("Offline APT index or roots.txt is missing.")
    roots = [line.strip() for line in roots_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    with tempfile.TemporaryDirectory(prefix="kvm-aavm-apt-", dir="/var/tmp") as temporary:
        temp = Path(temporary)
        # APT intentionally drops privileges to _apt for acquisition. A
        # TemporaryDirectory is 0700 by default, which makes it fall back to
        # an unsandboxed root download even when partial/ itself is writable.
        temp.chmod(0o755)
        # Keep the APT-facing repository path ASCII-only. The project may live
        # below a translated desktop directory (for example, 桌面), which is
        # not handled consistently by every version of APT's file transport.
        # Hard links also let _apt read the repository without granting it
        # traversal access to the user's home directory. A copy is used only
        # when the bundle and /var/tmp are on different filesystems.
        repository = temp / "repository"
        repository.mkdir(mode=0o755)
        for package in deb_dir.glob("*.deb"):
            _stage_apt_file(package, repository / package.name)
        _stage_apt_file(deb_dir / "Packages", repository / "Packages")

        source = temp / "offline.sources.list"
        source.write_text(f"deb [trusted=yes] file:{repository} ./\n", encoding="utf-8")
        source.chmod(0o644)
        lists = temp / "lists"
        lists.mkdir(mode=0o755)
        archives = temp / "archives"
        archives.mkdir(mode=0o755)
        _make_apt_partial(lists / "partial")
        _make_apt_partial(archives / "partial")
        options = [
            "-o", f"Dir::Etc::sourcelist={source}", "-o", "Dir::Etc::sourceparts=-",
            "-o", f"Dir::State::lists={lists}", "-o", "Acquire::Languages=none",
            "-o", f"Dir::Cache::archives={archives}",
        ]
        runner.run(["apt-get", *options, "update"])
        # --no-download passes relative Filename values from Packages directly
        # to dpkg. Normal acquisition only copies local DEBs into the private
        # archive cache; the isolated source list prevents network access.
        runner.run(["apt-get", *options, "install", "-y", *roots])
    if "openssh-server" in roots:
        runner.run(["systemctl", "enable", "--now", "ssh.service"])
    update_host_state(offline_packages_installed=True)


def _stage_apt_file(source: Path, destination: Path) -> None:
    readable_by_apt = bool(source.stat().st_mode & stat.S_IROTH)
    if readable_by_apt:
        try:
            os.link(source, destination)
            return
        except OSError as exc:
            if exc.errno not in {errno.EXDEV, errno.EPERM, errno.EACCES}:
                raise
    shutil.copyfile(source, destination)
    destination.chmod(0o644)


def _make_apt_partial(path: Path) -> None:
    path.mkdir(mode=0o700)
    apt_uid = pwd.getpwnam("_apt").pw_uid
    os.chown(path, apt_uid, 0)


def print_validation() -> bool:
    errors = validate(strict=True)
    if errors:
        print("離線資源不完整：")
        for error in errors:
            print(f"  - {error}")
        return False
    manifest = load_manifest()
    print(f"離線資源驗證通過：{len(manifest.get('files', []))} files")
    return True
