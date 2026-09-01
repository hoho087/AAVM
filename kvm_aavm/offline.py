from __future__ import annotations

import errno
import json
import os
import platform
import pwd
import shutil
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .paths import OFFLINE_DIR, PROJECT_DIR, STATE_DIR
from .state import load_host_state, update_host_state
from .util import AppError, Runner, atomic_write, require_root, sha256


SWTPM_SETUP_CONFIG = Path("/etc/swtpm_setup.conf")
SWTPM_LOCALCA_OPTIONS = Path("/etc/swtpm-localca.options")
TPM_SYSFS = Path("/sys/class/tpm/tpm0")
DEFAULT_AMD_FTPM_PCR_BANKS = "sha1,sha256"
AMD_FTPM_PLATFORM_OPTIONS = {
    "--platform-manufacturer": "AMD",
    "--platform-version": "2.0",
    "--platform-model": "fTPM",
}


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
    required_dirs = [
        "debs", "sources/qemu", "sources/edk2", "sources/linux-tkg", "sources/linux",
        "sources/libtpms",
    ]
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
    if "libtpms0" not in roots:
        raise AppError("Offline roots.txt must explicitly include the AMD-profile libtpms0 package.")
    released_holds = _release_managed_update_holds(runner)
    try:
        with _apt_temporary_directory() as temporary:
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
        _install_amd_ftpm_libtpms(runner)
        configure_amd_ftpm_swtpm()
    finally:
        _restore_managed_update_holds(runner, released_holds)
    if "openssh-server" in roots:
        runner.run(["systemctl", "enable", "--now", "ssh.service"])
    update_host_state(offline_packages_installed=True)


def _release_managed_update_holds(runner: Runner) -> list[str]:
    """Temporarily release only update-protection holds owned by this project."""
    state = load_host_state()
    if not state.get("update_protection_enabled", False):
        return []
    managed = set(state.get("update_protection_managed_holds", []))
    held = {
        line.strip()
        for line in runner.run(["apt-mark", "showhold"], capture=True).stdout.splitlines()
        if line.strip()
    }
    released = sorted(managed & held)
    if released:
        runner.run(["apt-mark", "unhold", *released])
        print(f"暫時解除 {len(released)} 個部署器管理的更新保護 hold。")
    return released


def _restore_managed_update_holds(runner: Runner, released: list[str]) -> None:
    if released:
        runner.run(["apt-mark", "hold", *released])
        print(f"已恢復 {len(released)} 個部署器管理的更新保護 hold。")


def _install_amd_ftpm_libtpms(runner: Runner) -> None:
    """Build and install the source-pinned AMD fTPM libtpms replacement."""
    script = PROJECT_DIR / "tools" / "build_libtpms_amd_package.sh"
    if not script.is_file():
        raise AppError(f"AMD fTPM package builder is missing: {script}")
    package_dir = STATE_DIR / "packages"
    package_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    runner.run([str(script)], env={
        **os.environ,
        "KVM_AAVM_LIBTPMS_DEB_DIR": str(package_dir),
    })
    packages = sorted(package_dir.glob("libtpms0_*+kvm-aavm1*_amd64.deb"))
    if not packages:
        raise AppError("AMD fTPM libtpms package build did not produce libtpms0.")
    package = packages[-1]
    runner.run(["dpkg", "-i", str(package)])
    result = runner.run(
        ["dpkg-query", "--show", "--showformat=${Version}", "libtpms0"],
        capture=True,
    )
    if "+kvm-aavm1" not in result.stdout.strip():
        raise AppError("Installed libtpms0 is not the KVM-AntiAntiVM AMD fTPM package.")


def _host_tpm_pcr_banks() -> str:
    """Return the PCR banks active on the host fTPM, with a safe fallback."""
    supported = {"sha1", "sha256", "sha384", "sha512"}
    banks = sorted(
        path.name.removeprefix("pcr-")
        for path in TPM_SYSFS.glob("pcr-*")
        if path.is_dir() and path.name.removeprefix("pcr-") in supported
    )
    return ",".join(banks) if banks else DEFAULT_AMD_FTPM_PCR_BANKS


def _replace_managed_swtpm_setup(text: str, pcr_banks: str = DEFAULT_AMD_FTPM_PCR_BANKS) -> str:
    """Set the PCR banks while preserving unrelated swtpm_setup settings."""
    lines = [
        line for line in text.splitlines()
        if not line.lstrip().startswith("active_pcr_banks")
    ]
    lines.extend([
        "# KVM-AntiAntiVM AMD fTPM profile",
        f"active_pcr_banks = {pcr_banks}",
    ])
    return "\n".join(lines).rstrip() + "\n"


def _replace_managed_localca_options(text: str) -> str:
    """Use AMD fTPM platform metadata for EK/platform certificates."""
    keys = set(AMD_FTPM_PLATFORM_OPTIONS)
    lines = [
        line for line in text.splitlines()
        if not any(line.lstrip().startswith(key + " ") for key in keys)
    ]
    lines.extend([
        "# KVM-AntiAntiVM AMD fTPM profile",
        *(
            f"{key} {value}"
            for key, value in AMD_FTPM_PLATFORM_OPTIONS.items()
        ),
    ])
    return "\n".join(lines).rstrip() + "\n"


def configure_amd_ftpm_swtpm() -> None:
    """Install the runtime metadata used when libvirt manufactures a TPM."""
    require_root()
    setup_text = SWTPM_SETUP_CONFIG.read_text(encoding="utf-8") if SWTPM_SETUP_CONFIG.exists() else ""
    localca_text = SWTPM_LOCALCA_OPTIONS.read_text(encoding="utf-8") if SWTPM_LOCALCA_OPTIONS.exists() else ""
    atomic_write(SWTPM_SETUP_CONFIG, _replace_managed_swtpm_setup(setup_text, _host_tpm_pcr_banks()))
    atomic_write(SWTPM_LOCALCA_OPTIONS, _replace_managed_localca_options(localca_text))


@contextmanager
def _apt_temporary_directory():
    """Prefer persistent temporary storage, with a usable /tmp fallback."""
    try:
        temporary = tempfile.TemporaryDirectory(prefix="kvm-aavm-apt-", dir="/var/tmp")
    except OSError as exc:
        if exc.errno not in {errno.EACCES, errno.EROFS, errno.ENOSPC}:
            raise
        temporary = tempfile.TemporaryDirectory(prefix="kvm-aavm-apt-")
    try:
        yield temporary.name
    finally:
        temporary.cleanup()


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
