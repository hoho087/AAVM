from __future__ import annotations

import os
import re
import shutil
import tempfile
from pathlib import Path

from .hardware import cpu_info
from .paths import OFFLINE_DIR, PROJECT_DIR, STATE_DIR
from .util import AppError, Runner, atomic_write, require_root

MOK_CERTIFICATE = Path("/var/lib/shim-signed/mok/MOK.der")
MOK_PRIVATE_KEY = Path("/var/lib/shim-signed/mok/MOK.priv")
KERNEL_MOK_DIRECTORY = STATE_DIR / "secure-boot"
KERNEL_MOK_CERTIFICATE = KERNEL_MOK_DIRECTORY / "kernel-signing.der"
KERNEL_MOK_CERTIFICATE_PEM = KERNEL_MOK_DIRECTORY / "kernel-signing.pem"
KERNEL_MOK_PRIVATE_KEY = KERNEL_MOK_DIRECTORY / "kernel-signing.key"
KERNEL_MOK_COMMON_NAME = "KVM-AAVM Custom Kernel Signing"
KERNEL_SIGNING_HOOK = Path("/etc/kernel/postinst.d/kvm-aavm-sign-custom-kernel")
BOOT_DIR = Path("/boot")


def _kernel_signing_hook() -> str:
    return f'''#!/bin/sh
set -eu
version="${{1:-}}"
image="${{2:-/boot/vmlinuz-${{version}}}}"
case "$version" in
  *-tkg-*) ;;
  *) exit 0 ;;
esac
[ -f "$image" ] || exit 0
key={KERNEL_MOK_PRIVATE_KEY}
cert_der={KERNEL_MOK_CERTIFICATE}
[ -r "$key" ] && [ -r "$cert_der" ] || {{
  echo "kvm-aavm: custom-kernel Secure Boot key is missing; refusing to leave $image unsigned" >&2
  exit 1
}}
umask 077
cert_pem=$(mktemp /run/kvm-aavm-mok.XXXXXX.pem)
unsigned=$(mktemp "${{image}}.unsigned.XXXXXX")
signed=$(mktemp "${{image}}.signed.XXXXXX")
trap 'rm -f "$cert_pem" "$unsigned" "$signed"' EXIT INT TERM
openssl x509 -inform DER -in "$cert_der" -out "$cert_pem"
if sbverify --cert "$cert_pem" "$image" >/dev/null 2>&1; then
  echo "kvm-aavm: custom kernel already signed: $image"
  exit 0
fi
cp --preserve=mode,ownership,timestamps "$image" "$unsigned"
# A previous DKMS-only MOK signature is valid to sbverify but is deliberately
# rejected by shim for boot images. Always replace the complete PE signature
# table before applying the dedicated kernel-boot certificate.
sbattach --remove "$unsigned" >/dev/null 2>&1 || true
sbsign --key "$key" --cert "$cert_pem" --output "$signed" "$unsigned"
sbverify --cert "$cert_pem" "$signed"
chmod --reference="$image" "$signed"
chown --reference="$image" "$signed"
touch --reference="$image" "$signed"
mv -f "$signed" "$image"
echo "kvm-aavm: signed custom kernel $image"
'''


def _install_kernel_signing_hook() -> None:
    atomic_write(KERNEL_SIGNING_HOOK, _kernel_signing_hook(), 0o755)


def _secure_boot_enabled(runner: Runner) -> bool:
    result = runner.run(["mokutil", "--sb-state"], check=False, capture=True)
    return result.returncode == 0 and "secureboot enabled" in (result.stdout + result.stderr).lower()


def _mok_enrolled(runner: Runner, certificate: Path | None = None) -> bool:
    certificate = certificate or MOK_CERTIFICATE
    if not certificate.is_file():
        return False
    result = runner.run(
        ["mokutil", "--test-key", str(certificate)],
        check=False, capture=True, env={**os.environ, "LC_ALL": "C"},
    )
    return "already enrolled" in (result.stdout + result.stderr).lower()


def _queue_dkms_mok_enrollment(runner: Runner, purpose: str) -> None:
    if not MOK_CERTIFICATE.is_file() or not MOK_PRIVATE_KEY.is_file():
        raise AppError(
            "Secure Boot 已啟用，但 Ubuntu 未建立 DKMS MOK 金鑰；"
            "請確認 shim-signed、mokutil、openssl 與 sbsigntool 已安裝。"
        )
    if _mok_enrolled(runner):
        return
    print(f"Secure Boot 需要信任用來簽署{purpose}的 Ubuntu DKMS MOK 金鑰。")
    print("請設定一組 8–16 字元的一次性 MOK 密碼，重新開機時還要輸入同一組密碼。")
    runner.run(["update-secureboot-policy", "--enroll-key"])
    pending = runner.run(
        ["mokutil", "--list-new"], check=False, capture=True,
        env={**os.environ, "LC_ALL": "C"},
    )
    if not pending.stdout.strip():
        raise AppError("MOK 登錄要求沒有寫入 EFI；請確認系統以 UEFI 啟動且 EFI variables 可寫入。")
    print("MOK 登錄要求已排程；請重新開機並在 MOK Manager 完成 Enroll MOK。")


def _ensure_kernel_mok(runner: Runner) -> None:
    if KERNEL_MOK_CERTIFICATE.is_file() and KERNEL_MOK_PRIVATE_KEY.is_file():
        return
    if KERNEL_MOK_CERTIFICATE.exists() or KERNEL_MOK_PRIVATE_KEY.exists():
        raise AppError(
            f"專用核心簽章金鑰不完整；請先備份後移除 {KERNEL_MOK_DIRECTORY} 再重試。"
        )
    KERNEL_MOK_DIRECTORY.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(KERNEL_MOK_DIRECTORY, 0o700)
    with tempfile.TemporaryDirectory(prefix=".kernel-key-", dir=KERNEL_MOK_DIRECTORY) as temporary:
        work = Path(temporary)
        key = work / "kernel-signing.key"
        certificate_pem = work / "kernel-signing.pem"
        certificate_der = work / "kernel-signing.der"
        runner.run([
            "openssl", "req", "-new", "-x509", "-newkey", "rsa:3072",
            "-sha256", "-days", "36500", "-nodes",
            "-subj", f"/CN={KERNEL_MOK_COMMON_NAME}/",
            "-addext", "basicConstraints=critical,CA:FALSE",
            "-addext", "keyUsage=critical,digitalSignature",
            "-addext", "extendedKeyUsage=codeSigning",
            "-keyout", str(key), "-out", str(certificate_pem),
        ])
        runner.run([
            "openssl", "x509", "-in", str(certificate_pem),
            "-outform", "DER", "-out", str(certificate_der),
        ])
        os.chmod(key, 0o600)
        os.chmod(certificate_pem, 0o644)
        os.chmod(certificate_der, 0o644)
        os.replace(key, KERNEL_MOK_PRIVATE_KEY)
        os.replace(certificate_pem, KERNEL_MOK_CERTIFICATE_PEM)
        os.replace(certificate_der, KERNEL_MOK_CERTIFICATE)


def _queue_kernel_mok_enrollment(runner: Runner) -> None:
    if _mok_enrolled(runner, KERNEL_MOK_CERTIFICATE):
        return
    pending = runner.run(
        ["mokutil", "--list-new"], check=False, capture=True,
        env={**os.environ, "LC_ALL": "C"},
    )
    if KERNEL_MOK_COMMON_NAME.lower() in (pending.stdout + pending.stderr).lower():
        print("專用核心開機 MOK 已在等待下次開機登錄。")
        return
    print("Secure Boot 需要另外信任專用於 linux-tkg 開機映像的 MOK。")
    print("這與 DKMS/memflow 的 module-only MOK 不同；請設定一組 8–16 字元的一次性密碼。")
    runner.run(["mokutil", "--import", str(KERNEL_MOK_CERTIFICATE)])
    pending = runner.run(
        ["mokutil", "--list-new"], check=False, capture=True,
        env={**os.environ, "LC_ALL": "C"},
    )
    if not pending.stdout.strip():
        raise AppError("專用核心 MOK 登錄要求沒有寫入 EFI。")
    print("專用核心 MOK 登錄要求已排程。")


def _ubuntu_kernel_fragment() -> str:
    return (
        "# KVM-AAVM: Ubuntu/libvirt host compatibility\n"
        "CONFIG_DEFAULT_SECURITY_APPARMOR=y\n"
        "# CONFIG_DEFAULT_SECURITY_DAC is not set\n"
        'CONFIG_LSM="landlock,lockdown,yama,integrity,apparmor,bpf"\n'
    )


def _validate_tkg_boot_config(version: str) -> None:
    config = BOOT_DIR / f"config-{version}"
    if not config.is_file():
        raise AppError(f"找不到自訂核心設定檔：{config}")
    text = config.read_text(encoding="utf-8")
    lsm = re.search(r'^CONFIG_LSM="([^"]*)"$', text, re.MULTILINE)
    if (
        "CONFIG_SECURITY_APPARMOR=y" not in text
        or lsm is None
        or "apparmor" not in lsm.group(1).split(",")
    ):
        raise AppError(
            f"{version} 沒有啟用 AppArmor LSM，會使 libvirt/AppArmor 維護失敗；"
            "已中止切換到此核心。"
        )


def _set_cfg(text: str, key: str, value: str) -> str:
    updated, count = re.subn(rf'^{re.escape(key)}="[^"]*"', f'{key}="{value}"', text, count=1, flags=re.MULTILINE)
    if count != 1:
        raise AppError(f"linux-tkg option is missing: {key}")
    return updated


def _installed_nvidia_drivers(runner: Runner) -> list[tuple[str, str]]:
    result = runner.run(
        [
            "dpkg-query", "-W",
            "-f=${binary:Package}\t${Version}\t${db:Status-Abbrev}\n",
            "nvidia-driver-*",
        ],
        check=False, capture=True,
    )
    drivers: list[tuple[str, str]] = []
    for line in result.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 3 or len(fields[2]) < 2 or fields[2][1] != "i":
            continue
        package = fields[0].split(":", 1)[0]
        match = re.fullmatch(r"nvidia-driver-(\d+)(.*)", package)
        if not match:
            continue
        suffix = match.group(2)
        drivers.append((f"nvidia-dkms-{match.group(1)}{suffix}", fields[1]))
    return sorted(set(drivers))


def _package_installed(runner: Runner, package: str) -> bool:
    result = runner.run(
        ["dpkg-query", "-W", "-f=${db:Status-Abbrev}", package],
        check=False, capture=True,
    )
    return result.returncode == 0 and len(result.stdout) >= 2 and result.stdout[1] == "i"


def _matching_offline_deb(runner: Runner, package: str, version: str) -> Path | None:
    for candidate in sorted((OFFLINE_DIR / "debs").glob(f"{package}_*.deb")):
        result = runner.run(
            ["dpkg-deb", "-f", str(candidate), "Version"],
            check=False, capture=True,
        )
        if result.returncode == 0 and result.stdout.strip() == version:
            return candidate.resolve()
    return None


def _ensure_nvidia_dkms_support(runner: Runner) -> bool:
    drivers = _installed_nvidia_drivers(runner)
    for package, version in drivers:
        if _package_installed(runner, package):
            continue
        companion = _matching_offline_deb(runner, package, version)
        if companion is None:
            raise AppError(
                f"已安裝 NVIDIA 驅動 {version}，但缺少匹配的 {package}。"
                "自訂核心將沒有 NVIDIA 顯示模組；請把相同版本的 companion DEB "
                "加入 offline/debs 後重新產生 Packages 與 manifest。"
            )
        runner.run(["apt-get", "install", "-y", str(companion)])
    return bool(drivers)


def _sign_tkg_dkms_modules(runner: Runner, version: str) -> bool:
    module_dir = Path("/lib/modules") / version / "updates/dkms"
    modules = sorted(module_dir.rglob("*.ko")) + sorted(module_dir.rglob("*.ko.zst"))
    if not modules:
        return False
    if not MOK_PRIVATE_KEY.is_file() or not MOK_CERTIFICATE.is_file():
        raise AppError("DKMS MOK 金鑰不存在，無法簽署自訂核心的外部模組。")
    sign_file = Path("/usr/src") / f"linux-headers-{version}" / "scripts/sign-file"
    if not sign_file.is_file():
        raise AppError(f"找不到 {version} 的 scripts/sign-file，無法簽署 DKMS 模組。")
    for module in modules:
        signer = runner.run(
            ["modinfo", "-F", "signer", str(module)],
            check=False, capture=True,
        )
        if signer.returncode == 0 and signer.stdout.strip():
            continue
        module_stat = module.stat()
        with tempfile.TemporaryDirectory(prefix=".kvm-aavm-sign-", dir=module.parent) as temporary:
            work = Path(temporary)
            raw = work / module.name.removesuffix(".zst")
            if module.name.endswith(".ko.zst"):
                runner.run(["zstd", "-q", "-d", "-f", str(module), "-o", str(raw)])
            else:
                shutil.copy2(module, raw)
            runner.run([
                str(sign_file), "sha512", str(MOK_PRIVATE_KEY),
                str(MOK_CERTIFICATE), str(raw),
            ])
            if module.name.endswith(".ko.zst"):
                packed = work / module.name
                runner.run(["zstd", "-q", "-f", str(raw), "-o", str(packed)])
                replacement = packed
            else:
                replacement = raw
            os.chmod(replacement, module_stat.st_mode)
            os.chown(replacement, module_stat.st_uid, module_stat.st_gid)
            os.utime(replacement, ns=(module_stat.st_atime_ns, module_stat.st_mtime_ns))
            os.replace(replacement, module)
    runner.run(["depmod", "-a", version])
    return True


def _prepare_tkg_external_modules(runner: Runner, secure_boot: bool) -> None:
    nvidia_required = _ensure_nvidia_dkms_support(runner)
    images = sorted(BOOT_DIR.glob("vmlinuz-*-tkg-*"))
    if secure_boot:
        runner.run(["update-secureboot-policy", "--new-key"])
    signed_any = False
    for image in images:
        version = image.name.removeprefix("vmlinuz-")
        runner.run(["dkms", "autoinstall", "-k", version])
        if secure_boot:
            signed_any = _sign_tkg_dkms_modules(runner, version) or signed_any
        if nvidia_required:
            check = runner.run(
                ["modinfo", "-k", version, "nvidia"],
                check=False, capture=True,
            )
            if check.returncode != 0:
                raise AppError(
                    f"NVIDIA DKMS 沒有為 {version} 產生 nvidia.ko；"
                    "不可重新開機進入此核心。"
                )
    if secure_boot and signed_any:
        _queue_dkms_mok_enrollment(runner, "自訂核心的 DKMS 驅動")


def _sign_installed_tkg_kernels(runner: Runner) -> None:
    images = sorted(BOOT_DIR.glob("vmlinuz-*-tkg-*"))
    if not images:
        raise AppError("linux-tkg 套件已安裝，但 /boot 中找不到自訂核心映像。")
    for image in images:
        version = image.name.removeprefix("vmlinuz-")
        runner.run([str(KERNEL_SIGNING_HOOK), version, str(image)])


def sign_custom_kernels(runner: Runner) -> None:
    require_root()
    secure_boot = _secure_boot_enabled(runner)
    if secure_boot:
        _ensure_kernel_mok(runner)
        _install_kernel_signing_hook()
        _sign_installed_tkg_kernels(runner)
    else:
        print("Secure Boot 未啟用；自訂核心映像不需要 MOK 簽章。")
    _prepare_tkg_external_modules(runner, secure_boot)
    if secure_boot:
        _queue_kernel_mok_enrollment(runner)
    runner.run(["update-initramfs", "-u", "-k", "all"])
    runner.run(["update-grub"])
    print("自訂 linux-tkg 核心與 DKMS 驅動已安裝並驗證。")
    if secure_boot and not _mok_enrolled(runner, KERNEL_MOK_CERTIFICATE):
        print("請重新開機並在 MOK Manager 完成 Enroll MOK 後，才能由 Secure Boot 啟動。")


def build_kernel(runner: Runner) -> None:
    require_root()
    source = OFFLINE_DIR / "sources/linux-tkg"
    linux = OFFLINE_DIR / "sources/linux"
    if not source.is_dir() or not linux.is_dir():
        raise AppError("Offline linux-tkg/Linux source is missing.")
    work = STATE_DIR / "kernel-build/linux-tkg"
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(source, work, symlinks=True)
    shutil.copytree(linux, work / "linux-src-git", symlinks=True)
    secure_boot = _secure_boot_enabled(runner)
    if secure_boot:
        _ensure_kernel_mok(runner)
        _install_kernel_signing_hook()
    cfg = work / "customization.cfg"
    text = cfg.read_text(encoding="utf-8")
    options = {
        "_distro": "Ubuntu", "_version": "6.19-latest", "_menunconfig": "false",
        "_diffconfig": "false", "_cpusched": "eevdf", "_compiler": "gcc",
        "_install_after_building": "no", "_user_patches_no_confirm": "true",
        "_config_fragments_no_confirm": "true",
    }
    for key, value in options.items():
        text = _set_cfg(text, key, value)
    cfg.write_text(text, encoding="utf-8")
    (work / "kvm-aavm-ubuntu.myfrag").write_text(
        _ubuntu_kernel_fragment(), encoding="utf-8",
    )
    patch = PROJECT_DIR / ("amd619.mypatch" if cpu_info()["vendor"] == "amd" else "intel619.mypatch")
    patch_dir = work / "linux619-tkg-userpatches"
    patch_dir.mkdir(exist_ok=True)
    shutil.copy2(patch, patch_dir / patch.name)
    runner.run(["bash", "install.sh", "install"], cwd=work, env={**os.environ, "_distro": "Ubuntu"})
    debs = sorted((work / "DEBS").glob("*.deb"))
    if not debs:
        raise AppError("linux-tkg did not produce Ubuntu DEB packages.")
    runner.run(["apt-get", "install", "-y", *debs])
    for image in sorted(BOOT_DIR.glob("vmlinuz-*-tkg-*")):
        _validate_tkg_boot_config(image.name.removeprefix("vmlinuz-"))
    if secure_boot:
        _sign_installed_tkg_kernels(runner)
    _prepare_tkg_external_modules(runner, secure_boot)
    if secure_boot:
        _queue_kernel_mok_enrollment(runner)
    runner.run(["update-initramfs", "-u", "-k", "all"])
    runner.run(["update-grub"])


def install_memflow(runner: Runner) -> None:
    require_root()
    archive = OFFLINE_DIR / "memflow-source-only.dkms.tar.gz"
    if not archive.is_file():
        raise AppError(f"Offline memflow DKMS archive is missing: {archive}")
    secure_boot = _secure_boot_enabled(runner)
    if secure_boot:
        runner.run(["update-secureboot-policy", "--new-key"])
    # Safe to resume after DKMS installed the module but MOK was not enrolled.
    runner.run(["dkms", "install", "--force", f"--archive={archive}"])
    loaded = runner.run(["modprobe", "memflow"], check=False, capture=True)
    if loaded.returncode == 0:
        print("memflow 已安裝並載入。")
        return
    detail = (loaded.stderr or loaded.stdout).strip()
    if not secure_boot:
        raise AppError(f"memflow 已由 DKMS 安裝，但無法載入：\n{detail}")
    if not MOK_CERTIFICATE.is_file():
        raise AppError(
            "Secure Boot 已啟用，但 Ubuntu 未建立 DKMS MOK 憑證；"
            "請確認 shim-signed、mokutil 與 openssl 已安裝。"
        )
    test = runner.run(
        ["mokutil", "--test-key", str(MOK_CERTIFICATE)],
        check=False, capture=True, env={**os.environ, "LC_ALL": "C"},
    )
    if "is not enrolled" not in (test.stdout + test.stderr).lower():
        raise AppError(f"memflow 的簽署金鑰已登錄，但模組仍無法載入：\n{detail}")
    print("Secure Boot 正在阻擋 memflow；現在將登錄 Ubuntu DKMS 的 MOK 憑證。")
    print("請設定一組 8–16 字元的一次性 MOK 密碼，重新開機時還要輸入同一組密碼。")
    runner.run(["update-secureboot-policy", "--enroll-key"])
    pending = runner.run(
        ["mokutil", "--list-new"], check=False, capture=True,
        env={**os.environ, "LC_ALL": "C"},
    )
    if not pending.stdout.strip():
        raise AppError("MOK 登錄要求沒有寫入 EFI；請確認系統以 UEFI 啟動且 EFI variables 可寫入。")
    print("MOK 登錄要求已排程；memflow DKMS 安裝已完成。")
    print("請重新開機，在藍色 MOK Manager 選 Enroll MOK → Continue → Yes，輸入剛才的密碼後再重新開機。")
    print("回到 Ubuntu 後再次選『安裝 memflow』；已登錄時會直接載入，不會重複要求 MOK。")
