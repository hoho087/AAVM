from __future__ import annotations

import os
import re
import shlex
import shutil
import sys
from pathlib import Path

from .hardware import cpu_info
from .paths import PREFIX, PROJECT_DIR, STATE_DIR, ensure_state_dirs
from .state import load_host_state, update_host_state
from .util import AppError, Runner, atomic_write, command_exists, require_root


APPARMOR_LIBVIRTD_PROFILE = Path("/etc/apparmor.d/usr.sbin.libvirtd")
APPARMOR_LIBVIRTD_LOCAL = Path("/etc/apparmor.d/local/usr.sbin.libvirtd")
APPARMOR_QEMU_DROPIN = Path("/etc/apparmor.d/abstractions/libvirt-qemu.d/kvm-aavm")
APPARMOR_SECURITY_DIR = Path("/sys/kernel/security/apparmor")
LIBVIRT_HOOK_DISPATCHER = Path("/etc/libvirt/hooks/qemu.d/50-kvm-aavm")
VIRTINST_GUEST = Path("/usr/share/virt-manager/virtinst/guest.py")
VIRTINST_GUEST_BACKUP = STATE_DIR / "backups" / "virtinst-guest.py.before-kvm-aavm"
VFIO_MODPROBE_CONFIG = Path("/etc/modprobe.d/kvm-aavm-vfio.conf")
OBSOLETE_ONESHOT_GRUB = Path("/etc/grub.d/09_kvm_aavm_oneshot")
OBSOLETE_ONESHOT_UNIT = Path("/etc/systemd/system/kvm-aavm-oneshot-vm.service")
OBSOLETE_ONESHOT_MARKER = STATE_DIR / "oneshot-vm.json"
GRUB_DEFAULT = Path("/etc/default/grub")
INITRAMFS_MODULES = Path("/etc/initramfs-tools/modules")
KVM_MODPROBE_CONFIG = Path("/etc/modprobe.d/kvm-aavm.conf")

UPDATE_PROTECTED_PACKAGE_PATTERNS = (
    re.compile(r"^linux-(?:generic|image|headers|modules|lowlatency|virtual|oem|tools|cloud-tools)(?:-|$)"),
    re.compile(r"^(?:qemu|libvirt)(?:[-0-9]|$)"),
    re.compile(r"^python3-libvirt$"),
    re.compile(r"^(?:virt-manager|virt-viewer|virtinst)$"),
    re.compile(r"^(?:ovmf|seabios|swtpm)(?:-|$)"),
    re.compile(r"^(?:nvidia|libnvidia|xserver-xorg-video-nvidia)(?:-|$)"),
    re.compile(r"^amdgpu(?:-|$)"),
)


def configure_vfio_module_options() -> None:
    """Keep modern passthrough GPUs out of idle D3.

    A physical GPU used as the guest's primary display needs VFIO's VGA region
    enabled for QEMU ``x-vga``.  ``disable_vga=1`` silently defeats that setup
    after the next initramfs boot and produced a signal-but-black display on a
    Blackwell single-GPU host.  Idle D3 remains disabled because it can still
    break the next host/VFIO hand-off.  Do not enable SR-IOV for whole-PF
    passthrough and never bypass VFIO's security denylist here.
    """
    atomic_write(
        VFIO_MODPROBE_CONFIG,
        "# Managed by KVM-AntiAntiVM; applied through initramfs.\n"
        "options vfio-pci disable_idle_d3=1\n",
    )


def _replace_grub_args(text: str, additions: list[str]) -> str:
    key = "GRUB_CMDLINE_LINUX_DEFAULT"
    pattern = re.compile(rf"^{key}=(['\"])(.*?)\1$", re.MULTILINE)
    match = pattern.search(text)
    current = match.group(2).split() if match else []
    mutually_exclusive = {"intel_iommu=on", "amd_iommu=on"}
    selected_vendor_arg = next((arg for arg in additions if arg in mutually_exclusive), None)
    selected_lsm = next((arg for arg in additions if arg.startswith("lsm=")), None)
    current = [
        arg for arg in current
        if (arg not in mutually_exclusive or arg == selected_vendor_arg)
        and (selected_lsm is None or not arg.startswith("lsm=") or arg == selected_lsm)
    ]
    for arg in additions:
        if arg not in current:
            current.append(arg)
    replacement = f'{key}="{" ".join(current)}"'
    if match:
        return text[:match.start()] + replacement + text[match.end():]
    return text.rstrip() + "\n" + replacement + "\n"


def _set_nested_module_option(text: str, module: str, enabled: bool) -> str:
    """Set only this deployer's nested option while preserving other options."""
    desired = "1" if enabled else "0"
    lines = text.splitlines()
    found = False
    updated: list[str] = []
    for line in lines:
        fields = line.split()
        if len(fields) >= 2 and fields[0] == "options" and fields[1] == module:
            options = [item for item in fields[2:] if not item.startswith("nested=")]
            updated.append(" ".join(["options", module, *options, f"nested={desired}"]))
            found = True
        else:
            updated.append(line)
    if not found:
        updated.append(f"options {module} nested={desired}")
    return "\n".join(updated).rstrip() + "\n"


def ensure_nested_virtualization(runner: Runner) -> None:
    """Prepare host nested VMX/SVM without exposing it to unrelated guests."""
    require_root()
    info = cpu_info()
    if not info["virtualization"]:
        raise AppError("CPU virtualization flag is missing. Enable SVM/VMX in firmware first.")
    module = "kvm_amd" if info["vendor"] == "amd" else "kvm_intel"
    current = (
        KVM_MODPROBE_CONFIG.read_text(encoding="utf-8")
        if KVM_MODPROBE_CONFIG.exists() else "options kvm ignore_msrs=0\n"
    )
    updated = _set_nested_module_option(current, module, True)
    if updated != current:
        atomic_write(KVM_MODPROBE_CONFIG, updated)
        runner.run(["update-initramfs", "-u", "-k", "all"])
    if runner.dry_run:
        return
    parameter = Path(f"/sys/module/{module}/parameters/nested")
    if not parameter.exists():
        runner.run(["modprobe", module])
    value = parameter.read_text(encoding="utf-8").strip().lower() if parameter.exists() else ""
    if value not in {"1", "y", "yes"}:
        update_host_state(reboot_required=True)
        raise AppError(
            "Nested virtualization has been prepared, but the loaded KVM module still has "
            "nested=0. Reboot Ubuntu, then run this VM option again; the deployer will not "
            "start the VM automatically."
        )


def _managed_block(text: str, body: str) -> str:
    start = "# BEGIN KVM-AAVM"
    end = "# END KVM-AAVM"
    block = f"{start}\n{body.rstrip()}\n{end}"
    pattern = re.compile(rf"{re.escape(start)}.*?{re.escape(end)}", re.DOTALL)
    if pattern.search(text):
        return pattern.sub(block, text)
    prefix = text.rstrip()
    return f"{prefix}\n\n{block}\n" if prefix else f"{block}\n"


def configure_apparmor(runner: Runner) -> None:
    """Allow only KVM-AAVM's root-owned per-generation QEMU binaries."""
    require_root()
    if not APPARMOR_LIBVIRTD_PROFILE.is_file() or not command_exists("apparmor_parser"):
        return
    artifact_bin_glob = f"{STATE_DIR}/vms/*/artifacts/generation-*/bin"
    binary_glob = f"{artifact_bin_glob}/qemu-system-x86_64"
    ssdt_glob = f"{artifact_bin_glob}/*.aml"
    qemu_share_glob = f"{STATE_DIR}/vms/*/artifacts/generation-*/share/qemu"
    qemu_firmware_glob = f"{STATE_DIR}/vms/*/artifacts/generation-*/share/qemu-firmware"
    vm_firmware_glob = f"{STATE_DIR}/vms/*/firmware"
    APPARMOR_LIBVIRTD_LOCAL.parent.mkdir(parents=True, exist_ok=True)
    current = APPARMOR_LIBVIRTD_LOCAL.read_text(encoding="utf-8") if APPARMOR_LIBVIRTD_LOCAL.exists() else ""
    atomic_write(APPARMOR_LIBVIRTD_LOCAL, _managed_block(current, f"{binary_glob} PUx,"))
    APPARMOR_QEMU_DROPIN.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(
        APPARMOR_QEMU_DROPIN,
        "# KVM-AAVM per-VM QEMU executable, -acpitable inputs and runtime ROMs\n"
        f"{binary_glob} rmix,\n"
        f"{ssdt_glob} r,\n"
        f"{qemu_share_glob}/{{,**}} r,\n"
        f"{qemu_firmware_glob}/{{,**}} r,\n"
        f"{vm_firmware_glob}/*.rom r,\n",
    )
    if not APPARMOR_SECURITY_DIR.is_dir():
        print(
            "目前核心未啟用 AppArmor LSM；規則已寫入，略過即時 reload。"
            "重新開機套用部署器管理的 lsm=...apparmor 參數後會自動生效。"
        )
        return
    runner.run(["apparmor_parser", "-r", str(APPARMOR_LIBVIRTD_PROFILE)])
    # Per-domain profiles are transient and include a matching `.files` that
    # virt-aa-helper creates only while preparing/starting the domain. Parsing
    # stale profiles here fails after shutdown because that include has already
    # been removed. Libvirt rebuilds and loads them with this drop-in on the
    # next domain start; active domains do not need new ACPI input permissions
    # until their next start either.


def configure_libvirt_hooks(runner: Runner) -> None:
    """Install one official qemu.d hook that dispatches per-VM scripts."""
    require_root()
    dispatcher = """#!/usr/bin/env bash
set -euo pipefail
vm=${1:-}
[[ "$vm" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || exit 0
hook_dir=/etc/libvirt/hooks/kvm-aavm/$vm
[[ -d "$hook_dir" ]] || exit 0
shopt -s nullglob
for hook in "$hook_dir"/*; do
  [[ -f "$hook" && -x "$hook" ]] || continue
  "$hook" "$@"
done
"""
    atomic_write(LIBVIRT_HOOK_DISPATCHER, dispatcher, 0o755)
    runner.run(["systemctl", "try-restart", "libvirtd.service"])


def configure_virt_manager(runner: Runner) -> None:
    """Let virt-manager compare a custom QEMU machine before host capabilities.

    Ubuntu 24.04's virtinst asks the system QEMU 8.2 capabilities whether a
    machine exists before comparing it with domcaps queried from the domain's
    custom emulator. Per-VM QEMU 11 therefore works in libvirt but crashes the
    virt-manager details page for pc-q35-11.0.
    """
    require_root()
    if not VIRTINST_GUEST.is_file():
        return
    text = VIRTINST_GUEST.read_text(encoding="utf-8")
    marker = "# KVM-AAVM: accept an exact custom-emulator machine before host caps"
    if marker in text:
        return
    old = """        def _compare_machine(domcaps):
            capsinfo = self.lookup_capsinfo()
            if self.os.machine == domcaps.machine:
                return True
            if capsinfo.is_machine_alias(self.os.machine, domcaps.machine):
                return True
            return False
"""
    new = f"""        def _compare_machine(domcaps):
            {marker}
            if self.os.machine == domcaps.machine:
                return True
            capsinfo = self.lookup_capsinfo()
            if capsinfo.is_machine_alias(self.os.machine, domcaps.machine):
                return True
            return False
"""
    if old not in text:
        print("virt-manager compatibility patch not needed or this virtinst version is not affected.")
        return
    VIRTINST_GUEST_BACKUP.parent.mkdir(parents=True, exist_ok=True)
    if not VIRTINST_GUEST_BACKUP.exists():
        shutil.copy2(VIRTINST_GUEST, VIRTINST_GUEST_BACKUP)
    atomic_write(VIRTINST_GUEST, text.replace(old, new, 1), VIRTINST_GUEST.stat().st_mode & 0o777)
    runner.run([sys.executable, "-m", "py_compile", str(VIRTINST_GUEST)])
    print("virt-manager compatibility patch installed; restart virt-manager to load it.")


def verify_spice_console_runtime(runner: Runner) -> None:
    """Fail early when Ubuntu omitted virt-manager's recommended SPICE GI modules."""
    check = (
        "import gi; "
        "gi.require_version('SpiceClientGLib', '2.0'); "
        "gi.require_version('SpiceClientGtk', '3.0'); "
        "from gi.repository import SpiceClientGLib, SpiceClientGtk"
    )
    result = runner.run([sys.executable, "-c", check], check=False, capture=True)
    if result.returncode:
        raise AppError(
            "virt-manager SPICE console runtime is missing. Run main-menu option 1 "
            "(Ubuntu 主機一鍵部署／更新), then retry."
        )


def remove_obsolete_oneshot_support(runner: Runner) -> None:
    """Migrate hosts back to the normal dynamic single-GPU hand-off."""
    grub_changed = False
    initramfs_changed = False
    had_unit = OBSOLETE_ONESHOT_UNIT.exists()
    if had_unit:
        runner.run(
            ["systemctl", "disable", "--now", "kvm-aavm-oneshot-vm.service"],
            check=False,
        )
    OBSOLETE_ONESHOT_UNIT.unlink(missing_ok=True)
    OBSOLETE_ONESHOT_MARKER.unlink(missing_ok=True)
    runner.run(
        [
            "grub-editenv", "/boot/grub/grubenv", "unset",
            "kvm_aavm_once", "kvm_aavm_vfio_ids",
        ],
        check=False,
    )
    if OBSOLETE_ONESHOT_GRUB.exists():
        OBSOLETE_ONESHOT_GRUB.unlink()
        grub_changed = True

    if GRUB_DEFAULT.exists():
        text = GRUB_DEFAULT.read_text(encoding="utf-8")
        key = "GRUB_CMDLINE_LINUX_DEFAULT"
        pattern = re.compile(rf"^{key}=([\"'])(.*?)\1$", re.MULTILINE)
        match = pattern.search(text)
        if match:
            args = [
                value for value in match.group(2).split()
                if value != r"\${kvm_aavm_args}"
            ]
            replacement = f'{key}="{" ".join(args)}"'
            updated = text[:match.start()] + replacement + text[match.end():]
            if updated != text:
                atomic_write(GRUB_DEFAULT, updated)
                grub_changed = True

    if INITRAMFS_MODULES.exists():
        text = INITRAMFS_MODULES.read_text(encoding="utf-8")
        pattern = re.compile(
            r"(?:\n\n|\n)?# BEGIN KVM-AAVM ONESHOT VFIO.*?"
            r"# END KVM-AAVM ONESHOT VFIO(?:\n|$)",
            re.DOTALL,
        )
        updated = pattern.sub("\n", text).rstrip() + "\n"
        if updated != text:
            atomic_write(INITRAMFS_MODULES, updated)
            initramfs_changed = True

    (PREFIX / "kvm_aavm" / "bootmode.py").unlink(missing_ok=True)
    if had_unit:
        runner.run(["systemctl", "daemon-reload"])
    if initramfs_changed:
        runner.run(["update-initramfs", "-u", "-k", "all"])
    if grub_changed:
        runner.run(["update-grub"])
    update_host_state(
        oneshot_vfio_support_installed=False,
        oneshot_vm_scheduled=False,
        oneshot_vm=None,
    )


def install_application(runner: Runner) -> None:
    require_root()
    ensure_state_dirs()
    PREFIX.mkdir(parents=True, exist_ok=True)
    (PREFIX / "kvm_aavm").mkdir(parents=True, exist_ok=True)
    for source in (PROJECT_DIR / "kvm_aavm").glob("*.py"):
        shutil.copy2(source, PREFIX / "kvm_aavm" / source.name)
    shutil.copy2(PROJECT_DIR / "deploy.sh", PREFIX / "deploy.sh")
    os.chmod(PREFIX / "deploy.sh", 0o755)
    project = shlex.quote(str(PROJECT_DIR))
    offline = shlex.quote(str(PROJECT_DIR / "offline"))
    wrapper = (
        "#!/usr/bin/env bash\n"
        f"export KVM_AAVM_PROJECT_DIR={project}\n"
        f"export KVM_AAVM_OFFLINE_DIR={offline}\n"
        f"exec {shlex.quote(str(PREFIX / 'deploy.sh'))} \"$@\"\n"
    )
    atomic_write(Path("/usr/local/sbin/kvm-aavm"), wrapper, 0o755)
    remove_obsolete_oneshot_support(runner)
    configure_apparmor(runner)
    configure_virt_manager(runner)
    verify_spice_console_runtime(runner)
    configure_libvirt_hooks(runner)
    # Existing managed VMs receive the same runtime power policy as newly
    # created ones when option 1 updates the deployer.
    from .hooks import install_performance_hook
    for profile in sorted((STATE_DIR / "vms").glob("*/profile.json")):
        try:
            install_performance_hook(profile.parent.name)
        except AppError as exc:
            print(f"Skipping performance hook for {profile.parent.name}: {exc}")
    update_host_state(application_installed=True, project_dir=str(PROJECT_DIR))


def _installed_update_targets(runner: Runner) -> list[str]:
    result = runner.run(
        ["dpkg-query", "-W", "-f=${Package}\\t${db:Status-Abbrev}\\n"],
        capture=True,
    )
    targets: set[str] = set()
    for line in result.stdout.splitlines():
        try:
            package, status = line.split("\t", 1)
        except ValueError:
            continue
        if len(status) >= 2 and status[1] == "i" and any(
            pattern.match(package) for pattern in UPDATE_PROTECTED_PACKAGE_PATTERNS
        ):
            targets.add(package)
    return sorted(targets)


def _apt_holds(runner: Runner) -> set[str]:
    result = runner.run(["apt-mark", "showhold"], capture=True)
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def configure_update_protection(runner: Runner, enabled: bool) -> None:
    """Protect the working kernel/virtualization stack without blocking security updates."""
    require_root()
    state = load_host_state()
    previous_managed = set(state.get("update_protection_managed_holds", []))
    held = _apt_holds(runner)

    if not enabled:
        release = sorted(previous_managed & held)
        if release:
            runner.run(["apt-mark", "unhold", *release])
        update_host_state(
            update_protection_enabled=False,
            update_protection_packages=[],
            update_protection_managed_holds=[],
        )
        print(
            f"更新保護已停用；解除 {len(release)} 個由部署器建立的 hold。"
            "其他既有 hold 保持不變。"
        )
        return

    targets = set(_installed_update_targets(runner))
    if not targets:
        raise AppError("No installed kernel or virtualization packages were found to protect.")

    # Existing user holds are effective but never become ours to remove.
    preexisting_user_holds = held - previous_managed
    managed = (previous_managed & held) | (targets - preexisting_user_holds)
    add = sorted(targets - held)
    if add:
        runner.run(["apt-mark", "hold", *add])
    update_host_state(
        update_protection_enabled=True,
        update_protection_packages=sorted(targets),
        update_protection_managed_holds=sorted(managed),
    )
    print(f"更新保護已啟用：{len(targets)} 個核心／虛擬化／GPU 套件已鎖定。")
    print("未列入保護的其他 Ubuntu 安全更新仍可安裝；主動升級此堆疊前請先停用保護。")


def configure_host(runner: Runner, *, memflow: bool = False) -> None:
    require_root()
    info = cpu_info()
    if not info["virtualization"]:
        raise AppError("CPU virtualization flag is missing. Enable SVM/VMX in firmware first.")
    iommu_arg = "amd_iommu=on" if info["vendor"] == "amd" else "intel_iommu=on"
    grub = Path("/etc/default/grub")
    text = grub.read_text(encoding="utf-8")
    additions = [
        iommu_arg, "iommu=pt", "split_lock_detect=off", "mitigations=auto",
        "lsm=landlock,lockdown,yama,integrity,apparmor,bpf",
    ]
    if memflow:
        additions.append("ibt=off")
    updated = _replace_grub_args(text, additions)
    if updated != text:
        backup = STATE_DIR / "backups" / "grub.before-kvm-aavm"
        backup.parent.mkdir(parents=True, exist_ok=True)
        if not backup.exists():
            shutil.copy2(grub, backup)
        atomic_write(grub, updated)
    module = "kvm_amd" if info["vendor"] == "amd" else "kvm_intel"
    # Nested capability is prepared globally, but no guest sees SVM/VMX unless
    # its per-VM Core Isolation/VBS option is explicitly enabled.
    atomic_write(KVM_MODPROBE_CONFIG, f"options {module} nested=1\noptions kvm ignore_msrs=0\n")
    configure_vfio_module_options()
    atomic_write(Path("/etc/modules-load.d/kvm-aavm.conf"), "vfio\nvfio_iommu_type1\nvfio_pci\n")
    runner.run(["update-initramfs", "-u", "-k", "all"])
    runner.run(["update-grub"])
    runner.run(["systemctl", "enable", "--now", "libvirtd"])
    target_user = os.environ.get("SUDO_USER")
    if target_user:
        runner.run(["usermod", "-aG", "libvirt,kvm", target_user])
    update_host_state(host_configured=True, reboot_required=True, cpu_vendor=info["vendor"])
    print("主機配置已寫入。請重新開機後再進行 VM 與直通驗證。")


def install_pending_service(runner: Runner) -> None:
    require_root()
    unit = """[Unit]
Description=Finish pending KVM-AAVM identity rotations
After=libvirtd.service
Wants=libvirtd.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/kvm-aavm randomize-pending

[Install]
WantedBy=multi-user.target
"""
    atomic_write(Path("/etc/systemd/system/kvm-aavm-pending.service"), unit)
    runner.run(["systemctl", "daemon-reload"])
    runner.run(["systemctl", "enable", "kvm-aavm-pending.service"])
