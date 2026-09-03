from __future__ import annotations

import re
import shlex
from pathlib import Path

from .hardware import PciDevice
from .util import AppError, Runner, atomic_write, require_root, valid_vm_name


HOOK_ROOT = Path("/etc/libvirt/hooks/kvm-aavm")
LEGACY_HOOK_ROOT = Path("/etc/libvirt/hooks/qemu.d")
PROC_ROOT = Path("/proc")
PCI_DEVICES_ROOT = Path("/sys/bus/pci/devices")
PCI_DRIVERS_PROBE = Path("/sys/bus/pci/drivers_probe")
VTCON_ROOT = Path("/sys/class/vtconsole")
EFI_FRAMEBUFFER_BIND = Path("/sys/bus/platform/drivers/efi-framebuffer/bind")
SYS_MODULE_ROOT = Path("/sys/module")


def _write_hook(path: Path, body: str) -> None:
    atomic_write(path, "#!/usr/bin/env bash\nset -euo pipefail\n" + body.strip() + "\n", 0o755)


def _remove_legacy(paths: list[Path]) -> None:
    for path in paths:
        path.unlink(missing_ok=True)
        parent = path.parent
        while parent != LEGACY_HOOK_ROOT:
            try:
                parent.rmdir()
            except OSError:
                break
            parent = parent.parent


def _driver_module(device: PciDevice) -> str | None:
    """Return the original host driver when one is known.

    Unbound devices and devices already bound to vfio-pci are valid passthrough
    candidates. In those cases there is no host driver to restore later, so
    return None instead of aborting VM creation.
    """
    module = device.driver or ""
    if module in {"", "driver", "vfio-pci"}:
        return None
    if not re.fullmatch(r"[A-Za-z0-9_-]+", module):
        raise AppError(f"Invalid host driver name for PCI {device.address}: {module!r}.")
    return module


def _gpu_unload_modules(devices: list[PciDevice]) -> list[str]:
    modules: list[str] = []
    for device in devices:
        module = _driver_module(device)
        if module is None or module == "snd_hda_intel":
            continue
        expanded = ["nvidia_drm", "nvidia_modeset", "nvidia_uvm", "nvidia"] if module == "nvidia" else [module]
        for item in expanded:
            if item not in modules:
                modules.append(item)
    return modules


def _qemu_running(vm_name: str) -> bool:
    needle = f"guest={vm_name},".encode()
    for cmdline in PROC_ROOT.glob("[0-9]*/cmdline"):
        try:
            value = cmdline.read_bytes()
        except OSError:
            continue
        if b"qemu-system" in value and needle in value:
            return True
    return False


def _bound_driver(device_path: Path) -> str | None:
    try:
        return (device_path / "driver").resolve(strict=True).name
    except OSError:
        return None


def _restore_device(device: PciDevice, runner: Runner) -> str:
    address = f"0000:{device.address}"
    device_path = PCI_DEVICES_ROOT / address
    if not device_path.is_dir():
        raise AppError(f"PCI device disappeared: {address}")
    expected = _driver_module(device)
    current = _bound_driver(device_path)

    # If there was no original host driver, restore the device to an unbound
    # state instead of guessing a driver such as nouveau/nvidia.
    if expected is None:
        if current:
            try:
                (device_path / "driver" / "unbind").write_text(address, encoding="utf-8")
            except OSError as exc:
                raise AppError(f"Cannot unbind {address} from {current}: {exc}") from exc
        override = device_path / "driver_override"
        if override.exists():
            try:
                override.write_text("\n", encoding="utf-8")
            except OSError as exc:
                raise AppError(f"Cannot clear driver_override for {address}: {exc}") from exc
        return ""

    if current and current != expected:
        try:
            (device_path / "driver" / "unbind").write_text(address, encoding="utf-8")
        except OSError as exc:
            raise AppError(f"Cannot unbind {address} from {current}: {exc}") from exc
    override = device_path / "driver_override"
    if override.exists():
        try:
            override.write_text("\n", encoding="utf-8")
        except OSError as exc:
            raise AppError(f"Cannot clear driver_override for {address}: {exc}") from exc
    runner.run(["modprobe", expected], check=False)
    if _bound_driver(device_path) != expected:
        try:
            PCI_DRIVERS_PROBE.write_text(address, encoding="utf-8")
        except OSError as exc:
            raise AppError(f"Cannot reprobe {address}: {exc}") from exc
    actual = _bound_driver(device_path)
    if actual != expected:
        raise AppError(f"PCI {address} expected driver {expected}, but is bound to {actual or 'none'}.")
    return expected


def _write_optional(path: Path, value: str) -> None:
    try:
        if path.exists():
            path.write_text(value, encoding="utf-8")
    except OSError:
        pass


def _clear_driver_override(device: PciDevice) -> None:
    override = PCI_DEVICES_ROOT / f"0000:{device.address}" / "driver_override"
    if override.exists():
        try:
            override.write_text("\n", encoding="utf-8")
        except OSError as exc:
            raise AppError(f"Cannot clear driver_override for PCI {device.address}: {exc}") from exc


def _reactivate_graphical_seat(runner: Runner) -> None:
    """Best-effort VT/connector refresh after a single GPU returns to the host."""
    script = r"""
session=""
for attempt in {1..30}; do
  session="$(loginctl show-seat seat0 -p ActiveSession --value 2>/dev/null || true)"
  [[ -n "$session" ]] && break
  sleep 0.25
done
[[ -n "$session" ]] || exit 0
tty="$(loginctl show-session "$session" -p TTY --value 2>/dev/null || true)"
if [[ "$tty" =~ ^tty([0-9]+)$ ]]; then
  chvt "${BASH_REMATCH[1]}" || true
fi
command -v xrandr >/dev/null 2>&1 || exit 0
command -v runuser >/dev/null 2>&1 || exit 0
uid="$(loginctl show-session "$session" -p User --value 2>/dev/null || true)"
user="$(loginctl show-session "$session" -p Name --value 2>/dev/null || true)"
[[ "$uid" =~ ^[0-9]+$ && -n "$user" ]] || exit 0
auth="/run/user/$uid/gdm/Xauthority"
xr=(runuser -u "$user" -- env DISPLAY=:0 XAUTHORITY="$auth" xrandr)
outputs=()
for attempt in {1..40}; do
  if [[ ! -r "$auth" ]]; then
    auth="$(getent passwd "$uid" | cut -d: -f6)/.Xauthority"
    xr=(runuser -u "$user" -- env DISPLAY=:0 XAUTHORITY="$auth" xrandr)
  fi
  mapfile -t outputs < <("${xr[@]}" --query 2>/dev/null | awk '$2 == "connected" {print $1}')
  ((${#outputs[@]})) && break
  sleep 0.25
done
((${#outputs[@]})) || exit 0
# Mutter can reapply the saved high-refresh mode shortly after GDM starts.
# Wait until that initialization settles, then select each monitor's EDID
# preferred mode as a hardware-neutral recovery baseline.
sleep 3
for output in "${outputs[@]}"; do
  "${xr[@]}" --output "$output" --off || true
done
sleep 1
for output in "${outputs[@]}"; do
  "${xr[@]}" --output "$output" --preferred || true
done
runuser -u "$user" -- env DISPLAY=:0 XAUTHORITY="$auth" xset dpms force on 2>/dev/null || true
"""
    runner.run(["bash", "-lc", script], check=False)


def recover_single_gpu(vm_name: str, devices: list[PciDevice], runner: Runner) -> None:
    """Reclaim a single passthrough GPU after a failed VM start."""
    require_root()
    name = valid_vm_name(vm_name)
    if not devices:
        raise AppError(f"VM {name} has no recorded single-GPU passthrough devices.")
    if _qemu_running(name):
        raise AppError(f"VM {name} is still running; shut it down before reclaiming its GPU.")
    stale_nvidia = [
        device for device in devices
        if _driver_module(device) == "nvidia"
        and _bound_driver(PCI_DEVICES_ROOT / f"0000:{device.address}") != "nvidia"
        and (SYS_MODULE_ROOT / "nvidia").exists()
    ]
    if stale_nvidia:
        for device in devices:
            _clear_driver_override(device)
        addresses = ", ".join(f"0000:{device.address}" for device in stale_nvidia)
        raise AppError(
            f"NVIDIA is still loaded after {addresses} was detached. Its kernel state may be stale; "
            "driver_override was cleared, but a reboot is required before starting the VM again."
        )
    expected_drivers = [_driver_module(device) for device in devices]
    display_active = runner.run(
        ["systemctl", "is-active", "--quiet", "display-manager.service"], check=False,
    )
    if (
        all(driver is not None for driver in expected_drivers)
        and getattr(display_active, "returncode", 1) == 0
        and all(
            _bound_driver(PCI_DEVICES_ROOT / f"0000:{device.address}") == expected
            for device, expected in zip(devices, expected_drivers)
        )
    ):
        print(f"{name}: host GPU and display manager already healthy; skipping GPU reclaim.")
        return
    runner.run(["systemctl", "stop", "display-manager.service"], check=False)
    runner.run(["systemctl", "stop", "nvidia-persistenced.service"], check=False)
    errors: list[str] = []
    restored: list[str] = []
    for device in devices:
        try:
            restored.append(_restore_device(device, runner))
        except AppError as exc:
            errors.append(str(exc))
    if "nvidia" in restored:
        runner.run(["modprobe", "nvidia_drm"], check=False)
    for bind in VTCON_ROOT.glob("vtcon*/bind"):
        _write_optional(bind, "1")
    _write_optional(EFI_FRAMEBUFFER_BIND, "efi-framebuffer.0")
    if errors:
        raise AppError(
            "Host display recovery was incomplete; display-manager was left stopped and a reboot is recommended:\n- "
            + "\n- ".join(errors)
        )
    runner.run(["systemctl", "daemon-reload"], check=False)
    runner.run(["systemctl", "start", "nvidia-persistenced.service"], check=False)
    runner.run(["systemctl", "restart", "display-manager.service"], check=False)
    runner.run(["systemctl", "is-active", "--quiet", "display-manager.service"], check=False)
    _reactivate_graphical_seat(runner)
    print(f"{name}: host GPU drivers restored; display-manager restarted.")


def install_dynamic_hooks(vm_name: str) -> None:
    require_root()
    name = valid_vm_name(vm_name)
    quoted = shlex.quote(name)
    body = f"""
[[ "${{1:-}}" == {quoted} ]] || exit 0
case "${{2:-}}:${{3:-}}" in
  prepare:begin)
    /usr/local/sbin/kvm-aavm mark-pending --vm {quoted}
    ;;
  release:end)
    systemd-run --quiet --collect --on-active=3s --unit=kvm-aavm-randomize-{name} /usr/local/sbin/kvm-aavm randomize-xml --vm {quoted}
    ;;
esac
"""
    _write_hook(HOOK_ROOT / name / "05-dynamic-randomization", body)
    _remove_legacy([
        LEGACY_HOOK_ROOT / name / "prepare" / "begin" / "05-kvm-aavm-generation",
        LEGACY_HOOK_ROOT / name / "release" / "end" / "95-kvm-aavm-randomize",
    ])


def remove_dynamic_hooks(vm_name: str) -> None:
    name = valid_vm_name(vm_name)
    (HOOK_ROOT / name / "05-dynamic-randomization").unlink(missing_ok=True)
    _remove_legacy([
        LEGACY_HOOK_ROOT / name / "prepare" / "begin" / "05-kvm-aavm-generation",
        LEGACY_HOOK_ROOT / name / "release" / "end" / "95-kvm-aavm-randomize",
    ])


def install_performance_hook(vm_name: str) -> None:
    """Use the host's performance EPP/governor only while managed VMs run."""
    require_root()
    name = valid_vm_name(vm_name)
    quoted = shlex.quote(name)
    body = f'''
[[ "${{1:-}}" == {quoted} ]] || exit 0
state=/run/kvm-aavm-performance
marker="$state/active-{name}"
mkdir -p "$state"
exec 9>"$state/lock"
flock 9
activate() {{
  if ! compgen -G "$state/active-*" >/dev/null; then
    : > "$state/saved.new"
    for path in /sys/devices/system/cpu/cpufreq/policy*/scaling_governor \
                /sys/devices/system/cpu/cpufreq/policy*/energy_performance_preference; do
      [[ -r "$path" ]] || continue
      printf '%s\\t%s\\n' "$path" "$(<"$path")" >> "$state/saved.new"
    done
    mv "$state/saved.new" "$state/saved"
  fi
  touch "$marker"
  for path in /sys/devices/system/cpu/cpufreq/policy*/scaling_governor; do
    [[ -w "$path" ]] && printf '%s' performance > "$path" || true
  done
  for path in /sys/devices/system/cpu/cpufreq/policy*/energy_performance_preference; do
    [[ -w "$path" ]] && printf '%s' performance > "$path" || true
  done
}}
deactivate() {{
  rm -f "$marker"
  if ! compgen -G "$state/active-*" >/dev/null && [[ -r "$state/saved" ]]; then
    while IFS=$'\\t' read -r path value; do
      [[ -w "$path" ]] && printf '%s' "$value" > "$path" || true
    done < "$state/saved"
    rm -f "$state/saved"
  fi
}}
case "${{2:-}}:${{3:-}}" in
  prepare:begin) activate ;;
  stopped:end|release:end) deactivate ;;
esac
'''
    _write_hook(HOOK_ROOT / name / "10-host-performance", body)


def remove_performance_hook(vm_name: str) -> None:
    require_root()
    name = valid_vm_name(vm_name)
    (HOOK_ROOT / name / "10-host-performance").unlink(missing_ok=True)
    try:
        (HOOK_ROOT / name).rmdir()
    except OSError:
        pass


def remove_single_gpu_hooks(vm_name: str) -> None:
    require_root()
    name = valid_vm_name(vm_name)
    (HOOK_ROOT / name / "20-single-gpu").unlink(missing_ok=True)
    _remove_legacy([
        LEGACY_HOOK_ROOT / name / "prepare" / "begin" / "20-single-gpu",
        LEGACY_HOOK_ROOT / name / "release" / "end" / "20-single-gpu",
    ])


def install_single_gpu_hooks(
    vm_name: str, devices: list[PciDevice], *, force_bus_reset: bool = False,
) -> None:
    require_root()
    name = valid_vm_name(vm_name)
    if not devices:
        raise AppError("At least one GPU PCI function is required.")
    quoted = shlex.quote(name)
    unload_modules = _gpu_unload_modules(devices)
    # NVIDIA's PCI remove path can wait indefinitely if nvidia_modeset or UVM
    # still owns a reference to the core module.  Drop the client modules while
    # the GPU is still bound, then unbind the PCI functions, and only then
    # remove the core nvidia module.  Other GPU drivers retain the established
    # unbind-before-unload order.
    pre_unbind_modules = " ".join(
        shlex.quote(module) for module in unload_modules
        if module in {"nvidia_drm", "nvidia_modeset", "nvidia_uvm"}
    )
    post_unbind_modules = " ".join(
        shlex.quote(module) for module in unload_modules
        if module not in {"nvidia_drm", "nvidia_modeset", "nvidia_uvm"}
    )
    restore_lines: list[str] = []
    restored_modules: list[str] = []
    for device in devices:
        module = _driver_module(device)
        address = f"0000:{device.address}"
        restore_lines.extend([
            f"  dev=/sys/bus/pci/devices/{address}",
            f"  if [[ -L \"$dev/driver\" && \"$(basename \"$(readlink \"$dev/driver\")\")\" == vfio-pci ]]; then printf '%s' {address} > \"$dev/driver/unbind\" 2>/dev/null || true; fi",
            "  [[ -w \"$dev/driver_override\" ]] && echo > \"$dev/driver_override\" || true",
        ])
        if module is not None:
            restore_lines.extend([
                f"  modprobe {shlex.quote(module)} || true",
                f"  echo {address} > /sys/bus/pci/drivers_probe || true",
            ])
            if module not in restored_modules:
                restored_modules.append(module)
    if "nvidia" in restored_modules:
        restore_lines.append("  modprobe nvidia_drm || true")
    restore_devices = "\n".join(restore_lines)
    unbind_lines: list[str] = []
    bind_lines: list[str] = []
    for device in devices:
        address = f"0000:{device.address}"
        unbind_lines.extend([
            f"    dev=/sys/bus/pci/devices/{address}",
            f"    if [[ -L \"$dev/driver\" && \"$(basename \"$(readlink \"$dev/driver\")\")\" != vfio-pci ]]; then unbind_pci_driver {address} \"$dev/driver/unbind\" || failed=1; fi",
        ])
        bind_lines.extend([
            f"  dev=/sys/bus/pci/devices/{address}",
            "  [[ -w \"$dev/driver_override\" ]] && echo vfio-pci > \"$dev/driver_override\" || failed=1",
            f"  echo {address} > /sys/bus/pci/drivers_probe || failed=1",
            "  [[ -L \"$dev/driver\" && \"$(basename \"$(readlink \"$dev/driver\")\")\" == vfio-pci ]] || failed=1",
        ])
    unbind_devices = "\n".join(unbind_lines)
    bind_devices = "\n".join(bind_lines)
    # VFIO already selects the safest reset method supported by the device.
    # Older profiles exposed a force_bus_reset option, but writing bus to
    # reset_method is rejected by many modern NVIDIA drivers and made libvirt
    # abort before QEMU was created. Keep the keyword for API compatibility,
    # while deliberately avoiding any reset_method sysfs operation here.
    del force_bus_reset
    bus_reset_devices = ""
    body = f"""
[[ "${{1:-}}" == {quoted} ]] || exit 0
exec >>/var/log/libvirt/qemu/{name}-gpu-hook.log 2>&1
handoff_started=0
handoff_committed=0
bounded() {{
  timeout --signal=TERM --kill-after=5s "$@"
}}
bind_efi_framebuffer() {{
  local bind=/sys/bus/platform/drivers/efi-framebuffer/bind
  local device=/sys/bus/platform/devices/efi-framebuffer.0
  [[ -w "$bind" && -e "$device" ]] || return 0
  printf '%s' efi-framebuffer.0 > "$bind" 2>/dev/null || true
}}
unload_gpu_modules() {{
  local attempt module failed status
  (($#)) || return 0
  failed=1
  # NVIDIA can keep its modules referenced by DRM even after the graphical
  # session is gone.  Module removal is an optimization; PCI unbind below is
  # the operation required for the managed libvirt hostdev handoff.
  for attempt in {{1..8}}; do
    failed=0
    for module in "$@"; do
      [[ -d "/sys/module/$module" ]] || continue
      timeout --signal=TERM --kill-after=2s 5s modprobe -r "$module" 2>/dev/null || {{
        status=$?
        if (( status == 124 || status == 137 )); then
          return 1
        fi
        failed=1
      }}
    done
    (( failed )) || return 0
    sleep 0.25
  done
  return 1
}}
unbind_pci_driver() {{
  local address="$1" unbind_path="$2"
  timeout --signal=TERM --kill-after=2s 15s \
    bash -c 'printf "%s" "$1" > "$2"' _ "$address" "$unbind_path"
}}
reactivate_graphical_seat() {{
  local session tty uid user auth output attempt
  for attempt in {{1..30}}; do
    session="$(loginctl show-seat seat0 -p ActiveSession --value 2>/dev/null || true)"
    [[ -n "$session" ]] && break
    sleep 0.25
  done
  [[ -n "${{session:-}}" ]] || return 0
  tty="$(loginctl show-session "$session" -p TTY --value 2>/dev/null || true)"
  if [[ "$tty" =~ ^tty([0-9]+)$ ]]; then chvt "${{BASH_REMATCH[1]}}" || true; fi
  command -v xrandr >/dev/null 2>&1 || return 0
  command -v runuser >/dev/null 2>&1 || return 0
  uid="$(loginctl show-session "$session" -p User --value 2>/dev/null || true)"
  user="$(loginctl show-session "$session" -p Name --value 2>/dev/null || true)"
  [[ "$uid" =~ ^[0-9]+$ && -n "$user" ]] || return 0
  auth="/run/user/$uid/gdm/Xauthority"
  outputs=()
  for attempt in {{1..40}}; do
    if [[ ! -r "$auth" ]]; then auth="$(getent passwd "$uid" | cut -d: -f6)/.Xauthority"; fi
    mapfile -t outputs < <(runuser -u "$user" -- env DISPLAY=:0 XAUTHORITY="$auth" xrandr --query 2>/dev/null | awk '$2 == "connected" {{print $1}}')
    ((${{#outputs[@]}})) && break
    sleep 0.25
  done
  ((${{#outputs[@]}})) || return 0
  sleep 3
  for output in "${{outputs[@]}}"; do
    runuser -u "$user" -- env DISPLAY=:0 XAUTHORITY="$auth" xrandr --output "$output" --off || true
  done
  sleep 1
  for output in "${{outputs[@]}}"; do
    runuser -u "$user" -- env DISPLAY=:0 XAUTHORITY="$auth" xrandr --output "$output" --preferred || true
  done
  runuser -u "$user" -- env DISPLAY=:0 XAUTHORITY="$auth" xset dpms force on 2>/dev/null || true
}}
drain_gpu_clients() {{
  local attempt
  # GDM/session processes can survive terminate-seat and keep NVIDIA device
  # nodes busy.  Wait first, then terminate stragglers; reserve KILL for the
  # bounded final step so an unresponsive client cannot hang PCI unbind.
  compgen -G '/dev/nvidia*' >/dev/null 2>&1 || return 0
  for attempt in {{1..120}}; do
    fuser /dev/nvidia* >/dev/null 2>&1 || return 0
    sleep 0.5
  done
  fuser -TERM -k /dev/nvidia* 2>/dev/null || true
  for attempt in {{1..20}}; do
    fuser /dev/nvidia* >/dev/null 2>&1 || return 0
    sleep 0.5
  done
  fuser -KILL -k /dev/nvidia* 2>/dev/null || true
}}
deactivate_graphical_outputs() {{
  local session uid user auth output
  session="$(loginctl show-seat seat0 -p ActiveSession --value 2>/dev/null || true)"
  [[ -n "$session" ]] || return 0
  command -v xrandr >/dev/null 2>&1 || return 0
  command -v runuser >/dev/null 2>&1 || return 0
  uid="$(loginctl show-session "$session" -p User --value 2>/dev/null || true)"
  user="$(loginctl show-session "$session" -p Name --value 2>/dev/null || true)"
  [[ "$uid" =~ ^[0-9]+$ && -n "$user" ]] || return 0
  auth="/run/user/$uid/gdm/Xauthority"
  [[ -r "$auth" ]] || auth="$(getent passwd "$uid" | cut -d: -f6)/.Xauthority"
  [[ -r "$auth" ]] || return 0
  mapfile -t outputs < <(runuser -u "$user" -- env DISPLAY=:0 XAUTHORITY="$auth" xrandr --query 2>/dev/null | awk '$2 == "connected" {{print $1}}')
  for output in "${{outputs[@]}}"; do
    runuser -u "$user" -- env DISPLAY=:0 XAUTHORITY="$auth" xrandr --output "$output" --off || true
  done
  sleep 1
}}
restore_host() {{
  # Disable EXIT rollback first so an unexpected recovery error cannot recurse.
  handoff_started=0
  echo "$(date -Is) restoring host GPU"
{restore_devices}
  if command -v udevadm >/dev/null 2>&1; then udevadm settle --timeout=10 || true; fi
  for vt in /sys/class/vtconsole/vtcon*/bind; do [[ -w "$vt" ]] && echo 1 > "$vt" || true; done
  bind_efi_framebuffer
  systemctl daemon-reload || true
  bounded 20s systemctl start nvidia-persistenced.service || true
  bounded 30s systemctl restart display-manager.service || true
  bounded 10s systemctl is-active --quiet display-manager.service || true
  reactivate_graphical_seat
}}
rollback_handoff() {{
  local status=$?
  trap - EXIT
  if (( status != 0 && handoff_started && ! handoff_committed )); then
    echo "$(date -Is) GPU handoff failed; running automatic host display rollback"
    restore_host || true
  fi
  exit "$status"
}}
trap rollback_handoff EXIT
case "${{2:-}}:${{3:-}}" in
  prepare:begin)
    echo "$(date -Is) releasing host GPU"
    systemctl daemon-reload || true
    handoff_started=1
    deactivate_graphical_outputs
    bounded 30s systemctl stop display-manager.service || true
    bounded 20s systemctl stop nvidia-persistenced.service || true
    # GDM's autologin session can outlive display-manager.service on Ubuntu.
    # Terminate only the local graphical seat; SSH sessions have no seat and
    # remain available while the single physical GPU belongs to the guest.
    if command -v loginctl >/dev/null 2>&1; then
      bounded 15s loginctl terminate-seat seat0 || true
    fi
    drain_gpu_clients
    for vt in /sys/class/vtconsole/vtcon*/bind; do [[ -w "$vt" ]] && echo 0 > "$vt" || true; done
    if [[ -w /sys/bus/platform/drivers/efi-framebuffer/unbind && -e /sys/bus/platform/devices/efi-framebuffer.0 ]]; then
      printf '%s' efi-framebuffer.0 > /sys/bus/platform/drivers/efi-framebuffer/unbind 2>/dev/null || true
    fi
    # Module removal is best effort.  A loaded vendor module is harmless once
    # the selected PCI functions are detached and handed to vfio-pci.
    if ! unload_gpu_modules {pre_unbind_modules}; then
      echo "GPU client modules remain loaded; continuing with PCI unbind"
    fi
    failed=0
{unbind_devices}
    if (( failed )); then
      echo "GPU device unbind failed; aborting VM start and restoring the host"
      exit 1
    fi
    if ! unload_gpu_modules {post_unbind_modules}; then
      echo "GPU vendor modules remain loaded after PCI unbind; continuing with VFIO"
    fi
    if ! modprobe vfio-pci; then
      echo "Could not load vfio-pci; aborting VM start and restoring the host"
      exit 1
    fi
    failed=0
{bind_devices}
    if (( failed )); then
      echo "Could not bind every selected GPU function to vfio-pci"
      exit 1
    fi
{bus_reset_devices}
    handoff_committed=1
    ;;
  release:end)
    restore_host
    ;;
esac
"""
    _write_hook(HOOK_ROOT / name / "20-single-gpu", body)
    _remove_legacy([
        LEGACY_HOOK_ROOT / name / "prepare" / "begin" / "20-single-gpu",
        LEGACY_HOOK_ROOT / name / "release" / "end" / "20-single-gpu",
    ])
