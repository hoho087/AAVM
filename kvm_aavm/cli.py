from __future__ import annotations

import argparse
import json
import os
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from . import __version__
from .build import build_all
from .hardware import PciDevice, UsbDevice, gpu_groups, host_fingerprint, pci_devices, print_preflight, usb_devices
from .hooks import (
    install_dynamic_hooks, install_performance_hook, install_single_gpu_hooks, recover_single_gpu,
    remove_dynamic_hooks, remove_single_gpu_hooks,
)
from .host import (
    configure_host, configure_update_protection, ensure_nested_virtualization,
    install_application, install_pending_service,
)
from .identity import rerandomize
from .kernel import build_kernel, install_memflow, sign_custom_kernels
from .offline import install_packages, print_validation
from .paths import PENDING_DIR, PROJECT_DIR, VM_DIR, ensure_state_dirs
from .state import clear_pending, load_host_state, load_profile, mark_pending, pending_names, save_profile, vm_lock
from .util import AppError, Runner, prompt, prompt_int, prompt_yes_no, require_root, valid_vm_name
from .vm import (
    configure_cpu_layout, configure_guest_security, configure_minimal_devices, configure_passthrough, create_vm, enable_devirtualized,
    enable_gpu_setup, finalize_vm,
    new_profile, randomize_all, randomize_xml, resume_vm, set_dynamic,
)
from .xmlgen import validate_required


def _recommended_resources() -> tuple[int, int]:
    host = host_fingerprint()
    memory = max(4, min(24, host["memory_gib"] // 2))
    cpu = host["cpu"]
    threads = 2 if int(cpu.get("threads_per_core", 1)) >= 2 else 1
    physical = max(1, int(cpu.get("cores", cpu["logical_cpus"] // threads)))
    reserve = 2 if physical >= 8 else 1 if physical >= 2 else 0
    guest_cores = max(1, physical - reserve)
    vcpus = max(2, min(12, guest_cores * threads))
    vcpus -= vcpus % threads
    return memory, vcpus


PCI_KIND = {
    "01": "儲存控制器",
    "02": "網路控制器",
    "03": "顯示控制器",
    "04": "音訊/多媒體",
    "0c03": "USB 控制器",
}


def _interface_details(names: list[str]) -> str:
    details = []
    for name in names:
        root = Path("/sys/class/net") / name
        address = (root / "address").read_text().strip() if (root / "address").is_file() else "?"
        state = (root / "operstate").read_text().strip() if (root / "operstate").is_file() else "?"
        details.append(f"{name} (MAC {address}, {state})")
    return ", ".join(details) if details else "無"

def _pci_kind(device: PciDevice) -> str:
    return PCI_KIND.get(device.class_code, PCI_KIND.get(device.class_code[:2], "其他裝置"))


def _default_keep_virtual_network(
    previous: dict, selected_pci: list[PciDevice], has_physical_network: bool,
) -> bool:
    if previous.get("virtual_network_choice_set", False):
        return not bool(previous.get("disable_virtual_network", False))
    # A passed-through USB controller may carry a USB NIC which is no longer
    # visible to the host after VFIO takes ownership of the controller.
    has_usb_controller = any(
        device.class_code.lower().startswith("0c03") for device in selected_pci
    )
    return not (has_physical_network or has_usb_controller)


def _print_pci(index: int | str, device: PciDevice) -> None:
    print(f"[{index}] PCI {device.address} — {_pci_kind(device)}")
    print(f"    名稱: {device.description}")
    print(f"    ID: {device.vendor_id}:{device.device_id} | IOMMU: {device.iommu_group if device.iommu_group is not None else '無'} | 驅動: {device.driver or '無'}")
    if device.interfaces:
        print(f"    網路介面: {_interface_details(device.interfaces)}")


def _print_usb(index: int | str, device: UsbDevice) -> None:
    print(f"[{index}] USB Bus {device.bus:03d} Device {device.device:03d}")
    print(f"    名稱: {device.description}")
    print(f"    ID: {device.vendor_id}:{device.product_id} | 網路介面: {_interface_details(device.interfaces)}")



def _choose_indices(label: str, count: int, defaults: list[int] | None = None) -> list[int]:
    default_text = ",".join(str(value) for value in (defaults or []))
    while True:
        raw = prompt(label, default_text) if default_text else prompt(label)
        if raw.strip() in {"", "0"}:
            return []
        try:
            selected: set[int] = set()
            for token in raw.replace(" ", "").split(","):
                if "-" in token:
                    start, end = (int(value) for value in token.split("-", 1))
                    selected.update(range(start, end + 1))
                else:
                    selected.add(int(token))
        except ValueError:
            print("格式錯誤；請輸入例如 1,3,5-7，或輸入 0 代表不選。")
            continue
        if not selected or min(selected) < 1 or max(selected) > count:
            print(f"編號必須介於 1 與 {count}。")
            continue
        return sorted(selected)

def _select_gpu() -> list[PciDevice]:
    groups = gpu_groups(pci_devices())
    if not groups:
        raise AppError("No display controller was detected by lspci.")
    for index, group in enumerate(groups, 1):
        print(f"\nGPU 組 {index}（PCI slot {group[0].slot}）")
        for function, device in enumerate(group, 1):
            _print_pci(f"{index}.{function}", device)
    choice = prompt_int("選擇要直通給 VM 的顯示卡", 1, 1, len(groups))
    chosen = groups[choice - 1]
    if not any(d.class_code.startswith("03") for d in chosen):
        raise AppError("The selected functions do not contain a GPU display controller.")
    print("此 PCI slot 的全部功能都會由單 GPU hook 從 Ubuntu 安全解綁。")
    return chosen


def _select_gpu_guest_functions(
    devices: list[PciDevice], current: set[str] | None = None,
) -> list[str]:
    """Choose which isolated GPU functions QEMU actually receives."""
    display = [device.address for device in devices if device.class_code.startswith("03")]
    if not display and devices:
        display = [devices[0].address]
    audio = [device for device in devices if device.class_code.startswith("04")]
    selected = set(display)
    if audio:
        audio_default = current is not None and any(item.address in current for item in audio)
        print("GPU 顯示功能會直通；同 slot 的 HDMI/DP 音訊可分別選擇。")
        include_audio = prompt_yes_no(
            "同時直通 GPU HDMI/DP 音訊",
            audio_default,
        )
        if include_audio:
            selected.update(item.address for item in audio)
    return [device.address for device in devices if device.address in selected]


def _select_additional_pci(excluded: set[str], current: set[str] | None = None, ask: bool = True) -> list[PciDevice]:
    devices = [
        device for device in pci_devices()
        if device.address not in excluded and device.class_code[:2] not in {"03", "05", "06", "08"}
    ]
    if not devices:
        print("沒有偵測到可列出的其他 PCI/PCIe 端點裝置。")
        return []
    if ask and not (current or set()) and not prompt_yes_no("直通其他 PCI/PCIe 實體裝置（網卡、聲卡、USB 控制器等）", False):
        return []
    print("警告：直通使用中的網卡、儲存或 USB 控制器會使 Ubuntu 失去對應裝置。")
    for index, device in enumerate(devices, 1):
        _print_pci(index, device)
    defaults = [index for index, device in enumerate(devices, 1) if device.address in (current or set())]
    selected = _choose_indices("輸入 PCI 裝置編號（可用 1,3,5-7；0=不選）", len(devices), defaults)
    return [devices[index - 1] for index in selected]



def _usb_key(device: UsbDevice | dict) -> tuple[str, str, int, int]:
    if isinstance(device, UsbDevice):
        return device.vendor_id, device.product_id, device.bus, device.device
    return str(device["vendor_id"]), str(device["product_id"]), int(device.get("bus", 0)), int(device.get("device", 0))


def _select_usb_devices(current: list[dict] | None = None, ask: bool = True) -> list[UsbDevice]:
    devices = usb_devices()
    if not devices:
        print("沒有偵測到可直通的 USB 周邊裝置（root hub 已自動隱藏）。")
        return []
    if ask and not current and not prompt_yes_no("直通 USB 實體裝置（USB 網卡、聲卡、接收器等）", False):
        return []
    print("警告：USB 鍵盤、滑鼠或正在使用的 USB 網卡直通後，Ubuntu 會暫時失去該裝置。")
    for index, device in enumerate(devices, 1):
        _print_usb(index, device)
    current_keys = {
        _usb_key(item)
        for item in (current or [])
    }
    defaults = [index for index, device in enumerate(devices, 1) if _usb_key(device) in current_keys]
    selected = _choose_indices("輸入 USB 裝置編號（可用 1,3,5-7；0=不選）", len(devices), defaults)
    return [devices[index - 1] for index in selected]



def _usb_configs(selected: list[UsbDevice]) -> list[dict]:
    all_devices = usb_devices()
    counts: dict[tuple[str, str], int] = {}
    for device in all_devices:
        key = (device.vendor_id, device.product_id)
        counts[key] = counts.get(key, 0) + 1
    configs = []
    for device in selected:
        key = (device.vendor_id, device.product_id)
        configs.append({
            "vendor_id": device.vendor_id, "product_id": device.product_id,
            "bus": device.bus, "device": device.device,
            "description": device.description, "interfaces": device.interfaces,
            "network": device.is_network, "match_address": counts.get(key, 0) > 1,
        })
    return configs
def _edit_identity(profile: dict) -> dict:
    identity = profile["identity"]
    print(json.dumps(identity, ensure_ascii=False, indent=2))
    if not prompt_yes_no("是否手動修改仿真資料", False):
        return profile
    editable = [
        "manufacturer", "product", "version", "system_serial", "baseboard_product",
        "baseboard_serial", "chassis_serial", "memory_manufacturer", "memory_part", "memory_serial", "disk_model",
    ]
    for key in editable:
        identity[key] = prompt(key, str(identity[key]))
    return profile


def _start_windows_installer(name: str, runner: Runner) -> None:
    """Start an install-stage VM and accept Windows optical-media boot."""
    runner.run(["virsh", "start", name])
    # Microsoft's installer deliberately offers only a short "Press any key"
    # window. OVMF reaches it at different times on different hosts, so cover
    # the useful interval instead of relying on one hardware-specific delay.
    # Extra spaces while Windows PE is loading are harmless.
    if not runner.dry_run:
        time.sleep(3)
    for attempt in range(8):
        runner.run(["virsh", "send-key", name, "KEY_SPACE"], check=False)
        if not runner.dry_run and attempt < 7:
            time.sleep(1)
    print(f"{name}: 已在光碟開機時窗重試送鍵；可開啟 virt-manager 繼續 Windows 安裝。")


def create_wizard(runner: Runner) -> None:
    # Disk size remains the first VM-creation prompt.
    disk_gib = prompt_int("新建虛擬磁碟容量 (GiB)", 240, 32, 8192)
    name = valid_vm_name(prompt("VM 名稱", "win10-aavm"))
    memory_default, vcpu_default = _recommended_resources()
    current_host = host_fingerprint()
    memory = prompt_int("記憶體 (GiB)", memory_default, 4, max(4, current_host["memory_gib"] - 2))
    host_threads = 2 if int(current_host["cpu"].get("threads_per_core", 1)) >= 2 else 1
    max_vcpus = max(2, int(current_host["cpu"]["logical_cpus"]) - host_threads)
    vcpus = prompt_int("vCPU 數量", min(vcpu_default, max_vcpus), 2, max_vcpus)
    if host_threads == 2 and vcpus % 2:
        raise AppError("SMT 主機請使用偶數 vCPU，才能配對完整的實體核心 threads。")
    bundled_isos = sorted(
        path for path in (PROJECT_DIR / "KVM").glob("*.iso")
        if "win" in path.name.lower() and "ubuntu" not in path.name.lower()
    )
    default_iso = str(bundled_isos[0]) if bundled_isos else None
    windows_iso = prompt("Windows ISO 的絕對路徑", default_iso)
    if not windows_iso:
        raise AppError("請提供自己合法取得的 Windows ISO 絕對路徑。")
    owner_uid = int(os.environ.get("SUDO_UID", os.getuid()))
    profile = new_profile(name, disk_gib, memory, vcpus, windows_iso, owner_uid)
    profile = _edit_identity(profile)
    print("\n將建立不含硬體直通的 Windows 安裝 VM：")
    print(json.dumps({
        "name": name, "disk_gib": disk_gib, "memory_gib": memory,
        "vcpus": vcpus, "console": "SPICE/VGA", "passthrough": False,
    }, ensure_ascii=False, indent=2))
    if not prompt_yes_no("開始建置（QEMU/OVMF 建置可能需要很長時間）", False):
        print("已取消。")
        return
    create_vm(profile, runner, build=True, start=False)
    install_performance_hook(name)
    if prompt_yes_no("現在啟動 Windows 安裝程式", True):
        _start_windows_installer(name, runner)
    print("完成 Windows 安裝並關機後，執行 VM 第 2 步『去虛擬化（保留 VNC/VGA）』。")

def _profile_gpu_devices(profile: dict) -> list[PciDevice]:
    addresses = list(profile.get("passthrough", {}).get("gpu_pci", []))
    devices_by_address = {
        item["address"]: PciDevice(**item)
        for item in profile.get("host", {}).get("pci", [])
    }
    missing = [address for address in addresses if address not in devices_by_address]
    if missing:
        raise AppError("PCI data is missing for: " + ", ".join(missing))
    return [devices_by_address[address] for address in addresses]


def _leave_single_gpu_stage(name: str, profile: dict, runner: Runner) -> None:
    """Remove the VM hook and reclaim the host display when leaving final stage."""
    gpu_devices = _profile_gpu_devices(profile)
    was_final = profile.get("stage") in {"gpu-setup", "final"} and bool(gpu_devices)
    remove_single_gpu_hooks(name)
    if was_final:
        recover_single_gpu(name, gpu_devices, runner)


def resume_creation(name: str, runner: Runner, *, ask_start: bool = False) -> None:
    profile = load_profile(valid_vm_name(name))
    _leave_single_gpu_stage(name, profile, runner)
    resume_vm(name, runner, start=False)
    install_performance_hook(name)
    print(f"{name}: 已恢復 Windows 安裝階段（SPICE/虛擬 VGA；實體 GPU 尚未直通）。")
    if ask_start and prompt_yes_no("現在啟動 Windows 安裝程式", True):
        _start_windows_installer(name, runner)
    print("完成 Windows 安裝並關機後，執行 VM 第 2 步『去虛擬化（保留 VNC/VGA）』。")


def devirtualize_creation(name: str, runner: Runner) -> None:
    name = valid_vm_name(name)
    profile = load_profile(name)
    guest_vtd = prompt_yes_no(
        "啟用 guest VT-d/vIOMMU（Windows 相容模式）",
        bool(profile.get("guest_vtd", False)),
    )
    guest_vtd_intremap = False
    if guest_vtd:
        guest_vtd_intremap = prompt_yes_no(
            "額外啟用 interrupt remapping（實驗性；QEMU 11 可能使 Windows 卡在 Start Boot Option）",
            bool(profile.get("guest_vtd_intremap", False)),
        )
    guest_secure_boot = prompt_yes_no(
        "啟用 Guest UEFI Secure Boot（Windows 10/11 建議）",
        bool(profile.get("guest_secure_boot", True)),
    )
    guest_dma_protection = False
    if guest_vtd:
        guest_dma_protection = prompt_yes_no(
            "讓 Windows 啟用核心 DMA 保護（保留 interrupt-remapping 相容模式）",
            bool(profile.get("guest_dma_protection", True)),
        )
    guest_core_isolation = prompt_yes_no(
        "啟用 Windows 核心隔離／記憶體完整性（VBS；可能增加 timing anomaly 偵測）",
        bool(profile.get("guest_core_isolation", False)),
    )
    if guest_core_isolation and not guest_secure_boot:
        raise AppError("核心隔離／VBS 需要同時啟用 Guest UEFI Secure Boot。")
    if guest_core_isolation:
        ensure_nested_virtualization(runner)
    _leave_single_gpu_stage(name, profile, runner)
    enable_devirtualized(
        name, runner,
        guest_vtd=guest_vtd,
        guest_vtd_intremap=guest_vtd_intremap,
        guest_secure_boot=guest_secure_boot,
        guest_dma_protection=guest_dma_protection,
        guest_core_isolation=guest_core_isolation,
    )
    install_performance_hook(name)
    print(f"{name}: 去虛擬化設定已啟用。")
    print("已使用 patched QEMU 11、pc-q35-11.0、patched OVMF/SSDT、KVM hidden 與 split IOAPIC。")
    if guest_vtd:
        mode = (
            "完整 interrupt remapping（實驗性）"
            if guest_vtd_intremap else "DMA-remapping 相容模式"
        )
        print(f"guest VT-d 已啟用（{mode}；caching mode；地址寬度使用 QEMU 預設值）。")
        if guest_dma_protection:
            print("Windows Kernel DMA Protection 的 DMAR 平台 opt-in 已啟用。")
    else:
        print("guest VT-d 已關閉；主機 IOMMU/VFIO 仍保持啟用，不影響 PCI/USB/GPU 直通。")
    print(f"Guest UEFI Secure Boot：{'已啟用' if guest_secure_boot else '未啟用'}。")
    if guest_core_isolation:
        print("Windows 核心隔離／VBS 已啟用；guest 會看到 SVM/VMX，並可能觸發 timing anomaly 偵測。")
    else:
        print("Windows 核心隔離／VBS 已關閉；guest SVM/VMX 繼續隱藏。")
    print("VNC/VGA 與虛擬網路仍保留，PCI/USB/GPU 直通尚未啟用。")
    print("若要自行處理特殊設備直通，可停在此步；否則執行 VM 第 3 步『一鍵直通』。")


def enable_gpu_creation(name: str, runner: Runner) -> None:
    """Compatibility alias for the former enable-gpu CLI command."""
    devirtualize_creation(name, runner)

def finalize_creation(name: str, runner: Runner) -> None:
    profile = load_profile(valid_vm_name(name))
    gpu_devices = _profile_gpu_devices(profile)
    finalize_vm(name, runner)
    install_performance_hook(name)
    if gpu_devices:
        install_single_gpu_hooks(
            name, gpu_devices,
            force_bus_reset=profile.get("passthrough", {}).get("gpu_reset_method") == "bus",
        )
    print(f"{name}: 已完成最終化；VNC/VGA 已移除，下次啟動只使用實體 GPU。")
    if gpu_devices:
        print("單 GPU 採完整重置策略：Windows 選『重新啟動』後 VM 會停止，請再啟動一次。")


def recover_display(name: str, runner: Runner) -> None:
    require_root()
    profile = load_profile(valid_vm_name(name))
    addresses = list(profile.get("passthrough", {}).get("gpu_pci", []))
    devices_by_address = {
        item["address"]: PciDevice(**item)
        for item in profile.get("host", {}).get("pci", [])
    }
    missing = [address for address in addresses if address not in devices_by_address]
    if missing:
        raise AppError("Cannot restore GPU; PCI data is missing for: " + ", ".join(missing))
    recover_single_gpu(name, [devices_by_address[address] for address in addresses], runner)


def adopt_vm(name: str, runner: Runner) -> None:
    require_root()
    name = valid_vm_name(name)
    if (VM_DIR / name / "profile.json").is_file():
        raise AppError(
            f"VM '{name}' 已由部署器管理；拒絕用納管流程覆寫現有 profile。"
        )
    result = runner.run(["virsh", "dumpxml", "--inactive", name], capture=True)
    root = ET.fromstring(result.stdout)
    memory_kib = int(root.findtext("memory", "8388608"))
    vcpus = int(root.findtext("vcpu", "4"))
    disk_source = root.find("./devices/disk[@device='disk']/source")
    disk = disk_source.get("file") if disk_source is not None else f"/var/lib/libvirt/images/{name}.qcow2"
    profile = new_profile(name, 0, max(1, memory_kib // 1024 // 1024), vcpus, "/dev/null", int(os.environ.get("SUDO_UID", os.getuid())))
    profile["paths"]["disk"] = disk
    profile["adopted"] = True
    mac = root.find("./devices/interface/mac")
    if mac is not None and mac.get("address"):
        profile["identity"]["mac"] = mac.get("address").lower()
    print(f"VM '{name}' 已納入管理；現在可用 randomize-xml，或完成離線原始碼後使用 randomize-all。")
    save_profile(name, _edit_identity(profile))
    install_performance_hook(name)


def one_click_passthrough(vm_name: str, runner: Runner) -> None:
    require_root()
    vm_name = valid_vm_name(vm_name)
    profile = load_profile(vm_name)
    if profile.get("adopted"):
        raise AppError("一鍵直通只適用部署器建立的 VM；納管 VM 請自行編輯其 XML。")
    stage = profile.get("stage", "install")
    if stage not in {"devirtualized", "gpu-setup", "final"}:
        raise AppError("請先完成 VM 第 2 步：去虛擬化（保留 VNC/VGA）。")

    old = profile.get("passthrough", {})
    old_gpu = set(old.get("gpu_pci", []))
    use_gpu = prompt_yes_no("使用部署器的單 GPU 動態直通", bool(old_gpu))
    gpu_devices = _select_gpu() if use_gpu else []
    gpu_pci = [device.address for device in gpu_devices]
    same_gpu = bool(gpu_pci) and set(gpu_pci) == old_gpu
    current_guest = set(old.get("gpu_guest_pci", [])) if same_gpu else None
    gpu_guest_pci = _select_gpu_guest_functions(gpu_devices, current_guest) if gpu_devices else []
    gpu_rom_bar = prompt_yes_no(
        "啟用 GPU ROM BAR（RTX 50 等高階顯卡建議關閉）",
        bool(old.get("gpu_rom_bar", False)) if same_gpu else False,
    ) if gpu_devices else False
    gpu_reset_method = "default"
    if gpu_devices and prompt_yes_no(
        "強制使用 PCIe bus reset（僅供 FLR 後重啟黑畫面的顯卡）",
        same_gpu and old.get("gpu_reset_method") == "bus",
    ):
        gpu_reset_method = "bus"

    current_extra = set(old.get("extra_pci", []))
    selected_pci = _select_additional_pci(set(gpu_pci), current_extra)
    selected_usb = _select_usb_devices(old.get("usb", []))
    usb = _usb_configs(selected_usb)
    minimal_devices = prompt_yes_no(
        "精簡無益虛擬設備（PS/2、虛擬網卡、audio、未使用 USB controller）",
        bool(profile.get("minimal_devices", False)),
    )
    if minimal_devices and not selected_usb:
        print("警告：沒有 USB 鍵盤/滑鼠直通時，移除 PS/2 後可能無法操作 guest。")
        minimal_devices = prompt_yes_no("確認仍要精簡虛擬設備", False)

    network_pci = [device.address for device in selected_pci if device.class_code[:2] == "02"]
    has_physical_network = bool(network_pci or any(device.is_network for device in selected_usb))
    keep_virtual_network = False
    if not minimal_devices:
        default_keep_network = _default_keep_virtual_network(
            old, selected_pci, has_physical_network,
        )
        keep_virtual_network = prompt_yes_no(
            "保留 libvirt e1000e 虛擬網卡（使用直通網路時建議關閉）",
            default_keep_network,
        )

    gpu_maintenance = bool(gpu_devices) and prompt_yes_no(
        "首次直通先保留 VNC/VGA（通用 GPU 驅動安裝／診斷模式）",
        stage == "devirtualized",
    )
    if gpu_maintenance and minimal_devices:
        print("GPU 維護模式需要可靠的 VNC 輸入；本次自動保留標準虛擬設備。")
        minimal_devices = False

    updated = dict(old)
    updated.update({
        "mode": "single-gpu" if gpu_devices else "manual",
        "pci": gpu_pci + [device.address for device in selected_pci],
        "gpu_pci": gpu_pci,
        "gpu_guest_pci": gpu_guest_pci,
        "gpu_rom_bar": gpu_rom_bar,
        "gpu_reset_method": gpu_reset_method,
        "extra_pci": [device.address for device in selected_pci],
        "usb": usb,
        "network_pci": network_pci[0] if network_pci else None,
        "disable_virtual_network": not keep_virtual_network,
        "virtual_network_choice_set": True,
    })
    print("一鍵直通設定：")
    print(json.dumps({
        "gpu_isolated": gpu_pci,
        "gpu_guest_pci": gpu_guest_pci,
        "gpu_rom_bar": gpu_rom_bar,
        "gpu_reset_method": gpu_reset_method,
        "additional_pci": updated["extra_pci"], "usb": usb,
        "virtual_network": not updated["disable_virtual_network"],
        "minimal_devices": minimal_devices,
        "target_stage": "gpu-setup (VNC/VGA retained)" if gpu_maintenance else "final",
    }, ensure_ascii=False, indent=2))
    confirmation = (
        "套用直通並進入 GPU 維護階段"
        if gpu_maintenance else "套用直通並進入最終階段"
    )
    if not prompt_yes_no(confirmation, False):
        print("已取消。")
        return

    configure_minimal_devices(vm_name, minimal_devices, runner)
    configure_passthrough(vm_name, updated, runner)
    if gpu_maintenance:
        enable_gpu_setup(vm_name, runner)
    else:
        finalize_vm(vm_name, runner)
    if gpu_devices:
        install_single_gpu_hooks(
            vm_name, gpu_devices,
            force_bus_reset=gpu_reset_method == "bus",
        )
        if gpu_maintenance:
            print(f"{vm_name}: GPU 維護模式完成；實體 GPU 已掛入，VNC/VGA 與虛擬網路保留。")
            print("請透過 VNC 安裝適合該硬體的 guest 驅動；關機後再次執行 VM 第 3 步進入正式模式。")
        else:
            print(f"{vm_name}: 一鍵直通完成；VNC/VGA 已移除，實體 GPU 為主要畫面。")
    else:
        remove_single_gpu_hooks(vm_name)
        print(f"{vm_name}: PCI/USB 直通完成；因未選實體 GPU，VNC/VGA 保留。")
    install_performance_hook(vm_name)


def passthrough_wizard(vm_name: str, runner: Runner) -> None:
    """Compatibility entry point for configure-passthrough."""
    one_click_passthrough(vm_name, runner)

def randomize_pending(runner: Runner) -> None:
    require_root()
    for name in pending_names():
        try:
            profile = load_profile(name)
            if profile.get("dynamic_randomization"):
                randomize_xml(name, runner)
            else:
                clear_pending(name)
        except AppError as exc:
            print(f"{name}: pending rotation deferred: {exc}", file=sys.stderr)


def print_status() -> None:
    print("主機狀態：")
    print(json.dumps(load_host_state(), ensure_ascii=False, indent=2))
    print("納管 VM：")
    profiles = sorted(VM_DIR.glob("*/profile.json")) if VM_DIR.exists() else []
    if not profiles:
        print("  (無)")
    for path in profiles:
        profile = json.loads(path.read_text(encoding="utf-8"))
        print(
            f"  {profile['name']}: stage={profile.get('stage', 'legacy')}, "
            f"minimal={profile.get('minimal_devices', False)}, "
            f"XML gen={profile['identity']['generation']}, "
            f"artifacts={profile.get('artifact_generation', '-')}, "
            f"dynamic={profile.get('dynamic_randomization', False)}"
        )



def validate_vm_xml(name: str, runner: Runner) -> None:
    result = runner.run(["virsh", "dumpxml", "--inactive", valid_vm_name(name)], capture=True)
    errors = validate_required(result.stdout)
    if errors:
        raise AppError("\n".join(errors))
    print(f"{name}: XML validation passed")


def install_app_stack(runner: Runner) -> None:
    install_application(runner)
    install_pending_service(runner)


def bootstrap(runner: Runner) -> None:
    install_packages(runner)
    install_app_stack(runner)
    configure_host(runner)


def quick_deploy(runner: Runner) -> None:
    """Run every required Ubuntu host deployment step in order."""
    print_preflight()
    if not print_validation():
        raise AppError("離線資源驗證失敗；請補齊清單中的檔案後重試。")
    bootstrap(runner)
    print_status()


def _identity_wizard(runner: Runner) -> None:
    require_root()
    name = valid_vm_name(prompt("VM 名稱"))
    profile = load_profile(name)
    print("[1] 動態隨機化開關（VM 每次關機後更新 XML）")
    print("[2] 立即僅隨機化 XML 身份")
    print("[3] 立即全部隨機化（XML + 重建 QEMU/OVMF patch）")
    print("[0] 返回")
    choice = prompt_int("選擇身份操作", 1, 0, 3)
    if choice == 0:
        return
    if choice == 1:
        enabled = prompt_yes_no(
            "啟用每次關機後動態 XML 隨機化",
            bool(profile.get("dynamic_randomization", False)),
        )
        set_dynamic(name, enabled)
        if enabled:
            install_dynamic_hooks(name)
            install_pending_service(runner)
            runner.run(["virsh", "autostart", "--disable", name])
        else:
            remove_dynamic_hooks(name)
    elif choice == 2:
        randomize_xml(name, runner)
    else:
        randomize_all(name, runner)


def _diagnostics() -> None:
    print_preflight()
    print_validation()
    print_status()


def _update_protection_wizard(runner: Runner) -> None:
    require_root()
    state = load_host_state()
    current = bool(state.get("update_protection_enabled", False))
    packages = list(state.get("update_protection_packages", []))
    print(f"目前更新保護：{'已啟用' if current else '未啟用'}")
    if packages:
        print(f"目前記錄 {len(packages)} 個受保護套件。")
    print("保護範圍：Ubuntu 核心、QEMU/libvirt、OVMF、virt-manager 及 GPU 驅動。")
    print("未列入保護的其他安全更新不受影響；準備主動升級上述堆疊時可從此處解除。")
    enabled = prompt_yes_no("啟用更新保護（建議）", True)
    configure_update_protection(runner, enabled)


def _guest_security_wizard(runner: Runner) -> None:
    require_root()
    name = valid_vm_name(prompt("VM 名稱"))
    profile = load_profile(name)
    print("此功能會保留 Windows Boot Manager、直通設備與目前 VM 階段。")
    print("核心 DMA 保護使用 DMAR platform opt-in，不會強制開啟曾造成卡機的 interrupt remapping。")
    secure_boot = prompt_yes_no(
        "啟用 Guest UEFI Secure Boot",
        bool(profile.get("guest_secure_boot", False)),
    )
    dma_protection = prompt_yes_no(
        "啟用 Windows 核心 DMA 保護",
        bool(profile.get("guest_dma_protection", False)),
    )
    if dma_protection and not profile.get("guest_vtd", False):
        print("核心 DMA 保護需要 guest VT-d；部署器會同時啟用相容模式 guest vIOMMU。")
    core_isolation = prompt_yes_no(
        "啟用 Windows 核心隔離／記憶體完整性（VBS）",
        bool(profile.get("guest_core_isolation", False)),
    )
    if core_isolation:
        print("注意：VBS 需要暴露 SVM/VMX，可能使 VMAware 增加一項 timing anomaly。")
        if not secure_boot:
            raise AppError("核心隔離／VBS 需要同時啟用 Guest UEFI Secure Boot。")
        ensure_nested_virtualization(runner)
    configure_guest_security(
        name, secure_boot, dma_protection, runner,
        core_isolation=core_isolation,
    )


def _maintenance_menu(runner: Runner) -> None:
    actions = [
        ("主機／離線資源／部署狀態總覽", _diagnostics),
        ("續接未完成的 VM 建立（不重新編譯）", lambda: resume_creation(prompt("VM 名稱"), runner, ask_start=True)),
        ("納管現有 VM", lambda: adopt_vm(prompt("VM 名稱"), runner)),
        ("虛擬設備／libvirt 虛擬網卡開關", lambda: _minimal_devices_wizard(runner)),
        ("Guest Secure Boot／核心 DMA 保護／核心隔離", lambda: _guest_security_wizard(runner)),
        ("CPU SMT 拓撲／綁核／主機電源效能模式", lambda: _performance_wizard(runner)),
        ("恢復主機顯示／重新綁定單 GPU", lambda: recover_display(prompt("VM 名稱"), runner)),
        ("驗證 VM XML 必要設定", lambda: validate_vm_xml(prompt("VM 名稱"), runner)),
        ("只安裝／更新部署器與服務", lambda: install_app_stack(runner)),
    ]
    while True:
        print("\n維護與進階工具")
        for index, (label, _) in enumerate(actions, 1):
            print(f"[{index}] {label}")
        print("[0] 返回主選單")
        choice = prompt_int("選擇功能", 1, 0, len(actions))
        if choice == 0:
            return
        try:
            actions[choice - 1][1]()
        except (AppError, OSError) as exc:
            print(f"錯誤：{exc}", file=sys.stderr)


def _performance_wizard(runner: Runner) -> None:
    require_root()
    name = valid_vm_name(prompt("VM 名稱"))
    profile = load_profile(name)
    host = host_fingerprint()["cpu"]
    threads = 2 if int(host.get("threads_per_core", 1)) >= 2 else 1
    maximum = max(2, int(host["logical_cpus"]) - threads)
    default = min(maximum, int(profile.get("resources", {}).get("vcpus", 2)))
    if default % threads:
        default = max(threads, default - default % threads)
    vcpus = prompt_int(
        f"vCPU 數量（主機每核 {threads} threads；建議保留完整實體核心）",
        default, 2, maximum,
    )
    if threads == 2 and vcpus % 2:
        raise AppError("SMT 拓撲需要偶數 vCPU。")
    configure_cpu_layout(name, vcpus, runner)
    install_performance_hook(name)
    print("電源效能 hook 已安裝：VM 啟動時切換 performance，最後一台管理中 VM 停止後復原。")
    print("若 VM 目前正在運行，新拓撲會從下次完整開機開始生效。")


def _custom_kernel_wizard(runner: Runner) -> None:
    print("\n自訂核心")
    print("[1] 建置並安裝新的 linux-tkg 自訂核心")
    print("[2] 修復／驗證現有自訂核心的 Secure Boot 簽章（不重新編譯）")
    print("[0] 返回主選單")
    choice = prompt_int("選擇功能", 1, 0, 2)
    if choice == 1:
        build_kernel(runner)
    elif choice == 2:
        sign_custom_kernels(runner)


def menu(runner: Runner) -> None:
    actions = [
        ("Ubuntu 主機一鍵部署／更新", lambda: quick_deploy(runner)),
        ("VM 1/3：建立新 Windows VM", lambda: create_wizard(runner)),
        ("VM 2/3：去虛擬化（保留 VNC/VGA，不啟用直通）", lambda: devirtualize_creation(prompt("VM 名稱"), runner)),
        ("VM 3/3：一鍵直通（可跳過並自行配置特殊設備）", lambda: one_click_passthrough(prompt("VM 名稱"), runner)),
        ("VM XML 身份隨機化", lambda: _identity_wizard(runner)),
        ("自訂核心（建置／修復 Secure Boot 簽章）", lambda: _custom_kernel_wizard(runner)),
        ("安裝 memflow", lambda: install_memflow(runner)),
        ("更新保護（鎖定核心／虛擬化／GPU 套件）", lambda: _update_protection_wizard(runner)),
        ("維護與進階工具", lambda: _maintenance_menu(runner)),
    ]
    while True:
        print(f"\nKVM-AntiAntiVM Ubuntu Deployer {__version__}")
        print("首次使用請先執行 [1]；VM 建議依序執行 [2] → [3] → [4]，自行直通者可在 [3] 後停止。")
        for index, (label, _) in enumerate(actions, 1):
            print(f"[{index}] {label}")
        print("[0] 離開")
        choice = prompt_int("選擇功能", 1, 0, len(actions))
        if choice == 0:
            return
        try:
            actions[choice - 1][1]()
        except (AppError, OSError) as exc:
            print(f"錯誤：{exc}", file=sys.stderr)

def _minimal_devices_wizard(runner: Runner) -> None:
    require_root()
    name = valid_vm_name(prompt("VM 名稱"))
    profile = load_profile(name)
    current = bool(profile.get("minimal_devices", False))
    print("啟用精簡模式會移除：PS/2 鍵鼠、QEMU audio backend，及未被 USB 直通使用的 xHCI controller。")
    print("保留：磁碟、SATA/PCI root、OVMF、IOMMU，以及 Windows 安裝階段需要的 SPICE/VGA。")
    enabled = prompt_yes_no("啟用精簡 QEMU 虛擬設備", current)
    if enabled and not profile.get("passthrough", {}).get("usb"):
        print("警告：此 VM 沒有記錄 USB 直通；移除 PS/2 後可能無法操作 guest。")
        if not prompt_yes_no("確認仍要套用", False):
            print("已取消。")
            return
    passthrough = profile.setdefault("passthrough", {})
    keep_virtual_network = prompt_yes_no(
        "保留 libvirt e1000e 虛擬網卡（使用直通網路時建議關閉）",
        not bool(passthrough.get("disable_virtual_network", False)),
    )
    passthrough["virtual_network_choice_set"] = True
    configure_minimal_devices(
        name, enabled, runner,
        disable_virtual_network=not keep_virtual_network,
    )


def _dynamic_wizard(runner: Runner) -> None:
    require_root()
    name = prompt("VM 名稱")
    enabled = prompt_yes_no("啟用每次關機後動態 XML 隨機化", False)
    set_dynamic(name, enabled)
    if enabled:
        install_dynamic_hooks(name)
        install_pending_service(runner)
        runner.run(["virsh", "autostart", "--disable", name])
    else:
        remove_dynamic_hooks(name)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Ubuntu 24.04 offline KVM-AntiAntiVM deployer")
    parser.add_argument("--dry-run", action="store_true", help="print commands without changing the host")
    sub = parser.add_subparsers(dest="command")
    for command in ("preflight", "status", "bootstrap", "validate-offline", "install-offline", "configure-host", "install-app", "create-vm", "build-kernel", "sign-custom-kernels", "install-memflow", "randomize-pending"):
        sub.add_parser(command)
    for command in ("resume-vm", "devirtualize-vm", "one-click-passthrough", "enable-gpu", "finalize-vm", "adopt-vm", "configure-passthrough", "recover-display", "randomize-xml", "randomize-all", "mark-pending", "validate-xml"):
        item = sub.add_parser(command)
        item.add_argument("--vm", required=True)
    performance = sub.add_parser("configure-performance")
    performance.add_argument("--vm", required=True)
    performance.add_argument("--vcpus", required=True, type=int)
    minimal = sub.add_parser("set-minimal-devices")
    minimal.add_argument("--vm", required=True)
    minimal.add_argument("--enable", action=argparse.BooleanOptionalAction, default=True)
    minimal.add_argument("--virtual-network", action=argparse.BooleanOptionalAction, default=None)
    dynamic = sub.add_parser("set-dynamic")
    dynamic.add_argument("--vm", required=True)
    dynamic.add_argument("--enable", action=argparse.BooleanOptionalAction, default=True)
    security = sub.add_parser("configure-guest-security")
    security.add_argument("--vm", required=True)
    security.add_argument("--secure-boot", action=argparse.BooleanOptionalAction, default=True)
    security.add_argument("--dma-protection", action=argparse.BooleanOptionalAction, default=True)
    security.add_argument("--core-isolation", action=argparse.BooleanOptionalAction, default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    runner = Runner(dry_run=args.dry_run)
    try:
        command = args.command
        if command is None:
            menu(runner)
        elif command == "status": print_status()
        elif command == "bootstrap":
            bootstrap(runner)
        elif command == "preflight": print_preflight()
        elif command == "validate-offline": return 0 if print_validation() else 2
        elif command == "install-offline": install_packages(runner)
        elif command == "configure-host": configure_host(runner)
        elif command == "install-app": install_app_stack(runner)
        elif command == "create-vm": create_wizard(runner)
        elif command in {"devirtualize-vm", "enable-gpu"}: devirtualize_creation(args.vm, runner)
        elif command == "one-click-passthrough": one_click_passthrough(args.vm, runner)
        elif command == "finalize-vm": finalize_creation(args.vm, runner)
        elif command == "adopt-vm": adopt_vm(args.vm, runner)
        elif command == "resume-vm": resume_creation(args.vm, runner)
        elif command == "configure-passthrough": passthrough_wizard(args.vm, runner)
        elif command == "recover-display": recover_display(args.vm, runner)
        elif command == "sign-custom-kernels": sign_custom_kernels(runner)
        elif command == "randomize-xml": randomize_xml(args.vm, runner)
        elif command == "randomize-all": randomize_all(args.vm, runner)
        elif command == "mark-pending": mark_pending(args.vm)
        elif command == "randomize-pending": randomize_pending(runner)
        elif command == "set-minimal-devices":
            configure_minimal_devices(
                args.vm, args.enable, runner,
                disable_virtual_network=(
                    None if args.virtual_network is None else not args.virtual_network
                ),
            )
        elif command == "set-dynamic":
            require_root(); set_dynamic(args.vm, args.enable)
            (install_dynamic_hooks(args.vm) if args.enable else remove_dynamic_hooks(args.vm))
            if args.enable:
                install_pending_service(runner)
                runner.run(["virsh", "autostart", "--disable", args.vm])
        elif command == "configure-guest-security":
            if args.core_isolation and not args.secure_boot:
                raise AppError("Core Isolation/VBS requires Guest UEFI Secure Boot.")
            if args.core_isolation:
                ensure_nested_virtualization(runner)
            configure_guest_security(
                args.vm, args.secure_boot, args.dma_protection, runner,
                core_isolation=args.core_isolation,
            )
        elif command == "configure-performance":
            configure_cpu_layout(args.vm, args.vcpus, runner)
            install_performance_hook(args.vm)
        elif command == "build-kernel": build_kernel(runner)
        elif command == "install-memflow": install_memflow(runner)
        elif command == "validate-xml": validate_vm_xml(args.vm, runner)
        return 0
    except (AppError, OSError, KeyboardInterrupt) as exc:
        print(f"錯誤：{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
