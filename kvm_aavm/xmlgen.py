from __future__ import annotations

import copy
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from .util import AppError

QEMU_NS = "http://libvirt.org/schemas/domain/qemu/1.0"
AAVM_NS = "https://kvm-aavm.local/xmlns/domain/1.0"
MACHINE_TYPE = "pc-q35-11.0"
INSTALL_MACHINE_TYPE = "pc-q35-noble"
INSTALL_QEMU = "/usr/bin/qemu-system-x86_64"
INSTALL_OVMF_CODE = "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd"
INSTALL_OVMF_VARS = "/usr/share/OVMF/OVMF_VARS_4M.fd"
ET.register_namespace("qemu", QEMU_NS)
ET.register_namespace("kvm-aavm", AAVM_NS)

HUGEPAGE_2M_KIB = 2048
HYPERV_STANDARD_FEATURES = (
    "relaxed", "vapic", "spinlocks", "vpindex", "runtime", "synic",
    "stimer", "reset", "vendor_id", "frequencies", "reenlightenment",
    "tlbflush", "ipi", "evmcs", "avic",
)
HYPERV_ACCELERATED_FEATURES = {
    "relaxed", "vapic", "spinlocks", "vpindex", "runtime", "synic",
    "stimer", "frequencies", "tlbflush", "ipi",
}
HYPERV_AMD_ACCELERATED_FEATURES = {"avic"}
HYPERV_AMD_QEMU_GLOBALS = (
    "host-x86_64-cpu.gmet=on",
    "host-x86_64-cpu.hv-emsr-bitmap=on",
    "host-x86_64-cpu.hv-tlbflush-ext=on",
    "host-x86_64-cpu.hv-tlbflush-direct=on",
)
HYPERV_NESTED_MMU_QEMU_GLOBALS = (
    # KVM's shadow MMU does not implement CET shadow-stack mappings.  A VBS
    # guest creates a nested MMU, so do not advertise CET-SS to the outer
    # Windows kernel while its Hyper-V enlightenments are active.
    "host-x86_64-cpu.cet-ss=off",
)
TPM_MODELS = {"tpm-tis", "tpm-crb"}
TPM_PROFILES = {"generic", "amd-ftpm"}


def _sub(parent: ET.Element, tag: str, text: str | None = None, **attrs: str) -> ET.Element:
    element = ET.SubElement(parent, tag, attrs)
    if text is not None:
        element.text = str(text)
    return element


def _tpm_settings(profile: dict) -> tuple[str, str, str]:
    """Return the supported guest TPM configuration."""
    value = profile.get("tpm", {})
    if not isinstance(value, dict):
        value = {}
    mode = str(value.get("mode", "none"))
    if mode not in {"none", "emulator"}:
        raise AppError(f"Unsupported TPM mode: {mode}")
    if mode == "none":
        return mode, "", ""

    model = str(value.get("model", "tpm-crb"))
    if model not in TPM_MODELS:
        raise AppError(f"Unsupported TPM model: {model}")
    tpm_profile = str(value.get("profile", "generic"))
    if tpm_profile not in TPM_PROFILES:
        raise AppError(f"Unsupported TPM profile: {tpm_profile}")
    if tpm_profile == "amd-ftpm" and model != "tpm-crb":
        raise AppError("The AMD fTPM profile requires the tpm-crb interface.")
    return mode, model, tpm_profile


def amd_nested_hyperv_acceleration_available(profile: dict) -> bool:
    host = profile.get("host", {})
    cpu = host.get("cpu", {})
    kvm = host.get("kvm", {})
    return cpu.get("vendor") == "amd" and all(
        bool(kvm.get(key, False)) for key in ("nested", "npt", "avic", "gmet")
    )


def amd_avic_available(profile: dict) -> bool:
    """Return whether the host can expose Hyper-V AVIC independently of GMET."""
    host = profile.get("host", {})
    return (
        host.get("cpu", {}).get("vendor") == "amd"
        and bool(host.get("kvm", {}).get("avic", False))
    )


def _set_qemu_global(commandline: ET.Element, value: str, enabled: bool) -> None:
    children = list(commandline)
    remove: set[ET.Element] = set()
    for index, child in enumerate(children):
        if child.get("value") != value:
            continue
        remove.add(child)
        if index and children[index - 1].get("value") == "-global":
            remove.add(children[index - 1])
    for child in remove:
        commandline.remove(child)
    if enabled:
        _sub(commandline, f"{{{QEMU_NS}}}arg", value="-global")
        _sub(commandline, f"{{{QEMU_NS}}}arg", value=value)


def apply_hyperv_enlightenments(
    root: ET.Element, enabled: bool, amd_acceleration: bool,
    amd_avic: bool | None = None,
) -> None:
    """Configure coherent nested Hyper-V acceleration without duplicate -cpu args."""
    features = root.find("features")
    if features is None:
        raise AppError("Domain XML has no features element for Hyper-V configuration.")
    hyperv = features.find("hyperv")
    if hyperv is None:
        hyperv = _sub(features, "hyperv", mode="custom")
    amd_avic = amd_acceleration if amd_avic is None else amd_avic
    for name in HYPERV_STANDARD_FEATURES:
        state = enabled and (
            name in HYPERV_ACCELERATED_FEATURES
            or (amd_avic and name in HYPERV_AMD_ACCELERATED_FEATURES)
        )
        element = hyperv.find(name)
        if element is None:
            element = _sub(hyperv, name)
        element.set("state", "on" if state else "off")
        if name == "spinlocks":
            if state:
                # libvirt requires retries whenever this Hyper-V feature is
                # enabled. 8191 is the conventional Windows/KVM value.
                element.set("retries", "8191")
            else:
                element.attrib.pop("retries", None)
        if name == "stimer":
            direct = element.find("direct")
            if state:
                if direct is None:
                    direct = _sub(element, "direct")
                direct.set("state", "on")
            elif direct is not None:
                element.remove(direct)

    clock = root.find("clock")
    if clock is None:
        raise AppError("Domain XML has no clock element for Hyper-V configuration.")
    hypervclock = clock.find("timer[@name='hypervclock']")
    if hypervclock is None:
        hypervclock = _sub(clock, "timer", name="hypervclock")
    hypervclock.set("present", "yes" if enabled else "no")

    commandline = root.find(f"{{{QEMU_NS}}}commandline")
    if commandline is None:
        commandline = _sub(root, f"{{{QEMU_NS}}}commandline")
    for value in HYPERV_AMD_QEMU_GLOBALS:
        _set_qemu_global(commandline, value, enabled and amd_acceleration)
    for value in HYPERV_NESTED_MMU_QEMU_GLOBALS:
        _set_qemu_global(commandline, value, enabled)


def _qemu_escape(value: str) -> str:
    return value.replace(",", ",,")


def _smbios_args(identity: dict, *, include_type9: bool = True) -> list[str]:
    entries = [
        f"type=1,manufacturer={_qemu_escape(identity['manufacturer'])},product={_qemu_escape(identity['product'])},version={identity['version']},serial={identity['system_serial']},uuid={identity['system_uuid']}",
        f"type=2,manufacturer={_qemu_escape(identity['manufacturer'])},product={_qemu_escape(identity['baseboard_product'])},version={identity['version']},serial={identity['baseboard_serial']}",
        f"type=3,manufacturer={_qemu_escape(identity['manufacturer'])},version={identity['version']},serial={identity['chassis_serial']}",
        f"type=4,sock_pfx=U1,manufacturer={_qemu_escape(identity['cpu_manufacturer'])},version={_qemu_escape(identity['cpu_version'])}",
        f"type=17,manufacturer={_qemu_escape(identity['memory_manufacturer'])},part={identity['memory_part']},serial={identity['memory_serial']}",
        "type=8,internal_reference=J1A1,external_reference=Keyboard,connector_type=0x0F,port_type=0x0D",
        "type=8,internal_reference=J1A1,external_reference=Mouse,connector_type=0x0F,port_type=0x0E",
    ]
    if include_type9:
        # The project's patched QEMU 11 adds support for constructing this
        # record. Ubuntu 24.04's QEMU 8.2 aborts at startup when it receives it,
        # so delay type 9 until the post-install patched stage.
        entries.append(
            "type=9,slot_designation=J6C1,slot_type=0xAA,slot_data_bus_width=0x0D,current_usage=0x04,slot_length=0x04,slot_id=0x01,slot_characteristics1=0x04,slot_characteristics2=0x03"
        )
    args: list[str] = []
    for entry in entries:
        args.extend(["-smbios", entry])
    return args


def _pci_address(address: str) -> dict[str, str]:
    match = re.fullmatch(r"(?:(?P<domain>[0-9a-fA-F]{4}):)?(?P<bus>[0-9a-fA-F]{2}):(?P<slot>[0-9a-fA-F]{2})\.(?P<function>[0-7])", address)
    if not match:
        raise AppError(f"Invalid PCI address: {address}")
    groups = match.groupdict(default="0000")
    return {
        "domain": f"0x{groups['domain']}", "bus": f"0x{groups['bus']}",
        "slot": f"0x{groups['slot']}", "function": f"0x{groups['function']}",
    }


def _normalized_pci_address(address: str) -> str:
    parts = _pci_address(address)
    return (
        f"{int(parts['bus'], 0):02x}:"
        f"{int(parts['slot'], 0):02x}."
        f"{int(parts['function'], 0)}"
    )


def _gpu_display_functions(gpu_pci: list[str], host_pci: list[dict]) -> list[str]:
    classes = {
        _normalized_pci_address(str(item["address"])): str(item.get("class_code", ""))
        for item in host_pci if item.get("address")
    }
    display = [
        address for address in gpu_pci
        if classes.get(_normalized_pci_address(address), "").startswith("03")
    ]
    # Profiles adopted from old releases may not contain host PCI inventory.
    # PCI function zero is the safest compatibility fallback for a GPU slot.
    return display or gpu_pci[:1]


def _single_gpu_guest_functions(passthrough: dict, host_pci: list[dict]) -> list[str]:
    """Return the GPU functions exposed to QEMU, not those isolated by hooks.

    ``gpu_pci`` deliberately keeps the complete physical slot/IOMMU group so
    the host hook can detach every related driver. Legacy profiles without a
    ``gpu_guest_pci`` selection retain display-only behavior; new profiles
    explicitly record the display and any user-selected HDMI/DP audio
    functions.
    """
    gpu_pci = list(passthrough.get("gpu_pci", []))
    display = _gpu_display_functions(gpu_pci, host_pci)
    requested = passthrough.get("gpu_guest_pci")
    if requested is None:
        requested = display
    wanted = set(display) | (set(requested) & set(gpu_pci))
    return [address for address in gpu_pci if address in wanted]


def _passthrough_group_key(address: str, host_pci: list[dict]) -> tuple[str, str]:
    normalized = _normalized_pci_address(address)
    for device in host_pci:
        if _normalized_pci_address(str(device.get("address", ""))) == normalized:
            group = device.get("iommu_group")
            if group is not None:
                return "iommu", str(group)
            break
    # Even when an adopted profile has no host inventory, functions of one
    # physical PCI slot must never be split across guest IOMMU address spaces.
    return "slot", normalized.rsplit(".", 1)[0]


def _passthrough_pcie_layout(
    devices: ET.Element, addresses: list[str], host_pci: list[dict],
    *, native_group_keys: set[tuple[str, str]] | None = None,
) -> dict[str, dict[str, str]]:
    """Create one guest requester-ID/address space per host IOMMU group.

    Intel vIOMMU gives every PCIe function a distinct AddressSpace.  Linux
    VFIO, however, opens a whole host IOMMU group in one container and refuses
    to attach that group to a second AddressSpace.  Put multi-device groups
    behind QEMU's PCIe-to-PCI bridge: its conventional downstream bus aliases
    all requests to one requester ID, exactly matching the host group.
    """
    groups: dict[tuple[str, str], list[str]] = {}
    for address in addresses:
        groups.setdefault(_passthrough_group_key(address, host_pci), []).append(address)
    if not groups:
        return {}

    managed_controllers = []
    for controller in devices.findall("controller[@type='pci'][@model='pcie-root-port']"):
        alias = controller.find("alias")
        if alias is not None and alias.get("name", "").startswith("ua-kvm-aavm-pcie-"):
            managed_controllers.append(controller)
    managed_controllers.sort(key=lambda item: int(item.get("index", "0")))

    # The devices below these ports are soldered/internal desktop devices, not
    # Thunderbolt-style surprise-removable endpoints.  QEMU's root-port
    # default advertises PCIe hot-plug capability; with Windows Kernel DMA
    # Protection enabled that makes the passed GPU and xHCI controllers look
    # like post-lock external DMA devices.  Keep the topology faithful to a
    # normal motherboard and prevent DMA Guard from withholding their drivers
    # at the lock screen.
    for controller in managed_controllers:
        target = controller.find("target")
        if target is not None:
            target.set("hotplug", "off")

    # Bridges created by an earlier passthrough update contain only managed
    # hostdevs (removed by update_passthrough before this helper is called).
    # Recreate them so a group changing between one and several devices never
    # leaves a stale conventional bus in the domain.
    for controller in list(devices.findall("controller[@type='pci'][@model='pcie-to-pci-bridge']")):
        alias = controller.find("alias")
        if alias is not None and alias.get("name", "").startswith("ua-kvm-aavm-pci-bridge-"):
            devices.remove(controller)

    # Device 2 on an Intel client root bus is reserved for the integrated
    # graphics function.  Advertising a PCI bridge at 00:02.0 in a DMAR
    # device scope is both topologically inconsistent and a known firmware
    # fingerprint.  Keep the complete slot free even on hosts without an
    # active iGPU so generated XML remains portable between machines.
    reserved_root_slots = {2}
    used_root_addresses = set()
    max_index = 0
    for controller in devices.findall("controller[@type='pci']"):
        max_index = max(max_index, int(controller.get("index", "0")))
        address = controller.find("address[@type='pci']")
        if address is not None and int(address.get("bus", "0"), 0) == 0:
            used_root_addresses.add((
                int(address.get("slot", "0"), 0),
                int(address.get("function", "0"), 0),
            ))

    def next_root_address() -> tuple[int, int] | None:
        return next(
            ((slot, function) for slot in range(3, 31) for function in range(8)
             if (slot, function) not in used_root_addresses),
            None,
        )

    # Migrate domains generated by older releases as soon as passthrough is
    # reconfigured.  Reusing their managed controller at 00:02.x would retain
    # the invalid DMAR bridge scope even though new controllers are safe.
    for controller in managed_controllers:
        address = controller.find("address[@type='pci']")
        if address is None or int(address.get("bus", "0"), 0) != 0:
            continue
        old_address = (
            int(address.get("slot", "0"), 0),
            int(address.get("function", "0"), 0),
        )
        if old_address[0] not in reserved_root_slots:
            continue
        used_root_addresses.discard(old_address)
        root_address = next_root_address()
        if root_address is None:
            raise AppError("No safe Q35 root-bus address remains for PCI passthrough.")
        slot, function = root_address
        used_root_addresses.add(root_address)
        address.attrib.clear()
        address.attrib.update({
            "type": "pci", "domain": "0x0000", "bus": "0x00",
            "slot": f"0x{slot:02x}", "function": f"0x{function:x}",
        })
        if function == 0:
            address.set("multifunction", "on")
        target = controller.find("target")
        if target is not None:
            target.set("port", f"0x{slot * 8 + function:x}")

    def add_controller() -> ET.Element:
        nonlocal max_index
        root_address = next_root_address()
        if root_address is None:
            raise AppError("No safe Q35 root-bus address remains for PCI passthrough.")
        slot, function = root_address
        used_root_addresses.add(root_address)
        max_index += 1
        controller = _sub(
            devices, "controller", type="pci", index=str(max_index),
            model="pcie-root-port",
        )
        _sub(controller, "model", name="pcie-root-port")
        # Q35 encodes a root port from its root-bus slot/function.  Using the
        # controller index here collides with ports that libvirt auto-adds for
        # unrelated devices (for example index 1 at 02.0 must be port 0x10,
        # while index 2 at 02.1 is port 0x11).
        _sub(
            controller, "target", chassis=str(max_index),
            port=f"0x{slot * 8 + function:x}", hotplug="off",
        )
        attrs = {
            "type": "pci", "domain": "0x0000", "bus": "0x00",
            "slot": f"0x{slot:02x}", "function": f"0x{function:x}",
        }
        if function == 0:
            attrs["multifunction"] = "on"
        _sub(controller, "address", **attrs)
        _sub(controller, "alias", name=f"ua-kvm-aavm-pcie-{max_index}")
        return controller

    while len(managed_controllers) < len(groups):
        managed_controllers.append(add_controller())

    layout: dict[str, dict[str, str]] = {}
    native_group_keys = native_group_keys or set()
    for (group_key, members), controller in zip(groups.items(), managed_controllers):
        controller_index = int(controller.get("index", "0"))
        endpoint_bus = controller_index
        physical_slots = {
            _normalized_pci_address(address).rsplit(".", 1)[0]
            for address in members
        }
        # A multifunction GPU must stay on its native PCIe root port for GOP
        # and x-vga.  Only do this when all functions are from the same physical
        # slot; unrelated devices sharing an IOMMU group still need the alias
        # bridge used by the guest vIOMMU path.
        conventional = not (
            group_key in native_group_keys and len(physical_slots) == 1
        ) and len(members) > 1
        if conventional:
            max_index += 1
            bridge = _sub(
                devices, "controller", type="pci", index=str(max_index),
                model="pcie-to-pci-bridge",
            )
            _sub(bridge, "model", name="pcie-pci-bridge")
            _sub(
                bridge, "address", type="pci", domain="0x0000",
                bus=f"0x{controller_index:02x}", slot="0x00", function="0x0",
            )
            _sub(bridge, "alias", name=f"ua-kvm-aavm-pci-bridge-{max_index}")
            endpoint_bus = max_index
        slot_order: dict[str, int] = {}
        multifunction_slots: set[str] = set()
        for address in members:
            normalized = _normalized_pci_address(address)
            physical_slot = normalized.rsplit(".", 1)[0]
            if physical_slot in slot_order:
                multifunction_slots.add(physical_slot)
            else:
                # Slot zero on a conventional bridge is reserved by its SHPC.
                slot_order[physical_slot] = len(slot_order) + (1 if conventional else 0)
        if len(slot_order) > (31 if conventional else 32):
            raise AppError("A single IOMMU group contains too many PCI slots.")
        for address in members:
            normalized = _normalized_pci_address(address)
            physical_slot, function_text = normalized.rsplit(".", 1)
            # A lone host function such as an AMD USB controller at 0c:00.4
            # must appear as function 0 in its own guest slot.  PCI firmware
            # and Windows normally probe functions 1-7 only after function 0
            # advertises a multifunction device.  Preserving .4 by itself
            # leaves its BAR unmapped and every attached USB device inert.
            guest_function = (
                int(function_text)
                if physical_slot in multifunction_slots else 0
            )
            attrs = {
                "type": "pci", "domain": "0x0000",
                "bus": f"0x{endpoint_bus:02x}",
                "slot": f"0x{slot_order[physical_slot]:02x}",
                "function": f"0x{guest_function:x}",
            }
            if physical_slot in multifunction_slots and int(function_text) == 0:
                attrs["multifunction"] = "on"
            layout[address] = attrs
    return layout


def build_domain_xml(profile: dict, install_stage: bool = True, *, stage: str | None = None) -> str:
    if stage is None:
        stage = "install" if install_stage else "final"
    if stage not in {"install", "devirtualized", "gpu-setup", "final"}:
        raise AppError(f"Invalid VM stage: {stage}")
    install_stage = stage == "install"
    name = profile["name"]
    identity = profile["identity"]
    resources = profile["resources"]
    paths = profile["paths"]
    host_cpu = profile["host"]["cpu"]
    passthrough = profile.get("passthrough", {})
    minimal_devices = bool(profile.get("minimal_devices", False))
    host_pci = list(profile.get("host", {}).get("pci", []))
    guest_vtd = bool(profile.get("guest_vtd", False))
    guest_vtd_intremap = bool(profile.get("guest_vtd_intremap", False))
    guest_secure_boot = bool(profile.get("guest_secure_boot", False))
    guest_dma_protection = bool(profile.get("guest_dma_protection", False))
    guest_core_isolation = bool(profile.get("guest_core_isolation", False))
    tpm_mode, tpm_model, tpm_profile = _tpm_settings(profile)
    if guest_core_isolation and not guest_secure_boot:
        raise AppError("Core Isolation/VBS requires Guest UEFI Secure Boot.")
    gpu_pci = passthrough.get("gpu_pci")
    if gpu_pci is None:
        gpu_pci = [
            address for address in passthrough.get("pci", [])
            if address != passthrough.get("network_pci")
        ]
    gpu_pci = list(gpu_pci)
    gpu_passthrough_active = bool(
        gpu_pci
        and passthrough.get("mode") == "single-gpu"
        and stage in {"gpu-setup", "final"}
    )
    physical_gpu_display = bool(gpu_passthrough_active and stage == "final")
    # Guest VT-d is a VM identity/capability choice, not a display-backend
    # choice. Keep it in the final single-GPU stage as well. caching_mode is
    # enabled below so VFIO devices can be mapped behind the emulated IOMMU.
    guest_vtd_active = bool(guest_vtd and not install_stage)
    guest_dma_protection_active = bool(
        guest_dma_protection and guest_vtd_active
    )
    guest_core_isolation_active = bool(guest_core_isolation and not install_stage)
    guest_hyperv_enlightenments = bool(
        guest_core_isolation_active
        and profile.get("guest_hyperv_enlightenments", guest_core_isolation)
    )
    amd_hyperv_acceleration = bool(
        guest_hyperv_enlightenments
        and amd_nested_hyperv_acceleration_available(profile)
    )
    amd_hyperv_avic = bool(
        guest_hyperv_enlightenments and amd_avic_available(profile)
    )
    gpu_guest_pci = (
        _single_gpu_guest_functions(passthrough, host_pci)
        if gpu_passthrough_active else gpu_pci
    )
    domain = ET.Element("domain", {"type": "kvm"})
    _sub(domain, "name", name)
    _sub(domain, "uuid", identity["domain_uuid"])
    metadata = _sub(domain, "metadata")
    stage_metadata = _sub(metadata, f"{{{AAVM_NS}}}stage", stage)
    stage_metadata.set("tpm-mode", tpm_mode)
    stage_metadata.set("tpm-profile", tpm_profile or "none")
    cpuid_policy = str(resources.get("cpuid_policy", "intercepted"))
    if cpuid_policy not in {"intercepted", "svme-gated-native"}:
        raise AppError(f"Unsupported CPUID policy: {cpuid_policy}")
    if cpuid_policy == "svme-gated-native":
        host_cpu = profile.get("host", {}).get("cpu", {})
        vcpus = int(resources.get("vcpus", 0))
        pins = [
            int(cpu) for cpu in resources.get("cpu_pinning", {}).get("vcpus", [])
        ]
        native_apic_ids = {
            int(cpu): int(apic_id)
            for cpu, apic_id in host_cpu.get("native_apic_ids", {}).items()
        }
        if (
            host_cpu.get("vendor") != "amd"
            or vcpus <= 0
            or len(pins) != vcpus
            or len(set(pins)) != vcpus
            or any(native_apic_ids.get(cpu) != vcpu for vcpu, cpu in enumerate(pins))
        ):
            raise AppError(
                "SVME-gated native CPUID requires each guest vCPU to be uniquely "
                "pinned to the AMD host logical CPU with the same native APIC ID."
            )
    stage_metadata.set("cpuid-policy", cpuid_policy)
    if physical_gpu_display:
        # libvirt preserves only one top-level element per custom metadata
        # namespace.  Store the mode on the existing stage element instead of
        # adding a sibling which disappears after virsh define/dumpxml.
        stage_metadata.set("single-gpu", "true")
    if not install_stage:
        stage_metadata.set("guest-vtd", "true" if guest_vtd_active else "false")
        stage_metadata.set("guest-secure-boot", "true" if guest_secure_boot else "false")
        stage_metadata.set(
            "guest-dma-protection",
            "true" if guest_dma_protection_active else "false",
        )
        stage_metadata.set(
            "guest-core-isolation",
            "true" if guest_core_isolation_active else "false",
        )
        stage_metadata.set(
            "guest-hyperv-enlightenments",
            "true" if guest_hyperv_enlightenments else "false",
        )
        stage_metadata.set(
            "guest-gmet", "true" if amd_hyperv_acceleration else "false",
        )
        if guest_vtd_active:
            stage_metadata.set(
                "guest-vtd-intremap",
                "true" if guest_vtd_intremap else "false",
            )
    _sub(domain, "memory", str(resources["memory_gib"]), unit="GiB")
    _sub(domain, "currentMemory", str(resources["memory_gib"]), unit="GiB")
    if bool(resources.get("hugepages_2m", False)):
        memory_backing = _sub(domain, "memoryBacking")
        hugepages = _sub(memory_backing, "hugepages")
        _sub(hugepages, "page", size=str(HUGEPAGE_2M_KIB), unit="KiB")
        _sub(memory_backing, "nosharepages")
    _sub(domain, "vcpu", str(resources["vcpus"]), placement="static")
    pinning = resources.get("cpu_pinning", {})
    vcpu_pins = [int(cpu) for cpu in pinning.get("vcpus", [])]
    emulator_cpus = sorted({int(cpu) for cpu in pinning.get("emulator", [])})
    if len(vcpu_pins) == int(resources["vcpus"]) and emulator_cpus:
        cputune = _sub(domain, "cputune")
        for vcpu, physical_cpu in enumerate(vcpu_pins):
            _sub(cputune, "vcpupin", vcpu=str(vcpu), cpuset=str(physical_cpu))
        _sub(
            cputune, "emulatorpin",
            cpuset=",".join(str(cpu) for cpu in emulator_cpus),
        )

    # Follow the README's safe order: install Windows on Ubuntu's known-good
    # QEMU/OVMF first, then switch to the patched QEMU 11/OVMF/SSDT artifacts.
    # A per-VM copy of Ubuntu's matching VARS template is persistent across
    # both stages so its BootOrder and Windows Boot Manager entry survive the
    # later switch to patched OVMF CODE.
    machine_type = INSTALL_MACHINE_TYPE if install_stage else MACHINE_TYPE
    qemu_path = INSTALL_QEMU if install_stage else paths["qemu"]
    ovmf_code = paths.get("install_ovmf_code", INSTALL_OVMF_CODE) if install_stage else paths["ovmf_code"]
    ovmf_code_format = "qcow2" if install_stage and paths.get("install_ovmf_code") else ("raw" if install_stage else "qcow2")
    ovmf_vars = paths.get("install_ovmf_vars", paths["ovmf_vars"])

    os_element = _sub(domain, "os")
    _sub(os_element, "type", "hvm", arch="x86_64", machine=machine_type)
    _sub(os_element, "loader", ovmf_code, readonly="yes", secure="yes", type="pflash", format=ovmf_code_format)
    _sub(os_element, "nvram", ovmf_vars, format="qcow2")
    _sub(os_element, "bootmenu", enable="yes")
    if install_stage:
        _sub(os_element, "boot", dev="cdrom")
    _sub(os_element, "boot", dev="hd")

    features = _sub(domain, "features")
    _sub(features, "acpi")
    _sub(features, "apic")
    hyperv = _sub(features, "hyperv", mode="custom")
    for feature in ("relaxed", "vapic", "spinlocks", "vpindex", "runtime", "synic", "stimer", "reset", "vendor_id", "frequencies", "reenlightenment", "tlbflush", "ipi", "evmcs", "avic"):
        _sub(hyperv, feature, state="off")
    kvm = _sub(features, "kvm")
    _sub(kvm, "hidden", state="on")
    if not install_stage:
        # split IOAPIC is part of the final VT-d identity. Keeping it out of
        # the bootstrap stage gives Windows PE the normal in-kernel IRQ path.
        _sub(features, "ioapic", driver="qemu")
    _sub(features, "msrs", unknown="fault")
    _sub(features, "pmu", state="on")
    _sub(features, "smm", state="on")
    _sub(features, "vmport", state="off")

    cpu = _sub(domain, "cpu", mode="host-passthrough", check="none", migratable="off")
    threads = max(1, int(resources.get("threads_per_core", host_cpu.get("threads_per_core", 1))))
    if int(resources["vcpus"]) % threads:
        threads = 1
    cores = max(1, int(resources["vcpus"]) // threads)
    _sub(cpu, "topology", sockets="1", cores=str(cores), threads=str(threads))
    _sub(cpu, "cache", mode="passthrough")
    _sub(cpu, "feature", policy="disable", name="hypervisor")
    virtualization = host_cpu.get("virtualization")
    if virtualization:
        # Host nested support is prepared globally. Only an explicitly opted-in
        # Core Isolation/VBS guest sees SVM/VMX; all other guests keep it hidden.
        _sub(
            cpu, "feature",
            policy="require" if guest_core_isolation_active else "disable",
            name=virtualization,
        )
    host_x86_features = set(host_cpu.get("x86_features", []))
    if (
        host_cpu.get("vendor") == "amd"
        and ("x86_features" not in host_cpu or "topoext" in host_x86_features)
    ):
        _sub(cpu, "feature", policy="require", name="topoext")

    clock = _sub(domain, "clock", offset="localtime")
    _sub(clock, "timer", name="tsc", present="yes", tickpolicy="discard", mode="native")
    for timer in ("hpet", "rtc", "pit"):
        _sub(clock, "timer", name=timer, present="yes")
    for timer in ("kvmclock", "hypervclock"):
        _sub(clock, "timer", name=timer, present="no")
    _sub(domain, "on_poweroff", "destroy")
    # A full domain stop gives firmware and the NVIDIA driver a clean reset.
    # Warm QEMU reset is unreliable on single-GPU passthrough; a Windows
    # "Restart" therefore stops the VM and it must be started once more.
    _sub(domain, "on_reboot", "destroy" if gpu_passthrough_active else "restart")
    _sub(domain, "on_crash", "destroy")
    pm = _sub(domain, "pm")
    _sub(pm, "suspend-to-mem", enabled="yes")
    _sub(pm, "suspend-to-disk", enabled="no")

    devices = _sub(domain, "devices")
    _sub(devices, "emulator", qemu_path)
    if tpm_mode == "emulator":
        tpm = _sub(devices, "tpm", model=tpm_model)
        _sub(tpm, "backend", type="emulator", version="2.0", persistent_state="yes")
    disk = _sub(devices, "disk", type="file", device="disk")
    _sub(disk, "driver", name="qemu", type="qcow2", cache="none", discard="ignore")
    _sub(disk, "source", file=paths["disk"])
    _sub(disk, "target", dev="sda", bus="sata")
    _sub(disk, "serial", identity["disk_serial"])
    if install_stage and paths.get("windows_iso"):
        cdrom = _sub(devices, "disk", type="file", device="cdrom")
        _sub(cdrom, "driver", name="qemu", type="raw")
        _sub(cdrom, "source", file=paths["windows_iso"])
        _sub(cdrom, "target", dev="sdb", bus="sata")
        _sub(cdrom, "readonly")
    _sub(devices, "controller", type="pci", index="0", model="pcie-root")
    _sub(devices, "controller", type="sata", index="0")
    if not minimal_devices or passthrough.get("usb"):
        _sub(devices, "controller", type="usb", index="0", model="qemu-xhci")
    else:
        # Omitting the controller makes libvirt add its default qemu-xhci
        # controller back when the domain is redefined.  An explicit none
        # model keeps the controller absent at runtime and in virt-manager.
        _sub(devices, "controller", type="usb", index="0", model="none")
    if not minimal_devices:
        _sub(devices, "input", type="mouse", bus="ps2")
        _sub(devices, "input", type="keyboard", bus="ps2")
    _sub(devices, "memballoon", model="none")
    if guest_vtd_active:
        iommu = _sub(devices, "iommu", model="intel")
        # QEMU refuses any VFIO device behind intel-iommu unless its caching
        # mode is enabled. DMA translation exposes the Intel DMAR/VT-d
        # device to the guest. Interrupt remapping is independent and defaults
        # off because QEMU 10.1/11 can hang Windows during early boot with it.
        # Leave aw-bits at QEMU's supported default (48).
        _sub(
            iommu, "driver",
            intremap="on" if guest_vtd_intremap else "off",
            caching_mode="on",
        )

    active_pci = list(passthrough.get("pci", []))
    if not gpu_passthrough_active and stage != "final":
        # Hardware passthrough starts only in the separate third VM step.
        active_pci = []
    elif gpu_passthrough_active:
        # Hooks still isolate the complete GPU slot, but expose only the
        # explicitly selected guest functions in both patched stages. New
        # profiles normally include HDMI/DP audio; legacy profiles without an
        # explicit guest list keep their prior display-only selection.
        active_pci = [
            address for address in active_pci
            if address not in set(gpu_pci) or address in set(gpu_guest_pci)
        ]
    native_group_keys = {
        _passthrough_group_key(address, host_pci)
        for address in gpu_guest_pci
    } if gpu_passthrough_active else set()
    pci_layout = _passthrough_pcie_layout(
        devices, active_pci, host_pci, native_group_keys=native_group_keys,
    )
    if gpu_passthrough_active:
        gpu_slots = {
            _normalized_pci_address(address).rsplit(".", 1)[0]
            for address in gpu_pci
        }
        for address in gpu_guest_pci:
            normalized = _normalized_pci_address(address)
            slot, function = normalized.rsplit(".", 1)
            # Preserve the real multifunction nature of the GPU slot even
            # when its optional HDMI/DP audio function is not exposed to the
            # guest. NVIDIA's Windows driver/GOP may depend on this bit.
            if address in pci_layout and function == "0" and slot in gpu_slots and any(
                _normalized_pci_address(other).rsplit(".", 1)[0] == slot
                and _normalized_pci_address(other).rsplit(".", 1)[1] != "0"
                for other in gpu_pci
            ):
                pci_layout[address]["multifunction"] = "on"
    gpu_display_pci = set(_gpu_display_functions(gpu_pci, host_pci))
    for index, address in enumerate(active_pci):
        hostdev = _sub(devices, "hostdev", mode="subsystem", type="pci", managed="yes")
        source = _sub(hostdev, "source")
        _sub(source, "address", **_pci_address(address))
        alias = address.replace(":", "-").replace(".", "-")
        _sub(hostdev, "alias", name=f"ua-kvm-aavm-pci-{alias}")
        _sub(hostdev, "address", **pci_layout[address])
        if gpu_passthrough_active and address in gpu_display_pci:
            rom_attributes = {
                "bar": "on" if passthrough.get("gpu_rom_bar", False) else "off"
            }
            if address == gpu_pci[0] and passthrough.get("rom_file"):
                rom_attributes["file"] = passthrough["rom_file"]
            _sub(hostdev, "rom", **rom_attributes)
    for index, usb in enumerate(
        passthrough.get("usb", []) if stage in {"gpu-setup", "final"} else []
    ):
        vendor = str(usb.get("vendor_id", "")).lower().removeprefix("0x")
        product = str(usb.get("product_id", "")).lower().removeprefix("0x")
        if not re.fullmatch(r"[0-9a-f]{4}", vendor) or not re.fullmatch(r"[0-9a-f]{4}", product):
            raise AppError(f"Invalid USB vendor/product ID: {vendor}:{product}")
        hostdev = _sub(devices, "hostdev", mode="subsystem", type="usb", managed="yes")
        source = _sub(hostdev, "source", startupPolicy="optional")
        _sub(source, "vendor", id=f"0x{vendor}")
        _sub(source, "product", id=f"0x{product}")
        if usb.get("match_address"):
            _sub(source, "address", bus=str(int(usb["bus"])), device=str(int(usb["device"])))
        _sub(hostdev, "alias", name=f"ua-kvm-aavm-usb-{vendor}-{product}-{index}")
    disable_virtual_network = (
        passthrough.get("disable_virtual_network", bool(passthrough.get("network_pci")))
        if stage == "final" else False
    )
    if not minimal_devices and not disable_virtual_network:
        interface = _sub(devices, "interface", type="network")
        _sub(interface, "mac", address=identity["mac"])
        _sub(interface, "source", network="default")
        _sub(interface, "model", type="e1000e")
        _sub(interface, "alias", name="ua-kvm-aavm-network")

    if not physical_gpu_display:
        graphics_type = "vnc" if stage in {"devirtualized", "gpu-setup"} else "spice"
        graphics = _sub(devices, "graphics", type=graphics_type, autoport="yes")
        _sub(graphics, "listen", type="address")
        video = _sub(devices, "video")
        _sub(video, "model", type="vga", vram="16384", heads="1", primary="yes")
    # The README keeps SPICE audio as the default and labels direct host
    # PipeWire as optional. A system-libvirt QEMU runs as libvirt-qemu and
    # cannot safely traverse /run/user/<desktop uid>; direct PipeWire therefore
    # fails before the monitor starts. The devirtualized stage uses VNC, so its
    # virtual HDA device needs the explicit "none" backend: libvirt rejects a
    # SPICE audio backend when there is no SPICE graphics device. During
    # single-GPU stages the passed-through GPU audio function replaces this
    # virtual HDA device.
    if not minimal_devices and (stage != "final" or not gpu_pci):
        sound = _sub(devices, "sound", model="ich9")
        _sub(sound, "codec", type="duplex")
        audio_type = "none" if stage in {"devirtualized", "gpu-setup"} else "spice"
        _sub(devices, "audio", id="1", type=audio_type)

    commandline = _sub(domain, f"{{{QEMU_NS}}}commandline")
    if guest_dma_protection_active:
        _sub(commandline, f"{{{QEMU_NS}}}arg", value="-global")
        _sub(
            commandline, f"{{{QEMU_NS}}}arg",
            value="intel-iommu.dma-control-platform-opt-in=on",
        )
    if minimal_devices:
        # Ubuntu 24.04 libvirt predates the <features><ps2 state='off'/>
        # schema, while the per-VM QEMU 11 q35 machine supports i8042=off.
        _sub(commandline, f"{{{QEMU_NS}}}arg", value="-machine")
        _sub(commandline, f"{{{QEMU_NS}}}arg", value="i8042=off")
    for value in _smbios_args(identity, include_type9=not install_stage):
        _sub(commandline, f"{{{QEMU_NS}}}arg", value=value)
    if not install_stage:
        for aml in paths.get("ssdt", []):
            _sub(commandline, f"{{{QEMU_NS}}}arg", value="-acpitable")
            _sub(commandline, f"{{{QEMU_NS}}}arg", value=f"file={aml}")
    apply_hyperv_enlightenments(
        domain, guest_hyperv_enlightenments, amd_hyperv_acceleration,
        amd_hyperv_avic,
    )

    if physical_gpu_display and gpu_guest_pci:
        display = _gpu_display_functions(gpu_guest_pci, host_pci)[0]
        alias = display.replace(":", "-").replace(".", "-")
        override = _sub(domain, f"{{{QEMU_NS}}}override")
        device = _sub(
            override, f"{{{QEMU_NS}}}device",
            alias=f"ua-kvm-aavm-pci-{alias}",
        )
        frontend = _sub(device, f"{{{QEMU_NS}}}frontend")
        _sub(
            frontend, f"{{{QEMU_NS}}}property", name="x-vga",
            type="bool", value="true",
        )

    ET.indent(domain, space="  ")
    return ET.tostring(domain, encoding="unicode", xml_declaration=True) + "\n"


def _pci_source_matches(source: ET.Element | None, addresses: set[str]) -> bool:
    element = source.find("address") if source is not None else None
    if element is None:
        return False
    actual = {
        "type": "pci",
        "domain": element.get("domain", "0x0000"),
        "bus": element.get("bus", "0x00"),
        "slot": element.get("slot", "0x00"),
        "function": element.get("function", "0x0"),
    }
    for address in addresses:
        expected = _pci_address(address)
        if all(int(actual[key], 0) == int(expected[key], 0) for key in ("domain", "bus", "slot", "function")):
            return True
    return False


def _usb_source_matches(source: ET.Element | None, configured: list[dict]) -> bool:
    if source is None:
        return False
    vendor_element = source.find("vendor")
    product_element = source.find("product")
    if vendor_element is None or product_element is None:
        return False
    vendor = vendor_element.get("id", "").lower().removeprefix("0x")
    product = product_element.get("id", "").lower().removeprefix("0x")
    return any(
        vendor == str(item.get("vendor_id", "")).lower().removeprefix("0x")
        and product == str(item.get("product_id", "")).lower().removeprefix("0x")
        for item in configured
    )


def update_passthrough(xml_text: str, old: dict, new: dict, identity: dict) -> str:
    root = ET.fromstring(xml_text)
    devices = root.find("devices")
    if devices is None:
        raise AppError("Domain XML has no <devices> section.")

    old_pci = set(old.get("pci", []))
    old_usb = old.get("usb", [])
    for hostdev in list(devices.findall("hostdev")):
        alias = hostdev.find("alias")
        managed_alias = alias is not None and alias.get("name", "").startswith("ua-kvm-aavm-")
        source = hostdev.find("source")
        known = (
            hostdev.get("type") == "pci" and _pci_source_matches(source, old_pci)
        ) or (
            hostdev.get("type") == "usb" and _usb_source_matches(source, old_usb)
        )
        if managed_alias or known:
            devices.remove(hostdev)

    pci_layout = _passthrough_pcie_layout(
        devices, list(new.get("pci", [])), list(new.get("_host_pci", [])),
    )
    for index, address in enumerate(new.get("pci", [])):
        hostdev = _sub(devices, "hostdev", mode="subsystem", type="pci", managed="yes")
        source = _sub(hostdev, "source")
        _sub(source, "address", **_pci_address(address))
        alias = address.replace(":", "-").replace(".", "-")
        _sub(hostdev, "alias", name=f"ua-kvm-aavm-pci-{alias}")
        _sub(hostdev, "address", **pci_layout[address])
        if index == 0 and new.get("rom_file"):
            _sub(hostdev, "rom", file=new["rom_file"])

    usb_controller = devices.find("controller[@type='usb'][@index='0'][@model='qemu-xhci']")
    want_usb_controller = bool(new.get("usb")) or not new.get("_minimal_devices", False)
    if want_usb_controller and usb_controller is None:
        _sub(devices, "controller", type="usb", index="0", model="qemu-xhci")
    elif not want_usb_controller and usb_controller is not None:
        devices.remove(usb_controller)

    for index, usb in enumerate(new.get("usb", [])):
        vendor = str(usb["vendor_id"]).lower().removeprefix("0x")
        product = str(usb["product_id"]).lower().removeprefix("0x")
        if not re.fullmatch(r"[0-9a-f]{4}", vendor) or not re.fullmatch(r"[0-9a-f]{4}", product):
            raise AppError(f"Invalid USB vendor/product ID: {vendor}:{product}")
        hostdev = _sub(devices, "hostdev", mode="subsystem", type="usb", managed="yes")
        source = _sub(hostdev, "source", startupPolicy="optional")
        _sub(source, "vendor", id=f"0x{vendor}")
        _sub(source, "product", id=f"0x{product}")
        if usb.get("match_address"):
            _sub(source, "address", bus=str(int(usb["bus"])), device=str(int(usb["device"])))
        _sub(hostdev, "alias", name=f"ua-kvm-aavm-usb-{vendor}-{product}-{index}")

    managed_interfaces = []
    default_interface_exists = False
    for interface in devices.findall("interface"):
        alias = interface.find("alias")
        source = interface.find("source")
        mac = interface.find("mac")
        if source is not None and source.get("network") == "default":
            default_interface_exists = True
        if (
            alias is not None and alias.get("name") == "ua-kvm-aavm-network"
        ) or (
            source is not None and source.get("network") == "default"
            and mac is not None and mac.get("address", "").lower() == identity["mac"].lower()
        ):
            managed_interfaces.append(interface)

    disable_network = new.get("_minimal_devices", False) or new.get("disable_virtual_network", bool(new.get("network_pci")))
    if disable_network:
        for interface in managed_interfaces:
            devices.remove(interface)
    elif not default_interface_exists:
        interface = _sub(devices, "interface", type="network")
        _sub(interface, "mac", address=identity["mac"])
        _sub(interface, "source", network="default")
        _sub(interface, "model", type="e1000e")
        _sub(interface, "alias", name="ua-kvm-aavm-network")

    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode", xml_declaration=True) + "\n"


def update_identity(xml_text: str, identity: dict, _memory_gib: int) -> str:
    root = ET.fromstring(xml_text)
    type_element = root.find("./os/type")
    emulator = root.findtext("./devices/emulator", default="")
    install_stage = (
        type_element is not None
        and type_element.get("machine") == INSTALL_MACHINE_TYPE
        and emulator == INSTALL_QEMU
    )
    uuid_element = root.find("uuid")
    if uuid_element is not None:
        uuid_element.text = identity["domain_uuid"]
    for mac in root.findall("./devices/interface/mac"):
        mac.set("address", identity["mac"])
    for disk in root.findall("./devices/disk[@device='disk']"):
        serial = disk.find("serial")
        if serial is None:
            serial = _sub(disk, "serial")
        serial.text = identity["disk_serial"]
        target = disk.find("target")
        bus = target.get("bus", "") if target is not None else ""
        wwn_element = disk.find("wwn")
        if bus in {"ide", "scsi"}:
            if wwn_element is None:
                wwn_element = _sub(disk, "wwn")
            wwn_element.text = identity["disk_wwn"].removeprefix("0x")
        elif wwn_element is not None:
            # libvirt rejects WWN on SATA, virtio and other disk buses.
            disk.remove(wwn_element)
    commandline = root.find(f"{{{QEMU_NS}}}commandline")
    if commandline is None:
        commandline = _sub(root, f"{{{QEMU_NS}}}commandline")
    preserved: list[ET.Element] = []
    children = list(commandline)
    skip_next = False
    for index, child in enumerate(children):
        if skip_next:
            skip_next = False
            continue
        if child.get("value") == "-smbios" and index + 1 < len(children):
            skip_next = True
            continue
        preserved.append(copy.deepcopy(child))
    commandline.clear()
    for value in _smbios_args(identity, include_type9=not install_stage):
        _sub(commandline, f"{{{QEMU_NS}}}arg", value=value)
    commandline.extend(preserved)
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode", xml_declaration=True) + "\n"


def update_artifact_paths(xml_text: str, paths: dict) -> str:
    root = ET.fromstring(xml_text)
    type_element = root.find("./os/type")
    install_stage = (
        type_element is not None
        and type_element.get("machine") == INSTALL_MACHINE_TYPE
    )
    emulator = root.find("./devices/emulator")
    if emulator is not None and not install_stage:
        emulator.text = paths["qemu"]
    loader = root.find("./os/loader")
    if loader is not None and not install_stage:
        loader.text = paths["ovmf_code"]
    nvram = root.find("./os/nvram")
    if nvram is not None:
        nvram.text = paths.get("install_ovmf_vars", paths["ovmf_vars"])
    commandline = root.find(f"{{{QEMU_NS}}}commandline")
    if commandline is not None:
        aml_paths = iter(paths.get("ssdt", []))
        for arg in commandline.findall(f"{{{QEMU_NS}}}arg"):
            value = arg.get("value", "")
            if value.startswith("file=") and "ssdt" in value.lower():
                try:
                    arg.set("value", f"file={next(aml_paths)}")
                except StopIteration:
                    break
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode", xml_declaration=True) + "\n"


def validate_required(xml_text: str) -> list[str]:
    root = ET.fromstring(xml_text)
    errors: list[str] = []
    type_element = root.find("./os/type")
    emulator = root.findtext("./devices/emulator", default="")
    machine = type_element.get("machine") if type_element is not None else ""
    install_stage = machine == INSTALL_MACHINE_TYPE and emulator == INSTALL_QEMU
    patched_stage = machine == MACHINE_TYPE and emulator != INSTALL_QEMU
    stage = root.findtext(f"./metadata/{{{AAVM_NS}}}stage", default="")
    stage_element = root.find(f"./metadata/{{{AAVM_NS}}}stage")
    x_vga = root.find(
        f"./{{{QEMU_NS}}}override/{{{QEMU_NS}}}device/"
        f"{{{QEMU_NS}}}frontend/{{{QEMU_NS}}}property"
        "[@name='x-vga'][@type='bool'][@value='true']"
    )
    single_gpu = bool(
        (stage_element is not None and stage_element.get("single-gpu") == "true")
        or x_vga is not None
    )
    checks = {
        "KVM hidden": root.find("./features/kvm/hidden[@state='on']"),
        "disabled balloon": root.find("./devices/memballoon[@model='none']"),
    }
    tpm = root.find("./devices/tpm")
    tpm_mode = stage_element.get("tpm-mode", "none") if stage_element is not None else "none"
    tpm_profile = stage_element.get("tpm-profile", "generic") if stage_element is not None else "generic"
    if tpm_mode == "emulator":
        checks["persistent vTPM"] = (
            tpm
            if tpm is not None
            and tpm.get("model") in TPM_MODELS
            and tpm.find("backend[@type='emulator'][@version='2.0'][@persistent_state='yes']") is not None
            else None
        )
        if tpm_profile == "amd-ftpm" and (tpm is None or tpm.get("model") != "tpm-crb"):
            errors.append("AMD fTPM profile requires tpm-crb")
        elif tpm_profile not in TPM_PROFILES:
            errors.append(f"Unsupported TPM profile metadata: {tpm_profile}")
    elif tpm_mode == "none" and tpm is not None:
        errors.append("TPM XML exists while profile declares no TPM")
    if patched_stage:
        checks["QEMU split IOAPIC"] = root.find("./features/ioapic[@driver='qemu']")
        if stage == "gpu-setup":
            checks["GPU maintenance VNC"] = root.find("./devices/graphics[@type='vnc']")
            checks["GPU maintenance VGA"] = root.find("./devices/video")
            checks["GPU maintenance passthrough"] = root.find(
                "./devices/hostdev[@type='pci']/rom[@bar]"
            )
            if x_vga is not None:
                errors.append("GPU maintenance mode must keep virtual VGA primary")
            if root.findtext("./on_reboot", default="") != "destroy":
                errors.append("GPU maintenance XML must use on_reboot=destroy")
        if single_gpu:
            checks["single-GPU x-vga override"] = x_vga
            checks["single-GPU explicit ROM BAR"] = root.find(
                "./devices/hostdev[@type='pci']/rom[@bar]"
            )
            if root.findtext("./on_reboot", default="") != "destroy":
                errors.append(
                    "Single-GPU compatibility XML must use on_reboot=destroy"
                )
        if (
            (stage_element is not None and stage_element.get("guest-vtd") == "true")
            or root.find("./devices/iommu") is not None
        ):
            # DMA translation is the guest-IOMMU capability. Interrupt
            # remapping is optional and is tracked independently in metadata.
            expected_intremap = (
                "on"
                if stage_element is not None
                and stage_element.get("guest-vtd-intremap") == "true"
                else "off"
            )
            iommu_driver = root.find("./devices/iommu[@model='intel']/driver")
            checks["Intel guest IOMMU"] = (
                iommu_driver
                if iommu_driver is not None
                and iommu_driver.get("intremap") == expected_intremap
                and iommu_driver.get("caching_mode") == "on"
                else None
            )
    for label, element in checks.items():
        if element is None:
            errors.append(f"Missing required XML: {label}")
    if not (install_stage or patched_stage):
        errors.append(
            "Invalid QEMU/machine stage: Windows install must use "
            f"{INSTALL_QEMU} + {INSTALL_MACHINE_TYPE}; patched stages must "
            f"use the per-VM QEMU + {MACHINE_TYPE}"
        )
    qemu_args = root.findall(
        f"./{{{QEMU_NS}}}commandline/{{{QEMU_NS}}}arg"
    )
    if (
        stage_element is not None
        and stage_element.get("guest-dma-protection") == "true"
        and not any(
            arg.get("value") == "intel-iommu.dma-control-platform-opt-in=on"
            for arg in qemu_args
        )
    ):
        errors.append("Kernel DMA Protection requires the QEMU DMAR platform opt-in property")
    if any(
        arg.get("value", "").startswith("type=17,")
        and re.search(r"(?:^|,)size=", arg.get("value", ""))
        for arg in qemu_args
    ):
        errors.append("Unsupported QEMU SMBIOS type 17 option: size")
    if install_stage and any(
        arg.get("value", "").startswith("type=9,") for arg in qemu_args
    ):
        errors.append("SMBIOS type 9 requires the patched QEMU stage")
    if root.find("./devices/audio[@type='pipewire']") is not None:
        errors.append("Unsupported system-libvirt audio backend: pipewire")
    if (
        root.find("./devices/audio[@type='spice']") is not None
        and root.find("./devices/graphics[@type='spice']") is None
    ):
        errors.append("SPICE audio requires SPICE graphics")
    required_virtualization = [
        feature for feature in root.findall("./cpu/feature")
        if feature.get("name") in {"svm", "vmx"}
        and feature.get("policy") == "require"
    ]
    core_isolation = bool(
        stage_element is not None
        and stage_element.get("guest-core-isolation") == "true"
    )
    if core_isolation and len(required_virtualization) != 1:
        errors.append("Core Isolation/VBS requires exactly one guest SVM/VMX CPU feature")
    if (
        core_isolation
        and stage_element is not None
        and stage_element.get("guest-secure-boot") != "true"
    ):
        errors.append("Core Isolation/VBS requires Guest UEFI Secure Boot metadata")
    if not core_isolation and required_virtualization:
        errors.append("Guest SVM/VMX requires explicit Core Isolation/VBS metadata")
    hyperv_enlightenments = bool(
        stage_element is not None
        and stage_element.get("guest-hyperv-enlightenments") == "true"
    )
    if hyperv_enlightenments:
        for feature in HYPERV_ACCELERATED_FEATURES:
            if root.find(f"./features/hyperv/{feature}[@state='on']") is None:
                errors.append(
                    f"HVCI nested Hyper-V acceleration is missing {feature}"
                )
        if root.find("./features/hyperv/stimer/direct[@state='on']") is None:
            errors.append("HVCI nested Hyper-V acceleration requires direct stimer")
        if root.find("./clock/timer[@name='hypervclock'][@present='yes']") is None:
            errors.append("HVCI nested Hyper-V acceleration requires hypervclock")
    gmet_enabled = bool(
        stage_element is not None and stage_element.get("guest-gmet") == "true"
    )
    qemu_values = {arg.get("value", "") for arg in qemu_args}
    if hyperv_enlightenments:
        for value in HYPERV_NESTED_MMU_QEMU_GLOBALS:
            if value not in qemu_values:
                errors.append(
                    f"HVCI nested shadow-MMU guard is missing {value}"
                )
    elif any(value in qemu_values for value in HYPERV_NESTED_MMU_QEMU_GLOBALS):
        errors.append("Nested shadow-MMU globals require Hyper-V enlightenments")
    if gmet_enabled:
        for value in HYPERV_AMD_QEMU_GLOBALS:
            if value not in qemu_values:
                errors.append(f"AMD nested Hyper-V acceleration is missing {value}")
    elif any(value in qemu_values for value in HYPERV_AMD_QEMU_GLOBALS):
        errors.append("AMD nested Hyper-V globals require guest-gmet metadata")
    memory_backing = root.find("./memoryBacking")
    if memory_backing is not None:
        hugepage = memory_backing.find(
            f"./hugepages/page[@size='{HUGEPAGE_2M_KIB}'][@unit='KiB']"
        )
        if hugepage is None:
            errors.append("Unsupported hugepage configuration: require 2 MiB pages")
        if memory_backing.find("nosharepages") is None:
            errors.append("Hugepage memory must disable KSM sharing")
    if install_stage and any(
        arg.get("value", "").startswith("file=")
        and "ssdt" in arg.get("value", "").lower()
        for arg in qemu_args
    ):
        errors.append("Patched SSDT must be delayed until Windows is installed")
    return errors
