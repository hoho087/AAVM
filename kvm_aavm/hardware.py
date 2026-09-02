from __future__ import annotations

import json
import os
import platform
import re
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .util import Runner, command_exists


@dataclass
class PciDevice:
    address: str
    class_code: str
    vendor_id: str
    device_id: str
    description: str
    iommu_group: int | None = None
    driver: str | None = None
    interfaces: list[str] = field(default_factory=list)

    @property
    def node_name(self) -> str:
        return "pci_0000_" + self.address.replace(":", "_").replace(".", "_")

    @property
    def slot(self) -> str:
        return self.address.rsplit(".", 1)[0]


@dataclass
class UsbDevice:
    bus: int
    device: int
    vendor_id: str
    product_id: str
    description: str
    interfaces: list[str] = field(default_factory=list)

    @property
    def is_network(self) -> bool:
        words = (self.description + " " + " ".join(self.interfaces)).lower()
        return bool(self.interfaces) or any(
            word in words for word in ("ethernet", "network", "wireless", "wlan", "wi-fi", "wifi", "lan")
        )


def _read_cpuinfo() -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        for line in Path("/proc/cpuinfo").read_text(errors="replace").splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                values.setdefault(key.strip(), value.strip())
    except OSError:
        pass
    return values


def _cpu_apic_ids() -> dict[str, int]:
    """Return Linux logical CPU -> native initial APIC ID from /proc/cpuinfo."""
    try:
        blocks = Path("/proc/cpuinfo").read_text(errors="replace").split("\n\n")
    except OSError:
        return {}
    result: dict[str, int] = {}
    for block in blocks:
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            fields[key.strip()] = value.strip()
        logical = fields.get("processor")
        apic = fields.get("initial apicid", fields.get("apicid"))
        try:
            if logical is not None and apic is not None:
                result[str(int(logical))] = int(apic)
        except ValueError:
            continue
    return result


def _cpu_topology() -> tuple[list[list[int]], int]:
    """Return online logical CPUs grouped by physical package/core.

    Unlike the human-readable labels emitted by ``lscpu -J``, sysfs is not
    translated by the current locale.  This matters on a Chinese Ubuntu host,
    where the old parser mistook an 8C/16T CPU for 16C/16T.
    """
    groups: dict[tuple[int, int], list[int]] = {}
    packages: set[int] = set()
    root = Path("/sys/devices/system/cpu")
    for cpu_path in root.glob("cpu[0-9]*"):
        suffix = cpu_path.name[3:]
        if not suffix.isdigit():
            continue
        online = cpu_path / "online"
        try:
            if online.exists() and online.read_text().strip() == "0":
                continue
            package = int((cpu_path / "topology/physical_package_id").read_text().strip())
            core = int((cpu_path / "topology/core_id").read_text().strip())
        except (OSError, ValueError):
            continue
        logical = int(suffix)
        packages.add(package)
        groups.setdefault((package, core), []).append(logical)
    ordered = [sorted(values) for _, values in sorted(groups.items())]
    return ordered, max(1, len(packages))


def vm_cpu_layout(info: dict, vcpus: int, shared_emulator_cores: int = 0) -> dict:
    """Build an SMT-aware guest topology and an optional physical CPU map.

    ``shared_emulator_cores`` is reserved for the full-topology AMD native
    CPUID-handoff profile.  In that profile every native APIC ID must have
    a matching vCPU, so QEMU's emulator thread shares the final complete SMT
    cores instead of requiring CPUs outside the guest pin set.
    """
    requested = max(1, int(vcpus))
    sibling_groups = [
        sorted({int(cpu) for cpu in group})
        for group in info.get("thread_siblings", [])
        if group
    ]
    host_threads = max(1, int(info.get("threads_per_core", 1)))
    # Two threads is the useful x86 default.  Fall back to one thread for an
    # odd/manual vCPU count instead of generating an invalid topology.
    threads = 2 if host_threads >= 2 and requested % 2 == 0 else 1
    eligible = [group for group in sibling_groups if len(group) >= threads]
    guest_cores = requested // threads
    allow_shared_emulator = int(shared_emulator_cores) > 0
    if len(eligible) < guest_cores or (
        len(eligible) == guest_cores and not allow_shared_emulator
    ):
        return {
            "threads_per_core": threads,
            "cores": guest_cores,
            "vcpus": requested,
            "vcpu_pins": [],
            "emulator_cpus": [],
        }

    # In the AMD delayed-handoff mode, CPUID reports the physical CPU's native
    # APIC ID after the reset grace (or after EFER.SVME).  Pin vCPU N to the host
    # logical CPU whose native APIC ID is N so Hyper-V's one-socket
    # core/thread topology remains coherent.  Firmware and the first reset
    # grace period use KVM's intercepted CPUID model before the handoff.
    native_apic_ids: dict[int, int] = {}
    for cpu, apic_id in info.get("native_apic_ids", {}).items():
        try:
            native_apic_ids[int(cpu)] = int(apic_id)
        except (TypeError, ValueError):
            continue
    if info.get("vendor") == "amd" and native_apic_ids:
        cpu_by_apic = {apic_id: cpu for cpu, apic_id in native_apic_ids.items()}
        aligned = [cpu_by_apic.get(vcpu) for vcpu in range(requested)]
        if all(cpu is not None for cpu in aligned) and len(set(aligned)) == requested:
            pins = [int(cpu) for cpu in aligned if cpu is not None]
            selected_cpus = set(pins)
            # Only accept a mapping made of complete SMT core groups.  This
            # preserves the guest topology and leaves complete cores to Linux.
            selected_groups = [
                group for group in eligible
                if set(group[:threads]).issubset(selected_cpus)
            ]
            if len(selected_groups) == guest_cores:
                emulator = sorted({
                    cpu for group in sibling_groups for cpu in group
                    if cpu not in selected_cpus
                })
                if not emulator and allow_shared_emulator:
                    shared_groups = selected_groups[-min(
                        int(shared_emulator_cores), len(selected_groups)
                    ):]
                    emulator = sorted({
                        cpu for group in shared_groups for cpu in group[:threads]
                    })
                if emulator:
                    return {
                        "threads_per_core": threads,
                        "cores": guest_cores,
                        "vcpus": requested,
                        "vcpu_pins": pins,
                        "emulator_cpus": emulator,
                        "emulator_shared": bool(
                            selected_cpus.intersection(emulator)
                        ),
                    }

    # Keep the first physical cores for Ubuntu and QEMU's emulator thread;
    # assign complete SMT sibling pairs from the remaining cores to the guest.
    selected = eligible[-guest_cores:]
    selected_ids = {id(group) for group in selected}
    reserved = [group for group in sibling_groups if id(group) not in selected_ids]
    pins = [cpu for group in selected for cpu in group[:threads]]
    emulator = sorted({cpu for group in reserved for cpu in group})
    return {
        "threads_per_core": threads,
        "cores": guest_cores,
        "vcpus": requested,
        "vcpu_pins": pins if len(pins) == requested else [],
        "emulator_cpus": emulator,
    }


def cpu_info() -> dict:
    raw = _read_cpuinfo()
    vendor_id = raw.get("vendor_id", "unknown")
    vendor = "amd" if vendor_id == "AuthenticAMD" else "intel" if vendor_id == "GenuineIntel" else "unknown"
    logical = os.cpu_count() or 1
    sibling_groups, sysfs_sockets = _cpu_topology()
    sockets = cores = threads = None
    if command_exists("lscpu"):
        result = Runner(verbose=False).run(["lscpu", "-J"], capture=True, check=False)
        try:
            fields = {x["field"].rstrip(":"): x["data"] for x in json.loads(result.stdout)["lscpu"]}
            sockets = int(fields.get("Socket(s)", "1"))
            cores = int(fields.get("Core(s) per socket", str(logical))) * sockets
            threads = int(fields.get("Thread(s) per core", "1"))
        except (ValueError, KeyError, json.JSONDecodeError):
            pass
    if sibling_groups:
        cores = len(sibling_groups)
        threads = max(len(group) for group in sibling_groups)
        sockets = sysfs_sockets
        logical = sum(len(group) for group in sibling_groups)
    threads = threads or 1
    cores = cores or max(1, logical // threads)
    sockets = sockets or 1
    flags = set(raw.get("flags", "").split())
    return {
        "vendor": vendor,
        "vendor_id": vendor_id,
        "model": raw.get("model name", platform.processor() or "Unknown CPU"),
        "logical_cpus": logical,
        "cores": cores,
        "threads_per_core": threads,
        "thread_siblings": sibling_groups,
        "native_apic_ids": _cpu_apic_ids(),
        "sockets": sockets,
        "virtualization": "svm" if "svm" in flags else "vmx" if "vmx" in flags else None,
        # Store only feature bits consumed by this deployer.  Older AMD CPUs
        # may provide SVM/NPT without AVIC or topoext; treating every AMD CPU
        # as a current Zen desktop made otherwise valid profiles fail at QEMU
        # feature validation.
        "x86_features": sorted(flags & {"svm", "npt", "avic", "topoext"}),
    }


def _module_parameter_enabled(module: str, parameter: str) -> bool:
    try:
        value = Path(f"/sys/module/{module}/parameters/{parameter}").read_text().strip().lower()
    except OSError:
        return False
    return value in {"1", "y", "yes", "on"}


def kvm_capabilities(cpu: dict | None = None) -> dict[str, bool]:
    """Return only KVM capabilities that are safe to encode in a VM profile."""
    cpu = cpu or cpu_info()
    if cpu.get("vendor") != "amd":
        return {"nested": False, "npt": False, "avic": False, "gmet": False}
    features = set(cpu.get("x86_features", []))
    # Profiles created before x86_features was recorded retain the old module
    # parameter behavior.  Fresh profiles additionally gate hardware-specific
    # acceleration, without changing current Zen behavior.
    feature_data_available = "x86_features" in cpu
    npt_supported = not feature_data_available or "npt" in features
    avic_supported = not feature_data_available or "avic" in features
    nested = _module_parameter_enabled("kvm_amd", "nested")
    npt = npt_supported and _module_parameter_enabled("kvm_amd", "npt")
    return {
        "nested": nested,
        "npt": npt,
        "avic": avic_supported and _module_parameter_enabled("kvm_amd", "avic"),
        "gmet": nested and npt and _module_parameter_enabled("kvm_amd", "gmet"),
    }


def memory_gib() -> int:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return max(1, int(line.split()[1]) // 1024 // 1024)
    except OSError:
        pass
    return 1


PCI_RE = re.compile(
    r"^(?P<addr>[0-9a-fA-F:.]+)\s+.+?\[(?P<class>[0-9a-fA-F]{4})\]:\s+"
    r"(?P<desc>.+?)\s+\[(?P<vendor>[0-9a-fA-F]{4}):(?P<device>[0-9a-fA-F]{4})\](?:\s|$)"
)

def _network_interfaces(sys_path: Path) -> list[str]:
    names: set[str] = set()
    for net_path in list(sys_path.glob("net/*")) + list(sys_path.glob("*/net/*")):
        names.add(net_path.name)
    return sorted(names)




def pci_devices() -> list[PciDevice]:
    if not command_exists("lspci"):
        return []
    result = Runner(verbose=False).run(["lspci", "-Dnn"], capture=True, check=False)
    devices: list[PciDevice] = []
    for line in result.stdout.splitlines():
        match = PCI_RE.match(line)
        if not match:
            continue
        address = match.group("addr")
        short = address[5:] if address.startswith("0000:") else address
        sys_path = Path("/sys/bus/pci/devices") / (address if address.startswith("0000:") else f"0000:{address}")
        group = None
        driver = None
        try:
            group = int((sys_path / "iommu_group").resolve().name)
        except (OSError, ValueError):
            pass
        try:
            driver = (sys_path / "driver").resolve().name
        except OSError:
            pass
        devices.append(PciDevice(
            address=short.lower(), class_code=match.group("class").lower(),
            vendor_id=match.group("vendor").lower(), device_id=match.group("device").lower(),
            description=match.group("desc"), iommu_group=group, driver=driver,
            interfaces=_network_interfaces(sys_path),
        ))
    return devices


USB_RE = re.compile(
    r"^Bus (?P<bus>\d{3}) Device (?P<device>\d{3}): ID "
    r"(?P<vendor>[0-9a-fA-F]{4}):(?P<product>[0-9a-fA-F]{4})(?:\s+(?P<desc>.*))?$"
)


def _usb_sys_path(bus: int, device: int) -> Path | None:
    for sys_path in Path("/sys/bus/usb/devices").glob("*"):
        try:
            if int((sys_path / "busnum").read_text().strip()) != bus:
                continue
            if int((sys_path / "devnum").read_text().strip()) != device:
                continue
        except (OSError, ValueError):
            continue
        return sys_path
    return None


def parse_usb_line(line: str) -> UsbDevice | None:
    match = USB_RE.match(line.strip())
    if not match:
        return None
    # Linux Foundation entries are the host controller's root hubs. They are
    # not detachable USB peripherals and must never be offered for passthrough.
    if match.group("vendor").lower() == "1d6b":
        return None
    bus = int(match.group("bus"))
    device = int(match.group("device"))
    sys_path = _usb_sys_path(bus, device)
    description = (match.group("desc") or "Unknown USB device").strip()
    if sys_path is not None:
        try:
            manufacturer = (sys_path / "manufacturer").read_text().strip()
            product = (sys_path / "product").read_text().strip()
            description = " ".join(part for part in (manufacturer, product) if part)
        except OSError:
            pass
    return UsbDevice(
        bus=bus, device=device, vendor_id=match.group("vendor").lower(),
        product_id=match.group("product").lower(), description=description,
        interfaces=_network_interfaces(sys_path) if sys_path is not None else [],
    )


def usb_devices() -> list[UsbDevice]:
    if not command_exists("lsusb"):
        return []
    result = Runner(verbose=False).run(["lsusb"], capture=True, check=False)
    return [device for line in result.stdout.splitlines() if (device := parse_usb_line(line)) is not None]



def gpu_groups(devices: list[PciDevice]) -> list[list[PciDevice]]:
    slots = {d.slot for d in devices if d.class_code in {"0300", "0302"}}
    return [[d for d in devices if d.slot == slot] for slot in sorted(slots)]


def host_fingerprint(devices: list[PciDevice] | None = None) -> dict:
    provided_devices = devices is not None
    devices = devices if provided_devices else pci_devices()
    cpu = cpu_info()
    return {
        "os": platform.freedesktop_os_release().get("PRETTY_NAME", platform.platform()),
        "arch": platform.machine(),
        "kernel": platform.release(),
        "cpu": cpu,
        "kvm": kvm_capabilities(cpu),
        "memory_gib": memory_gib(),
        "iommu_group_count": len(list(Path("/sys/kernel/iommu_groups").glob("*"))),
        "kvm_device": Path("/dev/kvm").exists(),
        "pci": [asdict(d) for d in devices],
        "usb": [] if provided_devices else [asdict(d) for d in usb_devices()],
        "free_gib": shutil.disk_usage(Path.cwd()).free // 1024**3,
    }


def print_preflight() -> dict:
    info = host_fingerprint()
    cpu = info["cpu"]
    print(f"OS: {info['os']} ({info['arch']})")
    print(f"Kernel: {info['kernel']}")
    print(f"CPU: {cpu['model']} / {cpu['vendor']} / {cpu['logical_cpus']} threads")
    print(f"Virtualization flag: {cpu['virtualization'] or 'MISSING'}")
    print(f"IOMMU groups: {info['iommu_group_count']}")
    print(f"/dev/kvm: {'available' if info['kvm_device'] else 'not available yet'}")
    print(f"Memory: {info['memory_gib']} GiB; free disk: {info['free_gib']} GiB")
    for number, group in enumerate(gpu_groups([PciDevice(**d) for d in info["pci"]]), 1):
        print(f"GPU {number}:")
        for device in group:
            print(f"  {device.address} [{device.vendor_id}:{device.device_id}] group={device.iommu_group} driver={device.driver or '-'} {device.description}")
    return info


def device_identity(devices: list[PciDevice], cpu_vendor: str) -> dict[str, str]:
    vendor = "1022" if cpu_vendor == "amd" else "8086"
    relevant = [d for d in devices if d.vendor_id == vendor]

    # Return the first matching real PCI device.  If the host does not expose
    # a device of that class, fall back to the legacy/default device ID instead
    # of returning None (which later crashes build.py on value.upper()).
    def first(
        classes: set[str], default: str, *, avoid_device_ids: set[str] | None = None,
    ) -> PciDevice | str:
        avoid = avoid_device_ids or set()
        return next(
            (
                d for d in relevant
                if d.class_code in classes and d.device_id not in avoid
            ),
            default,
        )

    # Every fallback is a real, publicly assigned chipset device ID.  Do not
    # use QEMU/Red Hat/Bochs IDs or generated numbers here: these values become
    # PCI identities in the patched firmware when a class is absent from
    # lspci (common for storage and integrated audio on some AMD systems).
    defaults = {
        "amd": {
            "lpc": "790e",
            "smbus": "790b",
            "audio": "1637",
            "storage": "7901",
            "rootport": "1448",
            "xhci": "7914",
            "hostbridge": "1630",
            "pcibridge": "1633",
        },
        "intel": {
            "lpc": "068d",
            "smbus": "a3a3",
            "audio": "a3f0",
            "storage": "06d2",
            "rootport": "06ba",
            "xhci": "06ed",
            "hostbridge": "9b54",
            "pcibridge": "1901",
        },
    }["amd" if cpu_vendor == "amd" else "intel"]

    rootport = first({"0604"}, defaults["rootport"])
    bridge_ids = {rootport.device_id} if isinstance(rootport, PciDevice) else set()
    mapping = {
        "lpc": first({"0601"}, defaults["lpc"]),
        "smbus": first({"0c05"}, defaults["smbus"]),
        "audio": first({"0401", "0403"}, defaults["audio"]),
        "storage": first({"0106", "0108"}, defaults["storage"]),
        "rootport": rootport,
        "xhci": first({"0c03"}, defaults["xhci"]),
        "hostbridge": first({"0600"}, defaults["hostbridge"]),
        # QEMU exposes both a root port and a downstream PCI bridge.  Do not
        # assign one host bridge identity to both roles when the inventory has
        # more than one candidate; duplicate IDs are needlessly conspicuous.
        "pcibridge": first(
            {"0604"}, defaults["pcibridge"], avoid_device_ids=bridge_ids,
        ),
    }

    output = {
        key: (device.device_id if isinstance(device, PciDevice) else device)
        for key, device in mapping.items()
    }
    audio = mapping["audio"]
    output["audio_name"] = (
        audio.description if isinstance(audio, PciDevice) else "HD Audio Controller"
    )
    return output
