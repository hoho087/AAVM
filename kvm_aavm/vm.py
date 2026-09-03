from __future__ import annotations

import errno
import json
import os
import re
import shutil
import stat
import struct
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from .build import build_all
from .hardware import host_fingerprint, vm_cpu_layout
from .identity import apply_board_identity, generate, rerandomize
from .offline import configure_amd_ftpm_swtpm
from .paths import BACKUP_DIR, PENDING_DIR, STATE_DIR, VM_DIR, VM_IMAGE_DIR, ensure_state_dirs, vm_dir
from .state import clear_pending, load_profile, mark_pending, save_profile, vm_lock
from .util import AppError, Runner, atomic_write, command_exists, prompt_yes_no, require_root, sha256, valid_vm_name
from .xmlgen import (
    AAVM_NS, HUGEPAGE_2M_KIB, QEMU_NS, INSTALL_OVMF_CODE, INSTALL_OVMF_VARS,
    amd_avic_available, amd_nested_hyperv_acceleration_available,
    apply_hyperv_enlightenments,
    build_domain_xml, update_artifact_paths, update_identity, update_passthrough,
    validate_required, _ensure_pci_hostdev_vfio,
)


# Guest Secure Boot policy mirrors the host's current active databases and
# preserves the motherboard's factory defaults separately. This keeps the
# guest's trust and revocation state aligned with the host after UEFI updates.
SECURE_BOOT_ACTIVE_NAMES = ("PK", "KEK", "db", "dbx")
SECURE_BOOT_FACTORY_NAMES = ("PKDefault", "KEKDefault", "dbDefault", "dbxDefault")
SECURE_BOOT_VARIABLE_NAMES = set(SECURE_BOOT_ACTIVE_NAMES) | set(SECURE_BOOT_FACTORY_NAMES) | {
    "VendorKeysNv", "CustomMode",
}
SECURE_BOOT_REQUIRED_NAMES = set(SECURE_BOOT_ACTIVE_NAMES) | set(SECURE_BOOT_FACTORY_NAMES)
EFI_GLOBAL_VARIABLE_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
EFI_IMAGE_SECURITY_DATABASE_GUID = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
EFI_VARIABLE_GUIDS = {
    "PK": EFI_GLOBAL_VARIABLE_GUID,
    "KEK": EFI_GLOBAL_VARIABLE_GUID,
    "db": EFI_IMAGE_SECURITY_DATABASE_GUID,
    "dbx": EFI_IMAGE_SECURITY_DATABASE_GUID,
    "PKDefault": EFI_GLOBAL_VARIABLE_GUID,
    "KEKDefault": EFI_GLOBAL_VARIABLE_GUID,
    "dbDefault": EFI_GLOBAL_VARIABLE_GUID,
    "dbxDefault": EFI_GLOBAL_VARIABLE_GUID,
}
EFI_VARIABLES_DIR = Path("/sys/firmware/efi/efivars")
HOST_SECURE_BOOT_SNAPSHOT = STATE_DIR / "secure-boot" / "host-active-microsoft.json"
AMD_FTPM_LIBTPMS_VERSION_MARKER = "+kvm-aavm1"
UBUNTU_SECURE_OVMF_VARS = Path("/usr/share/OVMF/OVMF_VARS_4M.ms.fd")
HUGEPAGES_2M_SYSFS = Path("/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages")
HUGEPAGES_SYSCTL = Path("/etc/sysctl.d/99-kvm-aavm-hugepages.conf")
DMI_IDENTITY_DIR = Path("/sys/class/dmi/id")
LIBVIRT_SWTPM_DIR = Path("/var/lib/libvirt/swtpm")


def new_profile(
    name: str, disk_gib: int, memory_gib: int, vcpus: int, windows_iso: str,
    owner_uid: int, passthrough_pci: list[str] | None = None,
) -> dict:
    name = valid_vm_name(name)
    host = host_fingerprint()
    identity = generate(host["cpu"])
    root = vm_dir(name)
    current = root / "artifacts" / "current"
    cpu_layout = vm_cpu_layout(host["cpu"], vcpus)
    return {
        "schema": 1, "name": name, "created_at": int(time.time()), "owner_uid": owner_uid,
        "host": host, "identity": identity,
        "resources": {
            "disk_gib": disk_gib, "memory_gib": memory_gib, "vcpus": vcpus,
            "hugepages_2m": False,
            "threads_per_core": cpu_layout["threads_per_core"],
            "cpuid_policy": "intercepted",
            "cpu_pinning": {
                "vcpus": cpu_layout["vcpu_pins"],
                "emulator": cpu_layout["emulator_cpus"],
            },
        },
        "paths": {
            "disk": str(VM_IMAGE_DIR / f"{name}.qcow2"), "windows_iso": str(Path(windows_iso).resolve()),
            "qemu": str(current / "bin/qemu-system-x86_64"),
            "ovmf_code": str(current / "ovmf/OVMF_CODE_4M.patched.qcow2"),
            "ovmf_vars": str(current / "ovmf/OVMF_VARS_4M.patched.qcow2"),
            "ssdt": [str(current / "bin/ssdt1.aml"), str(current / "bin/ssdt2.aml")],
        },
        "passthrough": {
            "mode": "manual", "pci": passthrough_pci or [], "gpu_pci": [],
            "gpu_guest_pci": [],
            "gpu_rom_bar": False,
            "gpu_reset_method": "default",
            "extra_pci": passthrough_pci or [], "usb": [], "network_pci": None,
            "disable_virtual_network": False,
            "virtual_network_choice_set": False,
        },
        "dynamic_randomization": False,
        "guest_vtd": False,
        # DMA translation remains available without QEMU's problematic
        # interrupt-remapping path.
        "guest_vtd_intremap": False,
        "guest_secure_boot": False,
        "guest_dma_protection": False,
        "guest_core_isolation": False,
        "guest_hyperv_enlightenments": False,
        "tpm": {"mode": "none"},
        "stage": "install",
        "minimal_devices": False,
    }


def _refresh_profile_host_capabilities(profile: dict) -> None:
    """Keep regenerated CPU XML tied to the KVM capabilities of this boot."""
    current = host_fingerprint()
    host = profile.setdefault("host", {})
    host["cpu"] = current["cpu"]
    host["kvm"] = current.get("kvm", {})


def _host_board_identity() -> dict:
    """Read the motherboard fields that must agree with factory Secure Boot PK."""
    fields = {
        "manufacturer": "board_vendor",
        "product": "board_name",
        "version": "board_version",
    }
    board: dict[str, str] = {}
    for target, filename in fields.items():
        try:
            value = (DMI_IDENTITY_DIR / filename).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise AppError(f"Unable to read host DMI {filename}.") from exc
        if not value or "\x00" in value or "\n" in value or "\r" in value:
            raise AppError(f"Host DMI {filename} is empty or invalid.")
        board[target] = value
    if "," in board["version"]:
        raise AppError("Host DMI board version cannot contain a comma.")
    return board


def _host_firmware_identity() -> dict:
    """Read BIOS fields that must agree with the board's factory key source."""
    fields = {
        "vendor": "bios_vendor",
        "version": "bios_version",
        "date": "bios_date",
    }
    firmware: dict[str, str] = {}
    for target, filename in fields.items():
        try:
            value = (DMI_IDENTITY_DIR / filename).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise AppError(f"Unable to read host DMI {filename}.") from exc
        if not value or "\x00" in value or "\n" in value or "\r" in value:
            raise AppError(f"Host DMI {filename} is empty or invalid.")
        firmware[target] = value
    return firmware


def _pin_host_board_identity(profile: dict) -> dict:
    """Bind SMBIOS OEM fields to the motherboard that supplied factory keys."""
    board = _host_board_identity()
    firmware = _host_firmware_identity()
    updated = dict(profile)
    updated["identity_board"] = board
    updated["identity_firmware"] = firmware
    updated["identity"] = apply_board_identity(profile["identity"], board)
    return updated


def _hugepages_2m_for_profile(profile: dict) -> int:
    resources = profile.get("resources", {})
    if not resources.get("hugepages_2m", False):
        return 0
    memory_gib = int(resources.get("memory_gib", 0))
    if memory_gib <= 0:
        raise AppError("Hugepages requires a positive VM memory size.")
    # 1 GiB contains 512 2 MiB hugepages.
    return memory_gib * (1024 * 1024 // HUGEPAGE_2M_KIB)


def _managed_hugepage_target_pages(name: str, proposed_profile: dict) -> int:
    """Return the reservation needed if all managed hugepage VMs run together."""
    total = 0
    found_current = False
    for path in VM_DIR.glob("*/profile.json"):
        vm_name = path.parent.name
        if vm_name == name:
            total += _hugepages_2m_for_profile(proposed_profile)
            found_current = True
            continue
        try:
            candidate = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            # An unrelated incomplete profile must not prevent a managed VM
            # from being updated. Its stale setting cannot be trusted either.
            continue
        total += _hugepages_2m_for_profile(candidate)
    if not found_current:
        total += _hugepages_2m_for_profile(proposed_profile)
    return total


def _read_hugepage_count() -> int:
    try:
        return int(HUGEPAGES_2M_SYSFS.read_text(encoding="utf-8").strip())
    except (OSError, ValueError) as exc:
        raise AppError(
            "The host does not expose 2 MiB hugetlbfs pages at "
            f"{HUGEPAGES_2M_SYSFS}."
        ) from exc


def _persist_hugepage_target(target_pages: int) -> None:
    if target_pages:
        atomic_write(
            HUGEPAGES_SYSCTL,
            "# Managed by KVM-AntiAntiVM. Do not edit while hugepage VMs are enabled.\n"
            f"vm.nr_hugepages={target_pages}\n",
        )
    else:
        HUGEPAGES_SYSCTL.unlink(missing_ok=True)


def _restore_hugepage_sysctl(previous: str | None) -> None:
    if previous is None:
        HUGEPAGES_SYSCTL.unlink(missing_ok=True)
    else:
        atomic_write(HUGEPAGES_SYSCTL, previous)


def _ensure_disk(disk: Path, required_gib: int, runner: Runner) -> None:
    disk.parent.mkdir(parents=True, exist_ok=True)
    if not disk.exists():
        runner.run(["qemu-img", "create", "-f", "qcow2", str(disk), f"{required_gib}G"])
        return
    if runner.dry_run:
        print(f"Existing disk would be reused: {disk}")
        return
    result = runner.run(["qemu-img", "info", "--output=json", str(disk)], capture=True)
    try:
        info = json.loads(result.stdout)
        disk_format = info["format"]
        virtual_size = int(info["virtual-size"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise AppError(f"Could not inspect existing VM disk {disk}: {exc}") from exc
    expected_size = required_gib * 1024**3
    if disk_format != "qcow2" or virtual_size != expected_size:
        raise AppError(
            f"Refusing to overwrite existing disk {disk}: expected qcow2/{required_gib} GiB, "
            f"found {disk_format}/{virtual_size / 1024**3:.2f} GiB."
        )
    print(f"Reusing existing qcow2 disk: {disk} ({required_gib} GiB virtual size)")


def _stage_install_media(name: str, source: Path) -> Path:
    """Place install media below the root-owned VM state tree.

    libvirt adds normal disk sources to its per-domain AppArmor allow-list, but
    QEMU still cannot traverse a user's 0750 home directory. Prefer a hard link
    so a multi-gigabyte ISO consumes no additional blocks; copy atomically only
    when the filesystems differ or the source is not world-readable.
    """
    if not source.is_file():
        raise AppError(f"Windows ISO not found: {source}")
    media_dir = vm_dir(name) / "media"
    media_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
    media_dir.chmod(0o755)
    destination = media_dir / "windows-install.iso"
    if destination.exists():
        if os.path.samefile(source, destination):
            print(f"Reusing staged Windows ISO: {destination}")
            return destination
        if source.stat().st_size == destination.stat().st_size and sha256(source) == sha256(destination):
            print(f"Reusing staged Windows ISO: {destination}")
            return destination
        raise AppError(
            f"Managed Windows ISO already exists with different content: {destination}"
        )

    source_mode = source.stat().st_mode
    if source_mode & stat.S_IROTH:
        try:
            os.link(source, destination)
            print(f"Staged Windows ISO using a hard link: {destination}")
            return destination
        except OSError as exc:
            if exc.errno not in {errno.EXDEV, errno.EPERM, errno.EACCES}:
                raise

    required = source.stat().st_size
    if shutil.disk_usage(media_dir).free < required:
        raise AppError(
            f"Insufficient space to stage Windows ISO: need {required / 1024**3:.2f} GiB"
        )
    print(f"Copying Windows ISO into managed storage: {destination}")
    fd, temporary = tempfile.mkstemp(prefix=".windows-install.", suffix=".iso", dir=media_dir)
    os.close(fd)
    try:
        shutil.copyfile(source, temporary)
        os.chmod(temporary, 0o644)
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return destination


def _ensure_install_ovmf_code(name: str, profile: dict, runner: Runner) -> Path:
    """Create a matched, persistent Ubuntu OVMF CODE/VARS qcow2 pair.

    The generated OVMF VARS from the patch build is not paired with Ubuntu's
    system CODE and can retain a stale BootOrder. A fresh system template lets
    the install DVD boot normally. This writable per-VM VARS is then retained
    with patched CODE so Windows Boot Manager and user firmware settings are
    not discarded by later identity/artifact rotations.
    """
    code_source = Path(INSTALL_OVMF_CODE)
    vars_source = Path(INSTALL_OVMF_VARS)
    missing = [str(path) for path in (code_source, vars_source) if not path.is_file()]
    if missing:
        raise AppError("Ubuntu OVMF firmware is missing:\n- " + "\n- ".join(missing))
    firmware_dir = vm_dir(name) / "firmware"
    firmware_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
    firmware_dir.chmod(0o755)
    code_destination = firmware_dir / "OVMF_CODE_4M.ubuntu-install.qcow2"
    vars_destination = firmware_dir / "OVMF_VARS_4M.ubuntu-install.qcow2"
    profile["paths"].update({
        "install_ovmf_code": str(code_destination),
        "install_ovmf_vars": str(vars_destination),
    })

    for source, destination in (
        (code_source, code_destination),
        (vars_source, vars_destination),
    ):
        if destination.is_file():
            continue
        if runner.dry_run:
            runner.run([
                "qemu-img", "convert", "-f", "raw", "-O", "qcow2",
                str(source), str(destination),
            ])
            continue
        temporary = destination.with_name(f".{destination.name}.new")
        if temporary.exists():
            temporary.unlink()
        try:
            runner.run([
                "qemu-img", "convert", "-f", "raw", "-O", "qcow2",
                str(source), str(temporary),
            ])
            temporary.chmod(0o644)
            os.replace(temporary, destination)
        finally:
            if temporary.exists():
                temporary.unlink()
    return code_destination


def _filtered_secure_boot_variables(value: dict) -> dict | None:
    """Keep only key-policy variables; never import guest boot entries."""
    variables = [
        item for item in value.get("variables", [])
        if item.get("name") in SECURE_BOOT_VARIABLE_NAMES
    ]
    names = {item.get("name") for item in variables}
    if not set(SECURE_BOOT_ACTIVE_NAMES).issubset(names):
        return None
    return {"version": int(value.get("version", 2)), "variables": variables}


def _secure_boot_variable_index(value: dict) -> dict[str, dict]:
    return {
        str(item["name"]): item
        for item in value.get("variables", [])
        if isinstance(item, dict) and item.get("name")
    }


def _read_host_secure_boot_variable(name: str) -> dict:
    """Read one raw UEFI variable without trusting its current active policy."""
    guid = EFI_VARIABLE_GUIDS[name]
    path = EFI_VARIABLES_DIR / f"{name}-{guid}"
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise AppError(f"Cannot read host UEFI variable {name}: {path}: {exc}") from exc
    if len(raw) < 4:
        raise AppError(f"Host UEFI variable {name} is missing UEFI attributes: {path}")
    return {
        "name": name,
        "guid": guid,
        "attr": int.from_bytes(raw[:4], byteorder="little"),
        "data": raw[4:].hex(),
    }


def _host_secure_boot_variables() -> dict[str, dict]:
    """Capture active and factory host key databases in one auditable snapshot."""
    if not EFI_VARIABLES_DIR.is_dir():
        raise AppError(
            "Host UEFI variables are unavailable. Boot the host in UEFI mode before "
            "enabling motherboard-backed Guest Secure Boot."
        )
    values = {
        name: _read_host_secure_boot_variable(name)
        for name in (*SECURE_BOOT_ACTIVE_NAMES, *SECURE_BOOT_FACTORY_NAMES)
    }
    for name in ("PK", "KEK", "PKDefault", "KEKDefault"):
        if not values[name]["data"]:
            raise AppError(f"Host UEFI variable {name} has no key data.")
    snapshot = {
        "format": 2,
        "policy": "host-active-with-factory-defaults",
        "captured_at": int(time.time()),
        "source": str(EFI_VARIABLES_DIR),
        "variables": [
            values[name]
            for name in (*SECURE_BOOT_ACTIVE_NAMES, *SECURE_BOOT_FACTORY_NAMES)
        ],
    }
    atomic_write(
        HOST_SECURE_BOOT_SNAPSHOT,
        json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n",
        mode=0o600,
    )
    return values


def export_host_secure_boot(destination: Path) -> Path:
    """Export the active and factory Secure Boot databases used for guests."""
    require_root()
    values = _host_secure_boot_variables()
    exported = {
        "format": 2,
        "policy": "host-active-with-factory-defaults",
        "captured_at": int(time.time()),
        "source": str(EFI_VARIABLES_DIR),
        "variables": [
            values[name]
            for name in (*SECURE_BOOT_ACTIVE_NAMES, *SECURE_BOOT_FACTORY_NAMES)
        ],
    }
    destination = destination.expanduser().resolve()
    atomic_write(
        destination,
        json.dumps(exported, ensure_ascii=False, indent=2) + "\n",
        mode=0o600,
    )
    return destination


def _decode_efi_signature_database(data: str, name: str) -> list[tuple[bytes, bytes, int, list[bytes]]]:
    """Decode EFI_SIGNATURE_LIST records and reject malformed key databases."""
    try:
        raw = bytes.fromhex(data)
    except ValueError as exc:
        raise AppError(f"Secure Boot variable {name} is not valid hexadecimal data.") from exc
    records: list[tuple[bytes, bytes, int, list[bytes]]] = []
    offset = 0
    while offset < len(raw):
        if len(raw) - offset < 28:
            raise AppError(f"Secure Boot variable {name} has a truncated EFI signature list.")
        signature_type = raw[offset:offset + 16]
        list_size, header_size, signature_size = struct.unpack_from("<III", raw, offset + 16)
        minimum = 28 + header_size
        if list_size < minimum or offset + list_size > len(raw):
            raise AppError(f"Secure Boot variable {name} has an invalid EFI signature-list size.")
        if signature_size < 16 or (list_size - minimum) % signature_size:
            raise AppError(f"Secure Boot variable {name} has an invalid EFI signature entry size.")
        header = raw[offset + 28:offset + 28 + header_size]
        entries_start = offset + minimum
        entries_end = offset + list_size
        entries = [
            raw[position:position + signature_size]
            for position in range(entries_start, entries_end, signature_size)
        ]
        records.append((signature_type, header, signature_size, entries))
        offset += list_size
    return records


def _with_template_attributes(template: dict, name: str, data: str) -> dict:
    value = dict(template)
    value["name"] = name
    value["guid"] = EFI_VARIABLE_GUIDS.get(name, str(value.get("guid", EFI_GLOBAL_VARIABLE_GUID)))
    value["data"] = data.lower()
    return value


def _database_has_microsoft(data: str, name: str) -> bool:
    """Require Microsoft trust material in an EFI signature database."""
    for _, _, _, entries in _decode_efi_signature_database(data, name):
        if any(b"Microsoft Corporation" in entry[16:] for entry in entries):
            return True
    return False


def _host_secure_boot_policy(template: dict[str, dict], host: dict[str, dict]) -> list[dict]:
    """Build a guest policy that mirrors active host keys and factory defaults."""
    required_template = set(SECURE_BOOT_ACTIVE_NAMES) | {"VendorKeysNv", "CustomMode"}
    missing_template = sorted(required_template - set(template))
    if missing_template:
        raise AppError("Ubuntu Secure Boot variable template is missing: " + ", ".join(missing_template))
    missing_host = sorted(SECURE_BOOT_REQUIRED_NAMES - set(host))
    if missing_host:
        raise AppError("Host Secure Boot key set is missing: " + ", ".join(missing_host))
    for name in ("KEK", "db"):
        if not _database_has_microsoft(host[name]["data"], name):
            raise AppError(
                f"Host active {name} does not contain a Microsoft certificate; "
                "refusing to import an OVMF-owned replacement key."
            )

    variables = [
        _with_template_attributes(template[name], name, host[name]["data"])
        for name in SECURE_BOOT_ACTIVE_NAMES
    ]
    # Keep factory-reset databases alongside the active host policy. OVMF
    # derives its runtime VendorKeys state from VendorKeysNv.
    variables.extend(host[name] for name in SECURE_BOOT_FACTORY_NAMES)
    variables.append(_with_template_attributes(template["VendorKeysNv"], "VendorKeysNv", "01"))
    variables.append(_with_template_attributes(template["CustomMode"], "CustomMode", "00"))
    return variables


def _secure_boot_defaults(runner: Runner, folder: Path) -> Path:
    """Mirror active host databases while preserving factory-reset defaults."""
    if not UBUNTU_SECURE_OVMF_VARS.is_file():
        raise AppError(
            "Secure Boot key template is missing; install the Ubuntu ovmf package "
            f"or restore {UBUNTU_SECURE_OVMF_VARS}."
        )
    exported = folder / "ubuntu-secure-vars.json"
    runner.run([
        "virt-fw-vars", "--input", str(UBUNTU_SECURE_OVMF_VARS),
        "--output-json", str(exported),
    ])
    try:
        filtered = _filtered_secure_boot_variables(json.loads(exported.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError) as exc:
        raise AppError(f"Could not read Ubuntu Secure Boot key template: {exc}") from exc
    if filtered is None:
        raise AppError("Ubuntu Secure Boot template does not contain PK, KEK and db variables.")

    template = _secure_boot_variable_index(filtered)
    host = _host_secure_boot_variables()
    variables = _host_secure_boot_policy(template, host)

    destination = folder / "secure-vars.json"
    atomic_write(
        destination,
        json.dumps({"version": int(filtered.get("version", 2)), "variables": variables}, ensure_ascii=False, indent=2) + "\n",
        mode=0o600,
    )
    return destination


def _secure_boot_policy_errors(
    variables: dict[str, dict], enabled: bool, reference: dict[str, dict] | None = None,
) -> list[str]:
    """Return policy consistency errors without interpreting guest boot data."""
    state = variables.get("SecureBootEnable", {}).get("data", "").lower()
    if not enabled:
        return [] if state in {"", "00"} else ["SecureBootEnable is still true"]

    errors: list[str] = []
    missing = sorted(SECURE_BOOT_REQUIRED_NAMES - set(variables))
    if missing:
        errors.append(f"missing {', '.join(missing)}")
    if state != "01":
        errors.append("SecureBootEnable is not true")
    if variables.get("CustomMode", {}).get("data", "").lower() != "00":
        errors.append("CustomMode is not disabled")
    if variables.get("VendorKeysNv", {}).get("data", "").lower() != "01":
        errors.append("VendorKeysNv does not identify vendor-managed keys")
    if reference is not None:
        for name in SECURE_BOOT_VARIABLE_NAMES:
            expected = reference.get(name, {}).get("data")
            actual = variables.get(name, {}).get("data")
            if expected is not None and str(actual).lower() != str(expected).lower():
                errors.append(f"{name} does not match the normalized OEM/Microsoft key policy")
    return errors


def _secure_boot_varstore_path(profile: dict) -> Path:
    value = profile.get("paths", {}).get("install_ovmf_vars")
    if not value:
        raise AppError("This VM has no managed persistent OVMF VARS file.")
    path = Path(value)
    if not path.is_file():
        raise AppError(f"Managed OVMF VARS file is missing: {path}")
    return path


def _set_guest_secure_boot_varstore(
    name: str, profile: dict, enabled: bool, runner: Runner,
) -> Path | None:
    if not command_exists("virt-fw-vars"):
        raise AppError("virt-fw-vars is required; install the python3-virt-firmware package.")
    varstore = _secure_boot_varstore_path(profile)
    if runner.dry_run:
        action = "mirror active host Secure Boot keys and remove guest custom keys" if enabled else "disable"
        print(f"Would atomically {action}: {varstore}")
        return None

    backup_dir = BACKUP_DIR / name
    backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    backup = backup_dir / f"ovmf-vars-{time.time_ns()}.qcow2"
    shutil.copy2(varstore, backup)

    with tempfile.TemporaryDirectory(prefix=".secure-boot-", dir=varstore.parent) as temporary:
        folder = Path(temporary)
        output = folder / varstore.name
        command = ["virt-fw-vars", "--input", str(varstore), "--output", str(output)]
        reference: dict[str, dict] | None = None
        if enabled:
            defaults = _secure_boot_defaults(runner, folder)
            reference = _secure_boot_variable_index(
                json.loads(defaults.read_text(encoding="utf-8"))
            )
            # set-json replaces PK/KEK/db/dbx with the exact normalized policy;
            # any custom signatures that existed in those databases are removed.
            command.extend(["--set-json", str(defaults), "--set-false", "CustomMode", "--secure-boot"])
        else:
            command.extend(["--set-false", "SecureBootEnable"])
        runner.run(command)

        exported = folder / "verify.json"
        runner.run(["virt-fw-vars", "--input", str(output), "--output-json", str(exported)])
        value = json.loads(exported.read_text(encoding="utf-8"))
        variables = {item.get("name"): item for item in value.get("variables", [])}
        errors = _secure_boot_policy_errors(variables, enabled, reference)
        if errors:
            raise AppError("Refusing invalid Secure Boot VARS output: " + "; ".join(errors) + ".")
        output.chmod(varstore.stat().st_mode & 0o777)
        os.replace(output, varstore)
    return backup


def _pci_source_address(source: ET.Element | None) -> str | None:
    address = source.find("address") if source is not None else None
    if address is None:
        return None
    try:
        domain = int(address.get("domain", "0"), 0)
        bus = int(address.get("bus", "0"), 0)
        slot = int(address.get("slot", "0"), 0)
        function = int(address.get("function", "0"), 0)
    except ValueError:
        return None
    if domain != 0:
        return f"{domain:04x}:{bus:02x}:{slot:02x}.{function:x}"
    return f"{bus:02x}:{slot:02x}.{function:x}"


def _remember_existing_hostdevs(profile: dict, xml_text: str) -> None:
    """Import XML-only hostdevs before any future profile-based regeneration."""
    root = ET.fromstring(xml_text)
    passthrough = profile.setdefault("passthrough", {})
    pci = list(passthrough.get("pci", []))
    gpu = set(passthrough.get("gpu_pci", []))
    extra = list(passthrough.get("extra_pci", []))
    for hostdev in root.findall("./devices/hostdev[@type='pci']"):
        address = _pci_source_address(hostdev.find("source"))
        if address and address not in pci:
            pci.append(address)
        if address and address not in gpu and address not in extra:
            extra.append(address)
    passthrough["pci"] = pci
    passthrough["extra_pci"] = extra


def tpm_config_from_xml(xml_text: str) -> dict | None:
    """Return a supported existing TPM configuration without changing state."""
    root = ET.fromstring(xml_text)
    tpm = root.find("./devices/tpm")
    backend = tpm.find("backend") if tpm is not None else None
    if tpm is None or backend is None:
        return None
    backend_type = backend.get("type")
    model = tpm.get("model", "tpm-crb")
    version = backend.get("version", "2.0")
    if backend_type == "emulator" and model in {"tpm-tis", "tpm-crb"}:
        result = {"mode": "emulator", "model": model, "version": version}
        stage = root.find(f"./metadata/{{{AAVM_NS}}}stage")
        tpm_profile = stage.get("tpm-profile", "generic") if stage is not None else "generic"
        if tpm_profile == "amd-ftpm":
            if model != "tpm-crb":
                return None
            result["profile"] = tpm_profile
        return result
    return None


def _remember_existing_tpm(profile: dict, xml_text: str) -> None:
    """Preserve a manually-added supported TPM across profile XML rebuilds."""
    config = tpm_config_from_xml(xml_text)
    if config is not None:
        profile["tpm"] = config


def _ensure_profile_tpm_xml(xml_text: str, profile: dict) -> str:
    """Restore the managed TPM node if libvirt omitted it from dumped XML."""
    value = profile.get("tpm", {})
    mode = value.get("mode", "none") if isinstance(value, dict) else "none"
    if mode != "emulator":
        return xml_text
    tpm_profile = str(value.get("profile", "generic"))
    if tpm_profile not in {"generic", "amd-ftpm"}:
        raise AppError(f"Unsupported TPM profile: {tpm_profile}")
    root = ET.fromstring(xml_text)
    stage = root.find(f"./metadata/{{{AAVM_NS}}}stage")
    if stage is not None:
        stage.set("tpm-mode", mode)
        stage.set("tpm-profile", tpm_profile)
    devices = root.find("devices")
    if devices is None:
        raise AppError("Managed VM XML has no devices element for TPM restoration.")
    model = str(value.get("model", "tpm-crb"))
    if tpm_profile == "amd-ftpm" and model != "tpm-crb":
        raise AppError("The AMD fTPM profile requires the tpm-crb interface.")
    tpm = devices.find("tpm")
    if tpm is None:
        tpm = ET.Element("tpm", {"model": model})
        index = 1 if devices.find("emulator") is not None else 0
        devices.insert(index, tpm)
    else:
        tpm.set("model", model)
        for child in list(tpm):
            if child.tag == "backend":
                tpm.remove(child)
    ET.SubElement(tpm, "backend", {
        "type": "emulator", "version": "2.0", "persistent_state": "yes",
    })
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode", xml_declaration=True) + "\n"


def _require_amd_ftpm_libtpms(profile: dict, runner: Runner) -> None:
    """Reject an AMD profile unless the managed libtpms package is installed."""
    if profile.get("host", {}).get("cpu", {}).get("vendor") != "amd":
        raise AppError("The AMD fTPM profile requires an AMD host CPU profile.")
    result = runner.run(
        ["dpkg-query", "--show", "--showformat=${Version}", "libtpms0"],
        check=False, capture=True,
    )
    version = result.stdout.strip()
    if result.returncode != 0 or AMD_FTPM_LIBTPMS_VERSION_MARKER not in version:
        raise AppError(
            "AMD fTPM profile requires the KVM-AntiAntiVM patched libtpms0 package. "
            "Run tools/prepare_offline.sh again, then install the refreshed offline bundle."
        )
    # libvirt reads these files only when it manufactures/reconfigures swtpm
    # state. Keep the host policy in place before a new AMD-profile TPM starts.
    configure_amd_ftpm_swtpm()


def _update_guest_security_xml(xml_text: str, profile: dict) -> str:
    """Change only guest-security nodes; preserve every existing device."""
    root = ET.fromstring(xml_text)
    # Legacy definitions may contain PCI hostdevs without an explicit VFIO
    # backend.  Security-only updates must repair those definitions as well,
    # otherwise libvirt 10/QEMU 11 rejects the unchanged hostdev at start.
    _ensure_pci_hostdev_vfio(root)
    stage = root.find(f"./metadata/{{{AAVM_NS}}}stage")
    if stage is None:
        raise AppError("Managed VM XML is missing kvm-aavm stage metadata.")
    secure_boot = bool(profile.get("guest_secure_boot", False))
    dma_protection = bool(profile.get("guest_dma_protection", False))
    core_isolation = bool(profile.get("guest_core_isolation", False))
    hyperv_enlightenments = bool(
        core_isolation
        and profile.get("guest_hyperv_enlightenments", core_isolation)
    )
    amd_hyperv_acceleration = bool(
        hyperv_enlightenments
        and amd_nested_hyperv_acceleration_available(profile)
    )
    amd_hyperv_avic = bool(
        hyperv_enlightenments and amd_avic_available(profile)
    )
    if core_isolation and not secure_boot:
        raise AppError("Core Isolation/VBS requires Guest UEFI Secure Boot.")
    stage.set("guest-secure-boot", "true" if secure_boot else "false")
    stage.set("guest-dma-protection", "true" if dma_protection else "false")
    stage.set("guest-core-isolation", "true" if core_isolation else "false")
    stage.set(
        "guest-hyperv-enlightenments",
        "true" if hyperv_enlightenments else "false",
    )
    stage.set("guest-gmet", "true" if amd_hyperv_acceleration else "false")

    virtualization = profile.get("host", {}).get("cpu", {}).get("virtualization")
    if core_isolation and virtualization not in {"svm", "vmx"}:
        raise AppError("Core Isolation/VBS requires an AMD SVM or Intel VMX host capability.")
    cpu = root.find("cpu")
    if cpu is None:
        raise AppError("Managed VM XML has no CPU section.")
    for feature in list(cpu.findall("feature")):
        if feature.get("name") in {"svm", "vmx"}:
            cpu.remove(feature)
    if virtualization:
        ET.SubElement(cpu, "feature", {
            "policy": "require" if core_isolation else "disable",
            "name": virtualization,
        })

    devices = root.find("devices")
    if devices is None:
        raise AppError("Managed VM XML has no devices section.")
    if dma_protection:
        profile["guest_vtd"] = True
        stage.set("guest-vtd", "true")
        iommu = devices.find("iommu[@model='intel']")
        if iommu is None:
            iommu = ET.SubElement(devices, "iommu", {"model": "intel"})
        driver = iommu.find("driver")
        if driver is None:
            driver = ET.SubElement(iommu, "driver")
        driver.set("caching_mode", "on")
        driver.set(
            "intremap",
            "on" if profile.get("guest_vtd_intremap", False) else "off",
        )

    commandline = root.find(f"{{{QEMU_NS}}}commandline")
    if commandline is None:
        commandline = ET.SubElement(root, f"{{{QEMU_NS}}}commandline")
    children = list(commandline)
    property_value = "intel-iommu.dma-control-platform-opt-in=on"
    remove: set[ET.Element] = set()
    for index, child in enumerate(children):
        if child.get("value") == property_value:
            remove.add(child)
            if index and children[index - 1].get("value") == "-global":
                remove.add(children[index - 1])
    for child in remove:
        commandline.remove(child)
    if dma_protection:
        ET.SubElement(commandline, f"{{{QEMU_NS}}}arg", {"value": "-global"})
        ET.SubElement(commandline, f"{{{QEMU_NS}}}arg", {"value": property_value})

    apply_hyperv_enlightenments(
        root, hyperv_enlightenments, amd_hyperv_acceleration,
        amd_hyperv_avic,
    )

    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode", xml_declaration=True) + "\n"


def create_vm(profile: dict, runner: Runner, *, build: bool = True, start: bool = False) -> None:
    require_root()
    ensure_state_dirs()
    name = profile["name"]
    with vm_lock(name):
        if _domain_exists(name, runner):
            raise AppError(f"A libvirt domain named '{name}' already exists.")
        disk = Path(profile["paths"]["disk"])
        iso = Path(profile["paths"]["windows_iso"])
        required = int(profile["resources"]["disk_gib"])
        if not disk.exists():
            free = shutil.disk_usage(disk.parent if disk.parent.exists() else VM_IMAGE_DIR.parent).free // 1024**3
            if required + 8 > free:
                raise AppError(f"Insufficient free space: requested {required} GiB, available {free} GiB.")
        iso = _stage_install_media(name, iso)
        profile["paths"]["windows_iso"] = str(iso)
        save_profile(name, profile)
        if build:
            profile = build_all(name, profile, runner)
            save_profile(name, profile)
        else:
            artifact_paths = [Path(profile["paths"][key]) for key in ("qemu", "ovmf_code", "ovmf_vars")] + [Path(value) for value in profile["paths"].get("ssdt", [])]
            missing = [str(path) for path in artifact_paths if not path.is_file()]
            if missing:
                raise AppError("Per-VM QEMU/OVMF artifacts are missing:\n- " + "\n- ".join(missing))
        _ensure_install_ovmf_code(name, profile, runner)
        save_profile(name, profile)
        xml = build_domain_xml(profile, install_stage=True)
        errors = validate_required(xml)
        if errors:
            raise AppError("Generated XML failed validation:\n- " + "\n- ".join(errors))
        xml_path = vm_dir(name) / "domain.xml"
        atomic_write(xml_path, xml)
        _ensure_disk(disk, required, runner)
        runner.run(["virsh", "define", "--validate", str(xml_path)])
        if start:
            runner.run(["virsh", "start", name])


def resume_vm(name: str, runner: Runner, *, start: bool = False) -> dict:
    require_root()
    name = valid_vm_name(name)
    profile = load_profile(name)
    profile["stage"] = "install"
    if _domain_exists(name, runner):
        _ensure_inactive(name, runner)
        profile["paths"]["windows_iso"] = str(
            _stage_install_media(name, Path(profile["paths"]["windows_iso"]))
        )
        _ensure_install_ovmf_code(name, profile, runner)
        old_xml = _dump_xml(name, runner)
        _backup_xml(name, old_xml)
        _remember_existing_tpm(profile, old_xml)
        xml = build_domain_xml(profile, install_stage=True)
        _replace_definition(name, xml, runner)
        save_profile(name, profile)
        if start:
            runner.run(["virsh", "start", name])
        return profile
    save_profile(name, profile)
    create_vm(profile, runner, build=False, start=start)
    return profile


def configure_cpu_layout(name: str, vcpus: int, runner: Runner) -> dict:
    """Update the persistent topology/pinning without interrupting a live VM."""
    require_root()
    name = valid_vm_name(name)
    with vm_lock(name):
        profile = load_profile(name)
        if profile.get("adopted"):
            raise AppError("Automatic CPU topology is available only for deployer-owned VMs.")
        current_host = host_fingerprint()
        resources = profile.setdefault("resources", {})
        layout = vm_cpu_layout(current_host["cpu"], vcpus)
        if not layout["vcpu_pins"] or not layout["emulator_cpus"]:
            raise AppError(
                "The requested vCPU count leaves no complete physical core for Ubuntu; "
                "choose fewer vCPUs or configure CPU pinning manually."
            )
        old_xml = _dump_xml(name, runner)
        _backup_xml(name, old_xml)
        _remember_existing_tpm(profile, old_xml)
        profile.setdefault("host", {})["cpu"] = current_host["cpu"]
        profile["host"]["kvm"] = current_host.get("kvm", {})
        resources["vcpus"] = int(layout["vcpus"])
        resources["threads_per_core"] = int(layout["threads_per_core"])
        resources["cpu_pinning"] = {
            "vcpus": layout["vcpu_pins"],
            "emulator": layout["emulator_cpus"],
        }
        xml = build_domain_xml(profile, stage=profile.get("stage", "install"))
        _replace_definition(name, xml, runner)
        save_profile(name, profile)
        atomic_write(vm_dir(name) / "domain.xml", xml)
        print(
            f"{name}: persistent CPU topology set to "
            f"{layout['cores']} cores x {layout['threads_per_core']} threads; "
            f"{len(layout['emulator_cpus'])} host logical CPUs reserved."
        )
        return profile


def configure_hugepages(name: str, enabled: bool, runner: Runner) -> dict:
    """Configure deployer-managed 2 MiB hugepages for one stopped VM.

    The host reservation covers every managed VM that has opted in, allowing
    those guests to be started concurrently.  Both the reservation and domain
    XML are updated transactionally so a failed domain definition does not
    leave a VM claiming pages it cannot use.
    """
    require_root()
    name = valid_vm_name(name)
    with vm_lock(name):
        profile = load_profile(name)
        if profile.get("adopted"):
            raise AppError("Hugepage management is available only for deployer-owned VMs.")
        _ensure_inactive(name, runner)
        old_xml = _dump_xml(name, runner)
        _backup_xml(name, old_xml)
        _remember_existing_tpm(profile, old_xml)

        resources = profile.setdefault("resources", {})
        had_setting = "hugepages_2m" in resources
        old_setting = resources.get("hugepages_2m", False)
        resources["hugepages_2m"] = bool(enabled)
        xml = build_domain_xml(profile, stage=profile.get("stage", "install"))
        target_pages = _managed_hugepage_target_pages(name, profile)

        # ``Runner`` dry-runs commands, therefore /sys cannot show the target
        # after the simulated sysctl call. Keep the preview usable without
        # writing either the real reservation or its persistent configuration.
        if runner.dry_run:
            runner.run(["sysctl", "-w", f"vm.nr_hugepages={target_pages}"])
            print(
                f"{name}: would {'enable' if enabled else 'disable'} 2 MiB hugepages "
                f"({target_pages} pages reserved across managed VMs)."
            )
            return profile

        previous_pages = _read_hugepage_count()
        previous_sysctl = (
            HUGEPAGES_SYSCTL.read_text(encoding="utf-8")
            if HUGEPAGES_SYSCTL.exists() else None
        )
        reservation_changed = False
        sysctl_written = False
        try:
            if target_pages != previous_pages:
                runner.run(["sysctl", "-w", f"vm.nr_hugepages={target_pages}"])
                reservation_changed = True
                actual_pages = _read_hugepage_count()
                if actual_pages != target_pages:
                    raise AppError(
                        "Could not reserve the requested 2 MiB hugepages: "
                        f"requested {target_pages}, kernel allocated {actual_pages}. "
                        "Close memory-intensive programs or reduce VM RAM."
                    )
            _persist_hugepage_target(target_pages)
            sysctl_written = True
            _replace_definition(name, xml, runner)
            save_profile(name, profile)
            atomic_write(vm_dir(name) / "domain.xml", xml)
        except Exception:
            if reservation_changed:
                runner.run(
                    ["sysctl", "-w", f"vm.nr_hugepages={previous_pages}"],
                    check=False,
                )
            if sysctl_written:
                _restore_hugepage_sysctl(previous_sysctl)
            if had_setting:
                resources["hugepages_2m"] = old_setting
            else:
                resources.pop("hugepages_2m", None)
            raise

        print(
            f"{name}: 2 MiB hugepages {'enabled' if enabled else 'disabled'}; "
            f"{target_pages} pages reserved across managed VMs."
        )
        return profile


def enable_devirtualized(
    name: str, runner: Runner, *, guest_vtd: bool | None = None,
    guest_vtd_intremap: bool | None = None,
    guest_secure_boot: bool | None = None,
    guest_dma_protection: bool | None = None,
    guest_core_isolation: bool | None = None,
    guest_hyperv_enlightenments: bool | None = None,
) -> None:
    """Activate patched identity while retaining a VNC/VGA safety console."""
    require_root()
    with vm_lock(name):
        profile = load_profile(name)
        _refresh_profile_host_capabilities(profile)
        resources = profile.setdefault("resources", {})
        # Older profiles may contain the withdrawn native policy.  Migrate it
        # before generating XML so KVM always owns the guest-visible CPUID.
        if resources.get("cpuid_policy") == "svme-gated-native":
            resources["cpuid_policy"] = "intercepted"
        else:
            resources.setdefault("cpuid_policy", "intercepted")
        profile["guest_vtd"] = bool(guest_vtd) if guest_vtd is not None else bool(
            profile.get("guest_vtd", False)
        )
        profile["guest_vtd_intremap"] = (
            bool(guest_vtd_intremap)
            if guest_vtd_intremap is not None
            else bool(profile.get("guest_vtd_intremap", False))
        )
        if not profile["guest_vtd"]:
            profile["guest_vtd_intremap"] = False
        profile["guest_secure_boot"] = (
            bool(guest_secure_boot)
            if guest_secure_boot is not None
            else bool(profile.get("guest_secure_boot", False))
        )
        profile["guest_dma_protection"] = (
            bool(guest_dma_protection)
            if guest_dma_protection is not None
            else bool(profile.get("guest_dma_protection", False))
        )
        if profile["guest_dma_protection"]:
            profile["guest_vtd"] = True
        profile["guest_core_isolation"] = (
            bool(guest_core_isolation)
            if guest_core_isolation is not None
            else bool(profile.get("guest_core_isolation", False))
        )
        if profile["guest_core_isolation"] and not profile["guest_secure_boot"]:
            raise AppError("Core Isolation/VBS requires Guest UEFI Secure Boot.")
        profile["guest_hyperv_enlightenments"] = (
            bool(guest_hyperv_enlightenments)
            if guest_hyperv_enlightenments is not None
            else bool(profile.get(
                "guest_hyperv_enlightenments",
                profile["guest_core_isolation"],
            ))
        )
        if not profile["guest_core_isolation"]:
            profile["guest_hyperv_enlightenments"] = False
        _ensure_inactive(name, runner)
        old_xml = _dump_xml(name, runner)
        _backup_xml(name, old_xml)
        _remember_existing_tpm(profile, old_xml)
        if profile["guest_secure_boot"]:
            # New VMs enable Secure Boot during this stage instead of through
            # configure_guest_security(), so pin the OEM SMBIOS here as well.
            profile = _pin_host_board_identity(profile)
        varstore_backup = _set_guest_secure_boot_varstore(
            name, profile, profile["guest_secure_boot"], runner,
        )
        try:
            xml = build_domain_xml(profile, stage="devirtualized")
            _replace_definition(name, xml, runner)
            profile["stage"] = "devirtualized"
            save_profile(name, profile)
            atomic_write(vm_dir(name) / "domain.xml", xml)
        except Exception:
            if varstore_backup is not None:
                shutil.copy2(varstore_backup, _secure_boot_varstore_path(profile))
            raise


def configure_guest_security(
    name: str, secure_boot: bool, dma_protection: bool, runner: Runner,
    *, core_isolation: bool | None = None,
    guest_hyperv_enlightenments: bool | None = None,
) -> None:
    """Configure persistent guest firmware security without changing passthrough."""
    require_root()
    name = valid_vm_name(name)
    with vm_lock(name):
        profile = load_profile(name)
        if profile.get("adopted"):
            raise AppError("Guest firmware security management is available only for deployer-owned VMs.")
        _ensure_inactive(name, runner)
        old_xml = _dump_xml(name, runner)
        _backup_xml(name, old_xml)
        _remember_existing_hostdevs(profile, old_xml)
        _remember_existing_tpm(profile, old_xml)
        _refresh_profile_host_capabilities(profile)
        profile["guest_secure_boot"] = bool(secure_boot)
        profile["guest_dma_protection"] = bool(dma_protection)
        if core_isolation is not None:
            profile["guest_core_isolation"] = bool(core_isolation)
        else:
            profile["guest_core_isolation"] = bool(
                profile.get("guest_core_isolation", False)
            )
        if profile["guest_core_isolation"] and not profile["guest_secure_boot"]:
            raise AppError("Core Isolation/VBS requires Guest UEFI Secure Boot.")
        profile["guest_hyperv_enlightenments"] = (
            bool(guest_hyperv_enlightenments)
            if guest_hyperv_enlightenments is not None
            else bool(profile.get(
                "guest_hyperv_enlightenments",
                profile["guest_core_isolation"],
            ))
        )
        if not profile["guest_core_isolation"]:
            profile["guest_hyperv_enlightenments"] = False
        if profile["guest_dma_protection"]:
            profile["guest_vtd"] = True
        if profile["guest_secure_boot"]:
            # The Secure Boot PK comes from this physical board. Keep the
            # visible SMBIOS OEM fields in the same manufacturer/model family.
            profile = _pin_host_board_identity(profile)
        varstore_backup = _set_guest_secure_boot_varstore(
            name, profile, profile["guest_secure_boot"], runner,
        )
        try:
            xml = _update_guest_security_xml(old_xml, profile)
            xml = update_identity(xml, profile["identity"], int(profile["resources"]["memory_gib"]))
            _replace_definition(name, xml, runner)
            save_profile(name, profile)
            atomic_write(vm_dir(name) / "domain.xml", xml)
        except Exception:
            if varstore_backup is not None:
                shutil.copy2(varstore_backup, _secure_boot_varstore_path(profile))
            raise
        print(
            f"{name}: guest Secure Boot {'enabled' if secure_boot else 'disabled'}; "
            f"Kernel DMA Protection advertisement {'enabled' if dma_protection else 'disabled'}; "
            f"Core Isolation/VBS {'enabled' if profile['guest_core_isolation'] else 'disabled'}"
        )
        if profile["guest_hyperv_enlightenments"]:
            if amd_nested_hyperv_acceleration_available(profile):
                print("Nested Hyper-V acceleration enabled (AMD GMET/AVIC/TLB flush extensions).")
            else:
                print("Nested Hyper-V acceleration enabled (standard libvirt Hyper-V features).")
        else:
            print("Nested Hyper-V acceleration disabled.")


def align_host_board_identity(name: str, runner: Runner) -> None:
    """Align a managed Secure Boot VM's SMBIOS board fields to host factory keys."""
    require_root()
    name = valid_vm_name(name)
    with vm_lock(name):
        profile = load_profile(name)
        if profile.get("adopted"):
            raise AppError("Host-board alignment is available only for deployer-owned VMs.")
        if not profile.get("guest_secure_boot", False):
            raise AppError("Host-board alignment requires managed Guest UEFI Secure Boot.")
        _ensure_inactive(name, runner)
        old_xml = _dump_xml(name, runner)
        _backup_xml(name, old_xml)
        updated = _pin_host_board_identity(profile)
        xml = update_identity(
            old_xml, updated["identity"], int(updated["resources"]["memory_gib"]),
        )
        _replace_definition(name, xml, runner)
        save_profile(name, updated)
        atomic_write(vm_dir(name) / "domain.xml", xml)
        print(
            f"{name}: SMBIOS board identity aligned to "
            f"{updated['identity_board']['manufacturer']} "
            f"{updated['identity_board']['product']}; randomized serials were preserved."
        )


def configure_tpm(name: str, mode: str, runner: Runner) -> None:
    """Set a VM TPM backend using persistent swtpm state when enabled."""
    require_root()
    name = valid_vm_name(name)
    if mode not in {"none", "emulator", "amd-ftpm"}:
        raise AppError("TPM mode must be one of: none, emulator, amd-ftpm.")
    with vm_lock(name):
        profile = load_profile(name)
        if profile.get("adopted"):
            raise AppError("TPM management is available only for deployer-owned VMs.")
        _ensure_inactive(name, runner)
        old_xml = _dump_xml(name, runner)
        _backup_xml(name, old_xml)
        _remember_existing_tpm(profile, old_xml)

        if mode == "amd-ftpm":
            _require_amd_ftpm_libtpms(profile, runner)
            profile["tpm"] = {
                "mode": "emulator", "model": "tpm-crb", "version": "2.0",
                "profile": "amd-ftpm",
            }
        elif mode == "emulator":
            profile["tpm"] = {"mode": "emulator", "model": "tpm-crb", "version": "2.0"}
        else:
            profile["tpm"] = {"mode": "none"}

        xml = build_domain_xml(profile, stage=profile.get("stage", "install"))
        _replace_definition(name, xml, runner)
        save_profile(name, profile)
        atomic_write(vm_dir(name) / "domain.xml", xml)
        if mode == "amd-ftpm":
            print(
                f"{name}: AMD-profiled software TPM 2.0 is enabled through tpm-crb. "
                "Existing TPM state is preserved; PCR/certificate policy changes apply "
                "only when libvirt manufactures a new TPM state."
            )
        elif mode == "emulator":
            print(f"{name}: persistent swtpm vTPM 2.0 is enabled.")
        else:
            print(f"{name}: TPM device removed.")


def _swtpm_state_root(xml_text: str) -> Path:
    """Locate libvirt's persistent swtpm state for a domain definition."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise AppError("Cannot read the domain UUID for TPM state recreation.") from exc
    value = root.findtext("uuid", default="").strip().lower()
    if not value or not re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value,
    ):
        raise AppError("Domain XML has no valid UUID for TPM state recreation.")
    return LIBVIRT_SWTPM_DIR / value


def _persistent_swtpm_state_root(xml_text: str) -> Path | None:
    """Return the UUID-keyed state directory for a persistent emulator TPM."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise AppError("Cannot read the domain XML while preserving TPM state.") from exc
    tpm = root.find("./devices/tpm")
    backend = tpm.find("backend") if tpm is not None else None
    if (
        backend is None
        or backend.get("type") != "emulator"
        or backend.get("version", "2.0") != "2.0"
        or backend.get("persistent_state") != "yes"
    ):
        return None
    return _swtpm_state_root(xml_text)


def _migrate_tpm_state_for_uuid(old_xml: str, new_xml: str) -> tuple[Path, Path] | None:
    """Move an existing persistent swtpm state when only the domain UUID changes."""
    old_root = _persistent_swtpm_state_root(old_xml)
    new_root = _persistent_swtpm_state_root(new_xml)
    if (
        old_root is None or new_root is None or old_root == new_root
        or not old_root.is_dir() or old_root.is_symlink()
    ):
        return None
    if new_root.exists() or new_root.is_symlink():
        raise AppError(
            f"Refusing to overwrite an existing swtpm state directory: {new_root}"
        )
    marker = old_root.with_name(f"{old_root.name}.kvm-aavm-migrating-{time.time_ns()}")
    try:
        # Two renames on one filesystem make the operation recoverable without
        # copying or partially deleting TPM state.
        os.rename(old_root, marker)
        os.rename(marker, new_root)
    except OSError as exc:
        if marker.exists() and not old_root.exists():
            try:
                os.rename(marker, old_root)
            except OSError:
                pass
        raise AppError(
            f"Could not migrate persistent swtpm state from {old_root} to {new_root}."
        ) from exc
    return old_root, new_root


def _rollback_tpm_state_migration(migration: tuple[Path, Path] | None) -> None:
    """Restore a UUID-keyed swtpm state after an XML definition failure."""
    if migration is None:
        return
    old_root, new_root = migration
    if not new_root.exists():
        return
    if old_root.exists():
        raise AppError(
            f"Cannot roll back swtpm state migration because {old_root} already exists."
        )
    try:
        os.rename(new_root, old_root)
    except OSError as exc:
        raise AppError(
            f"Could not roll back persistent swtpm state to {old_root}."
        ) from exc


def _replace_definition_preserving_tpm(
    name: str, old_xml: str, new_xml: str, runner: Runner,
    require_aavm: bool = True,
) -> None:
    """Define XML while retaining UUID-keyed persistent swtpm state."""
    migration = _migrate_tpm_state_for_uuid(old_xml, new_xml)
    try:
        _replace_definition(name, new_xml, runner, require_aavm=require_aavm)
    except Exception as exc:
        try:
            _rollback_tpm_state_migration(migration)
        except Exception as rollback_exc:
            raise AppError(
                f"Domain definition failed and TPM state rollback also failed: {rollback_exc}"
            ) from exc
        raise


def recreate_tpm(name: str, runner: Runner, *, confirmed: bool = False) -> Path | None:
    """Retire a vTPM state so libvirt manufactures a fresh one on next boot."""
    require_root()
    name = valid_vm_name(name)
    if not confirmed:
        raise AppError(
            "TPM recreation changes the TPM identity. Re-run with explicit confirmation."
        )
    with vm_lock(name):
        profile = load_profile(name)
        if profile.get("adopted"):
            raise AppError("TPM recreation is available only for deployer-owned VMs.")
        _ensure_inactive(name, runner)
        old_xml = _dump_xml(name, runner)
        _remember_existing_tpm(profile, old_xml)
        tpm = profile.get("tpm", {})
        if not isinstance(tpm, dict) or tpm.get("mode") != "emulator":
            raise AppError("TPM recreation requires an enabled persistent swtpm TPM 2.0 device.")
        _backup_xml(name, old_xml)
        if profile.get("tpm", {}).get("profile") == "amd-ftpm":
            _require_amd_ftpm_libtpms(profile, runner)

        state_root = _swtpm_state_root(old_xml)
        tpm2_state = state_root / "tpm2"
        if not state_root.is_dir():
            print(
                f"{name}: no existing libvirt swtpm state was found; "
                "the next VM start will manufacture a new TPM state."
            )
            return None
        if not tpm2_state.is_dir():
            raise AppError(
                f"Refusing to recreate an unrecognized TPM state layout: {state_root}"
            )

        stamp = time.time_ns()
        backup = BACKUP_DIR / name / f"tpm-state-{stamp}"
        backup.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copytree(state_root, backup)
        retired = state_root.with_name(f"{state_root.name}.kvm-aavm-retired-{stamp}")
        try:
            os.rename(state_root, retired)
        except OSError as exc:
            raise AppError(
                f"TPM state backup was created at {backup}, but the active state could not be retired."
            ) from exc
        atomic_write(
            backup / "recreation.json",
            json.dumps({
                "format": 1,
                "vm": name,
                "retired_state": str(retired),
                "created_at": stamp,
                "tpm": profile["tpm"],
            }, ensure_ascii=False, indent=2) + "\n",
            mode=0o600,
        )
        print(
            f"{name}: previous TPM state retired to {retired}; backup saved to {backup}. "
            "Start the VM once to manufacture a new TPM identity. Windows may require "
            "BitLocker recovery and re-registration of TPM-bound credentials."
        )
        return backup


def enable_gpu_setup(name: str, runner: Runner) -> None:
    """Attach the physical GPU while retaining VNC/VGA for driver setup."""
    require_root()
    with vm_lock(name):
        profile = load_profile(name)
        passthrough = profile.get("passthrough", {})
        if not passthrough.get("gpu_pci") or passthrough.get("mode") != "single-gpu":
            raise AppError("GPU maintenance mode requires a configured single-GPU passthrough device.")
        if profile.get("stage") not in {"devirtualized", "gpu-setup", "final"}:
            raise AppError(
                "Complete VM step 2 (devirtualization with VNC/VGA) before GPU maintenance mode."
            )
        _ensure_inactive(name, runner)
        old_xml = _dump_xml(name, runner)
        _backup_xml(name, old_xml)
        _remember_existing_tpm(profile, old_xml)
        xml = build_domain_xml(profile, stage="gpu-setup")
        _replace_definition(name, xml, runner)
        profile["stage"] = "gpu-setup"
        save_profile(name, profile)
        atomic_write(vm_dir(name) / "domain.xml", xml)


def finalize_vm(name: str, runner: Runner) -> None:
    require_root()
    with vm_lock(name):
        profile = load_profile(name)
        if profile.get("passthrough", {}).get("gpu_pci") and profile.get("stage") not in {"devirtualized", "gpu-setup", "final"}:
            raise AppError(
                "Complete VM step 2 (devirtualization with VNC/VGA) before enabling passthrough."
            )
        _ensure_inactive(name, runner)
        old_xml = _dump_xml(name, runner)
        _backup_xml(name, old_xml)
        _remember_existing_tpm(profile, old_xml)
        xml = build_domain_xml(profile, stage="final")
        _replace_definition(name, xml, runner)
        profile["stage"] = "final"
        save_profile(name, profile)
        atomic_write(vm_dir(name) / "domain.xml", xml)


def configure_minimal_devices(
    name: str, enabled: bool, runner: Runner,
    *, disable_virtual_network: bool | None = None,
) -> None:
    require_root()
    with vm_lock(name):
        profile = load_profile(name)
        if profile.get("adopted"):
            raise AppError("Minimal-device regeneration is available only for VMs created by this deployer.")
        _ensure_inactive(name, runner)
        old_xml = _dump_xml(name, runner)
        _backup_xml(name, old_xml)
        _remember_existing_tpm(profile, old_xml)
        profile["minimal_devices"] = bool(enabled)
        if disable_virtual_network is not None:
            passthrough = profile.setdefault("passthrough", {})
            passthrough["disable_virtual_network"] = bool(disable_virtual_network)
            passthrough["virtual_network_choice_set"] = True
        stage = profile.get("stage", "install")
        xml = build_domain_xml(profile, stage=stage)
        _replace_definition(name, xml, runner)
        save_profile(name, profile)
        atomic_write(vm_dir(name) / "domain.xml", xml)
        state = "enabled" if enabled else "disabled"
        network_state = (
            "unchanged" if disable_virtual_network is None
            else ("disabled" if disable_virtual_network else "enabled")
        )
        print(
            f"{name}: minimal QEMU virtual devices {state}; "
            f"libvirt virtual network {network_state}"
        )


def configure_passthrough(name: str, passthrough: dict, runner: Runner) -> None:
    require_root()
    with vm_lock(name):
        profile = load_profile(name)
        _ensure_inactive(name, runner)
        old_xml = _dump_xml(name, runner)
        _backup_xml(name, old_xml)
        _remember_existing_tpm(profile, old_xml)
        if profile.get("adopted"):
            xml_passthrough = dict(passthrough)
            xml_passthrough["_minimal_devices"] = bool(profile.get("minimal_devices", False))
            xml_passthrough["_host_pci"] = list(profile.get("host", {}).get("pci", []))
            xml = update_passthrough(
                old_xml, profile.get("passthrough", {}), xml_passthrough,
                profile["identity"],
            )
        else:
            # Rebuild deployer-owned domains so stage-specific single-GPU
            # settings (selected GPU functions, ROM BAR, x-vga and the saved
            # guest-vIOMMU mode) are applied just as during initial creation.
            profile["passthrough"] = passthrough
            xml = build_domain_xml(profile, stage=profile.get("stage", "install"))
        _replace_definition(name, xml, runner, require_aavm=not profile.get("adopted", False))
        profile["passthrough"] = passthrough
        save_profile(name, profile)
        atomic_write(vm_dir(name) / "domain.xml", xml)
        print(f"{name}: PCI/USB passthrough configuration updated")


def disable_passthrough(name: str, runner: Runner) -> None:
    """Remove all hostdev passthrough and restore a VNC/VGA troubleshooting VM."""
    require_root()
    name = valid_vm_name(name)
    with vm_lock(name):
        profile = load_profile(name)
        _ensure_inactive(name, runner)
        old_xml = _dump_xml(name, runner)
        _backup_xml(name, old_xml)
        _remember_existing_tpm(profile, old_xml)
        passthrough = profile.setdefault("passthrough", {})
        passthrough.update({
            "mode": "manual",
            "pci": [],
            "gpu_pci": [],
            "gpu_guest_pci": [],
            "extra_pci": [],
            "usb": [],
            "network_pci": None,
            "gpu_rom_bar": False,
            "rom_file": None,
            "gpu_reset_method": "default",
            "disable_virtual_network": False,
            "virtual_network_choice_set": True,
        })
        # A reliable troubleshooting console requires the standard virtual
        # input devices even when minimal-device mode was previously enabled.
        profile["minimal_devices"] = False
        profile["stage"] = "devirtualized"
        xml = build_domain_xml(profile, stage="devirtualized")
        _replace_definition(name, xml, runner)
        save_profile(name, profile)
        atomic_write(vm_dir(name) / "domain.xml", xml)
        from .hooks import remove_single_gpu_hooks
        remove_single_gpu_hooks(name)
        runner.run(["systemctl", "daemon-reload"], check=False)
        print(f"{name}: 已移除所有 PCI/USB 直通，VNC/VGA、虛擬輸入與虛擬網路已恢復。")


def _domain_exists(name: str, runner: Runner) -> bool:
    result = runner.run(["virsh", "dominfo", name], check=False, capture=True)
    return result.returncode == 0


def _ensure_inactive(name: str, runner: Runner) -> None:
    result = runner.run(["virsh", "domstate", name], check=False, capture=True)
    if result.returncode == 0 and result.stdout.strip().lower() not in {"shut off", "shutoff", "crashed"}:
        raise AppError(f"VM '{name}' must be completely shut off.")


def _dump_xml(name: str, runner: Runner) -> str:
    result = runner.run(["virsh", "dumpxml", "--inactive", name], capture=True)
    return result.stdout


def _backup_xml(name: str, xml: str) -> Path:
    folder = BACKUP_DIR / name
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"domain-{int(time.time())}.xml"
    atomic_write(path, xml)
    return path


def _replace_definition(name: str, xml: str, runner: Runner, require_aavm: bool = True) -> None:
    errors = validate_required(xml) if require_aavm else []
    if errors:
        raise AppError("Refusing invalid XML:\n- " + "\n- ".join(errors))
    target = vm_dir(name) / ".domain-new.xml"
    atomic_write(target, xml)
    if command_exists("virt-xml-validate") and command_exists("xmllint"):
        runner.run(["virt-xml-validate", str(target), "domain"])
    # A UUID rotation requires undefining the inactive domain first. NVRAM is kept.
    previous = _dump_xml(name, runner)
    runner.run(["virsh", "undefine", name, "--keep-nvram"])
    try:
        # Capture libvirt's diagnostic so the transactional wrapper includes
        # the actual incompatibility instead of only the failed command line.
        runner.run(["virsh", "define", "--validate", str(target)], capture=True)
    except Exception as exc:
        recovery = vm_dir(name) / ".domain-recovery.xml"
        atomic_write(recovery, previous)
        runner.run(["virsh", "define", str(recovery)], check=False)
        raise AppError(f"New XML could not be defined; the previous definition was restored. Cause: {exc}")
    os.replace(target, vm_dir(name) / "domain.xml")


def randomize_xml(name: str, runner: Runner) -> None:
    require_root()
    with vm_lock(name):
        profile = load_profile(name)
        _ensure_inactive(name, runner)
        old_xml = _dump_xml(name, runner)
        _backup_xml(name, old_xml)
        updated = rerandomize(profile)
        xml = update_identity(old_xml, updated["identity"], int(updated["resources"]["memory_gib"]))
        _replace_definition_preserving_tpm(
            name, old_xml, xml, runner,
            require_aavm=not profile.get("adopted", False),
        )
        save_profile(name, updated)
        clear_pending(name)
        print(f"{name}: XML identity generation {updated['identity']['generation']} active")


def randomize_all(name: str, runner: Runner) -> None:
    require_root()
    with vm_lock(name):
        profile = load_profile(name)
        resources = profile.setdefault("resources", {})
        if resources.get("cpuid_policy") == "svme-gated-native":
            resources["cpuid_policy"] = "intercepted"
        else:
            resources.setdefault("cpuid_policy", "intercepted")
        _ensure_inactive(name, runner)
        old_xml = _dump_xml(name, runner)
        _backup_xml(name, old_xml)
        updated = rerandomize(profile)
        updated = build_all(name, updated, runner)
        xml = update_identity(old_xml, updated["identity"], int(updated["resources"]["memory_gib"]))
        xml = update_artifact_paths(xml, updated["paths"])
        xml = _ensure_profile_tpm_xml(xml, updated)
        _replace_definition_preserving_tpm(
            name, old_xml, xml, runner,
            require_aavm=not profile.get("adopted", False),
        )
        save_profile(name, updated)
        clear_pending(name)
        print(f"{name}: complete identity/artifact generation {updated['identity']['generation']} active")


def rebuild_artifacts(name: str, runner: Runner) -> None:
    """Rebuild patched QEMU/OVMF without changing a VM's persistent identity."""
    require_root()
    name = valid_vm_name(name)
    with vm_lock(name):
        profile = load_profile(name)
        if profile.get("adopted"):
            raise AppError("Artifact rebuild is available only for deployer-owned VMs.")
        resources = profile.setdefault("resources", {})
        if resources.get("cpuid_policy") == "svme-gated-native":
            resources["cpuid_policy"] = "intercepted"
        else:
            resources.setdefault("cpuid_policy", "intercepted")
        _ensure_inactive(name, runner)
        old_xml = _dump_xml(name, runner)
        _backup_xml(name, old_xml)
        if profile.get("guest_secure_boot", False):
            # Keep future firmware rebuilds tied to the board whose factory
            # Secure Boot databases are already stored in this VM's VARS.
            profile = _pin_host_board_identity(profile)
            old_xml = update_identity(
                old_xml, profile["identity"], int(profile["resources"]["memory_gib"]),
            )
        generation = max(
            int(profile.get("artifact_generation", 0)),
            int(profile["identity"]["generation"]),
        ) + 1
        updated = build_all(name, profile, runner, generation=generation)
        xml = update_artifact_paths(old_xml, updated["paths"])
        _remember_existing_tpm(updated, old_xml)
        xml = _ensure_profile_tpm_xml(xml, updated)
        _replace_definition(name, xml, runner)
        save_profile(name, updated)
        clear_pending(name)
        print(
            f"{name}: QEMU/OVMF artifact generation {generation} active; "
            f"XML identity generation {updated['identity']['generation']} was preserved"
        )


def cleanup_vm_artifacts(name: str, runner: Runner) -> None:
    """Remove inactive QEMU/OVMF generations and completed build worktrees."""
    require_root()
    name = valid_vm_name(name)
    with vm_lock(name):
        profile = load_profile(name)
        if profile.get("adopted"):
            raise AppError("Artifact cleanup is available only for deployer-owned VMs.")
        _ensure_inactive(name, runner)
        active_generation = int(profile.get("artifact_generation", 0))
        if active_generation < 1:
            raise AppError("VM profile has no active artifact generation.")
        required = [
            Path(profile["paths"]["qemu"]),
            Path(profile["paths"]["ovmf_code"]),
            Path(profile["paths"]["ovmf_vars"]),
            *(Path(value) for value in profile["paths"].get("ssdt", [])),
        ]
        missing = [str(path) for path in required if not path.is_file()]
        if missing:
            raise AppError(
                "Active VM artifacts are incomplete; refusing cleanup:\n- "
                + "\n- ".join(missing)
            )
        root = vm_dir(name)
        artifact_root = root / "artifacts"
        build_root = root / "build"
        active_name = f"generation-{active_generation}"
        targets = [
            path for path in artifact_root.glob("generation-*")
            if path.name != active_name
        ]
        targets.extend(build_root.glob("generation-*"))
        if not targets:
            print(f"{name}: 沒有可清理的舊 QEMU/OVMF 產物或 build 暫存。")
            return
        print(f"{name}: 將保留目前 active {active_name} 產物，刪除：")
        for path in targets:
            print(f"  - {path}")
        if not prompt_yes_no("確認清理這些 VM 產物與 build 暫存", False):
            print(f"{name}: 已取消清理。")
            return
        for path in targets:
            if path.is_symlink() or path.is_file():
                path.unlink()
            elif path.is_dir():
                shutil.rmtree(path)
        print(f"{name}: 舊 VM 產物與 build 暫存已清理；active {active_name} 保留。")


def purge_vm(name: str, runner: Runner) -> None:
    """Permanently remove a managed VM and its local artifacts."""
    require_root()
    name = valid_vm_name(name)
    root = vm_dir(name)
    profile: dict = {}
    profile_path = root / "profile.json"
    if profile_path.is_file():
        try:
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError) as exc:
            raise AppError(f"Cannot read VM profile before purge: {exc}") from exc

    domain_exists = _domain_exists(name, runner)
    if domain_exists:
        _ensure_inactive(name, runner)

    disk = VM_IMAGE_DIR / f"{name}.qcow2"
    profile_disk = Path(str(profile.get("paths", {}).get("disk", "")))
    if profile_disk.parent == VM_IMAGE_DIR and profile_disk.name == disk.name:
        disk = profile_disk
    backups = [
        path for path in BACKUP_DIR.iterdir()
        if path.name == name or path.name.startswith(f"{name}-")
    ] if BACKUP_DIR.is_dir() else []
    pending = PENDING_DIR / f"{name}.json"
    targets = [path for path in (root, disk, pending, *backups) if path.exists()]
    if not targets and not domain_exists:
        raise AppError(f"找不到 VM '{name}' 的管理資料、產物或磁碟。")

    print(f"{name}: 完全移除將刪除以下項目（不可復原）：")
    if domain_exists:
        print(f"  - libvirt domain: {name}（含 NVRAM 定義）")
    for path in targets:
        print(f"  - {path}")
    print("原始 Windows ISO（若位於 VM 目錄外）不會被刪除。")
    if not prompt_yes_no("確認完全移除這個 VM 及其所有本地產物", False):
        print(f"{name}: 已取消完全移除。")
        return

    from .hooks import remove_dynamic_hooks, remove_performance_hook, remove_single_gpu_hooks
    remove_dynamic_hooks(name)
    remove_single_gpu_hooks(name)
    remove_performance_hook(name)
    runner.run(["systemctl", "stop", f"kvm-aavm-randomize-{name}.service"], check=False)
    runner.run(["systemctl", "daemon-reload"], check=False)
    clear_pending(name)
    if domain_exists:
        runner.run(["virsh", "undefine", name, "--nvram"], check=False)
    for path in targets:
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink(missing_ok=True)
    if profile.get("resources", {}).get("hugepages_2m", False) and not runner.dry_run:
        # The profile has now disappeared from VM_DIR, so the remaining total
        # is exact even if its name is reused later. Failure to shrink a busy
        # hugetlb pool must not turn a completed destructive purge into an
        # apparent failure; a later hugepage update will retry the target.
        try:
            target_pages = _managed_hugepage_target_pages(name, {
                "resources": {"hugepages_2m": False},
            })
            current_pages = _read_hugepage_count()
            if current_pages != target_pages:
                runner.run(["sysctl", "-w", f"vm.nr_hugepages={target_pages}"])
                if _read_hugepage_count() != target_pages:
                    raise AppError("kernel did not release the requested hugepages")
            _persist_hugepage_target(target_pages)
            print(f"{name}: 已重新計算 2 MiB hugepages，剩餘預留 {target_pages} 頁。")
        except AppError as exc:
            print(
                f"{name}: VM 已移除，但 2 MiB hugepages 尚未縮減：{exc}",
            )
    print(f"{name}: VM、產物、備份、安裝媒體副本與 qcow2 已完全移除。")


def set_dynamic(name: str, enabled: bool) -> dict:
    with vm_lock(name):
        profile = load_profile(name)
        profile["dynamic_randomization"] = enabled
        save_profile(name, profile)
        return profile
