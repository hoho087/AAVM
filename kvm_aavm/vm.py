from __future__ import annotations

import errno
import json
import os
import shutil
import stat
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from .build import build_all
from .hardware import host_fingerprint, vm_cpu_layout
from .identity import generate, rerandomize
from .paths import BACKUP_DIR, VM_IMAGE_DIR, ensure_state_dirs, vm_dir
from .state import clear_pending, load_profile, mark_pending, save_profile, vm_lock
from .util import AppError, Runner, atomic_write, command_exists, require_root, sha256, valid_vm_name
from .xmlgen import AAVM_NS, QEMU_NS, INSTALL_OVMF_CODE, INSTALL_OVMF_VARS, build_domain_xml, update_artifact_paths, update_identity, update_passthrough, validate_required


SECURE_BOOT_VARIABLE_NAMES = {
    "PK", "KEK", "db", "dbx",
    "PKDefault", "KEKDefault", "dbDefault", "dbxDefault",
}
SECURE_BOOT_REQUIRED_NAMES = {"PK", "KEK", "db"}
UBUNTU_SECURE_OVMF_VARS = Path("/usr/share/OVMF/OVMF_VARS_4M.ms.fd")


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
            "threads_per_core": cpu_layout["threads_per_core"],
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
        "stage": "install",
        "minimal_devices": False,
    }


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
    variables = [
        item for item in value.get("variables", [])
        if item.get("name") in SECURE_BOOT_VARIABLE_NAMES
    ]
    names = {item.get("name") for item in variables}
    if not SECURE_BOOT_REQUIRED_NAMES.issubset(names):
        return None
    return {"version": int(value.get("version", 2)), "variables": variables}


def _secure_boot_defaults(name: str, profile: dict, runner: Runner, folder: Path) -> Path:
    """Return only PK/KEK/db variables, never BootOrder or device identity."""
    generation = int(profile.get("artifact_generation", 1))
    build_defaults = vm_dir(name) / "build" / f"generation-{generation}" / "work" / "defaults.json"
    filtered = None
    if build_defaults.is_file():
        try:
            filtered = _filtered_secure_boot_variables(json.loads(build_defaults.read_text(encoding="utf-8")))
        except (OSError, ValueError, TypeError):
            filtered = None

    if filtered is None:
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

    destination = folder / "secure-vars.json"
    atomic_write(destination, json.dumps(filtered, ensure_ascii=False, indent=2) + "\n", mode=0o600)
    return destination


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
        action = "enable with enrolled platform/Microsoft keys" if enabled else "disable"
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
        if enabled:
            defaults = _secure_boot_defaults(name, profile, runner, folder)
            command.extend(["--set-json", str(defaults), "--secure-boot"])
        else:
            command.extend(["--set-false", "SecureBootEnable"])
        runner.run(command)

        exported = folder / "verify.json"
        runner.run(["virt-fw-vars", "--input", str(output), "--output-json", str(exported)])
        value = json.loads(exported.read_text(encoding="utf-8"))
        variables = {item.get("name"): item for item in value.get("variables", [])}
        state = variables.get("SecureBootEnable", {}).get("data", "").lower()
        if enabled:
            missing = sorted(SECURE_BOOT_REQUIRED_NAMES - set(variables))
            if missing or state != "01":
                detail = f"missing {', '.join(missing)}" if missing else "SecureBootEnable is not true"
                raise AppError(f"Refusing invalid Secure Boot VARS output: {detail}.")
        elif state not in {"", "00"}:
            raise AppError("Refusing invalid Secure Boot VARS output: SecureBootEnable is still true.")
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


def _update_guest_security_xml(xml_text: str, profile: dict) -> str:
    """Change only guest-security nodes; preserve every existing device."""
    root = ET.fromstring(xml_text)
    stage = root.find(f"./metadata/{{{AAVM_NS}}}stage")
    if stage is None:
        raise AppError("Managed VM XML is missing kvm-aavm stage metadata.")
    secure_boot = bool(profile.get("guest_secure_boot", False))
    dma_protection = bool(profile.get("guest_dma_protection", False))
    core_isolation = bool(profile.get("guest_core_isolation", False))
    if core_isolation and not secure_boot:
        raise AppError("Core Isolation/VBS requires Guest UEFI Secure Boot.")
    stage.set("guest-secure-boot", "true" if secure_boot else "false")
    stage.set("guest-dma-protection", "true" if dma_protection else "false")
    stage.set("guest-core-isolation", "true" if core_isolation else "false")

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
        layout = vm_cpu_layout(current_host["cpu"], vcpus)
        if not layout["vcpu_pins"] or not layout["emulator_cpus"]:
            raise AppError(
                "The requested vCPU count leaves no complete physical core for Ubuntu; "
                "choose fewer vCPUs or configure CPU pinning manually."
            )
        old_xml = _dump_xml(name, runner)
        _backup_xml(name, old_xml)
        profile.setdefault("host", {})["cpu"] = current_host["cpu"]
        resources = profile.setdefault("resources", {})
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


def enable_devirtualized(
    name: str, runner: Runner, *, guest_vtd: bool | None = None,
    guest_vtd_intremap: bool | None = None,
    guest_secure_boot: bool | None = None,
    guest_dma_protection: bool | None = None,
    guest_core_isolation: bool | None = None,
) -> None:
    """Activate patched identity while retaining a VNC/VGA safety console."""
    require_root()
    with vm_lock(name):
        profile = load_profile(name)
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
        _ensure_inactive(name, runner)
        _backup_xml(name, _dump_xml(name, runner))
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
        if profile["guest_dma_protection"]:
            profile["guest_vtd"] = True
        varstore_backup = _set_guest_secure_boot_varstore(
            name, profile, profile["guest_secure_boot"], runner,
        )
        try:
            xml = _update_guest_security_xml(old_xml, profile)
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
        _backup_xml(name, _dump_xml(name, runner))
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
        _backup_xml(name, _dump_xml(name, runner))
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
        _replace_definition(name, xml, runner, require_aavm=not profile.get("adopted", False))
        save_profile(name, updated)
        clear_pending(name)
        print(f"{name}: XML identity generation {updated['identity']['generation']} active")


def randomize_all(name: str, runner: Runner) -> None:
    require_root()
    with vm_lock(name):
        profile = load_profile(name)
        _ensure_inactive(name, runner)
        old_xml = _dump_xml(name, runner)
        _backup_xml(name, old_xml)
        updated = rerandomize(profile)
        updated = build_all(name, updated, runner)
        xml = update_identity(old_xml, updated["identity"], int(updated["resources"]["memory_gib"]))
        xml = update_artifact_paths(xml, updated["paths"])
        _replace_definition(name, xml, runner, require_aavm=not profile.get("adopted", False))
        save_profile(name, updated)
        clear_pending(name)
        print(f"{name}: complete identity/artifact generation {updated['identity']['generation']} active")


def set_dynamic(name: str, enabled: bool) -> dict:
    with vm_lock(name):
        profile = load_profile(name)
        profile["dynamic_randomization"] = enabled
        save_profile(name, profile)
        return profile
