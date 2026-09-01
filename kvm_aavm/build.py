from __future__ import annotations

import os
import re
import shlex
import shutil
from pathlib import Path

from .hardware import PciDevice, device_identity
from .paths import OFFLINE_DIR, PROJECT_DIR, vm_dir
from .util import AppError, Runner, atomic_write, require_root


LEGACY_FILES = [
    "qemupatch.sh", "ovmfpatch.sh",
    "splash.bmp", "ssdt1.dsl", "ssdt2.dsl",
]
DEFAULT_MAX_BUILD_JOBS = 4


def _validate_generated_vars(path: Path) -> None:
    """Reject unsafe cross-component interface values before building OVMF."""
    if not path.is_file():
        raise AppError(f"QEMU patch did not generate identity variables: {path}")
    text = path.read_text(encoding="utf-8")
    matches = re.findall(r'^cpu="([0-9]+)"$', text, flags=re.MULTILINE)
    if len(matches) != 1:
        raise AppError("Generated vars.sh must contain exactly one decimal cpu value.")
    cpu_hotplug_base = int(matches[0])
    if cpu_hotplug_base > 0xFFF0 or cpu_hotplug_base % 4:
        raise AppError(
            "Generated CPU hotplug I/O base is unsafe: "
            f"0x{cpu_hotplug_base:X}. It must be 4-byte aligned and leave "
            "room below 0x10000; refusing to build an OVMF image that would "
            "deadlock in CpuHotplugSmm."
        )


def _validate_qemu_firmware_hardening(qemu_source: Path) -> None:
    """Ensure the patched HPET AML does not retain VMAware's QEMU shape."""
    acpi_build = qemu_source / "hw/i386/acpi-build.c"
    if not acpi_build.is_file():
        raise AppError(f"Patched QEMU ACPI source is missing: {acpi_build}")
    text = acpi_build.read_text(encoding="utf-8")
    expected = "aml_lless(aml_int(41666666), period)"
    legacy = "aml_lgreater(period, aml_int(41666666))"
    if expected not in text or legacy in text:
        raise AppError(
            "QEMU HPET firmware hardening was not applied; refusing to "
            "publish artifacts with the legacy AML validation shape."
        )


def _validate_qemu_kvm_hypercall_hardening(qemu_source: Path) -> None:
    """Ensure QEMU disables KVM's cross-vendor hypercall rewrite quirk."""
    kvm_source = qemu_source / "target/i386/kvm/kvm.c"
    if not kvm_source.is_file():
        raise AppError(f"Patched QEMU KVM source is missing: {kvm_source}")
    text = kvm_source.read_text(encoding="utf-8")
    required = (
        "KVM-AAVM: disable KVM hypercall rewrite quirk.",
        "kvm_vm_enable_cap(s, KVM_CAP_DISABLE_QUIRKS2, 0",
        "KVM_X86_QUIRK_FIX_HYPERCALL_INSN",
    )
    if any(value not in text for value in required):
        raise AppError(
            "QEMU KVM hypercall hardening was not applied; refusing to publish "
            "artifacts that retain KVM VMCALL/VMMCALL rewriting."
        )


def _validate_ovmf_firmware_identity(
    ovmf_source: Path, expected_firmware: dict[str, str] | None = None,
) -> None:
    """Reject OVMF's default BIOS identity in a published firmware build."""
    declarations = ovmf_source / "MdeModulePkg/MdeModulePkg.dec"
    if not declarations.is_file():
        raise AppError(f"Patched OVMF declarations are missing: {declarations}")
    text = declarations.read_text(encoding="utf-8")
    expected = {
        "PcdFirmwareVendor": re.compile(
            r"PcdFirmwareVendor\|L\"([^\"]+)\""
        ),
        "PcdFirmwareVersionString": re.compile(
            r"PcdFirmwareVersionString\|L\"([^\"]+)\""
        ),
        "PcdFirmwareReleaseDateString": re.compile(
            r"PcdFirmwareReleaseDateString\|L\"([^\"]+)\""
        ),
    }
    values: dict[str, str] = {}
    for name, pattern in expected.items():
        match = pattern.search(text)
        value = match.group(1).strip() if match else ""
        if not value:
            raise AppError(
                f"Patched OVMF {name} is empty; refusing to publish firmware "
                "with the generic 440/10/11/2017 BIOS fallback."
            )
        values[name] = value
    if re.search(r"(?:edk\s*ii|ovmf|tianocore)", values["PcdFirmwareVendor"], re.I):
        raise AppError(
            "Patched OVMF still advertises an EDK2/OVMF firmware vendor; "
            "refusing to publish a detectable generic Secure Boot image."
        )
    if expected_firmware:
        expected = {
            "PcdFirmwareVendor": expected_firmware.get("vendor", ""),
            "PcdFirmwareVersionString": expected_firmware.get("version", ""),
            "PcdFirmwareReleaseDateString": expected_firmware.get("date", ""),
        }
        mismatches = [
            f"{name}={values[name]!r} (expected {value!r})"
            for name, value in expected.items()
            if value and values[name] != value
        ]
        if mismatches:
            raise AppError(
                "Patched OVMF BIOS identity does not match the Secure Boot board profile: "
                + "; ".join(mismatches)
            )
        # The two SMBIOS producers are compiled separately from the PCD
        # declarations. Check both source files so a future patch cannot make
        # Windows see a different Type 0 BIOS identity at runtime.
        for relative in (
            "OvmfPkg/Bhyve/SmbiosPlatformDxe/SmbiosPlatformDxe.c",
            "OvmfPkg/SmbiosPlatformDxe/SmbiosPlatformDxe.c",
        ):
            source = ovmf_source / relative
            if not source.is_file():
                raise AppError(f"Patched OVMF SMBIOS source is missing: {source}")
            source_text = source.read_text(encoding="utf-8")
            missing = [value for value in expected.values() if value and value not in source_text]
            if missing:
                raise AppError(
                    f"Patched OVMF SMBIOS source {source} is missing: "
                    + ", ".join(missing)
                )


def _validate_ovmf_measured_boot(ovmf_source: Path) -> None:
    """Require the TPM2 measurement and TCG2 event-log modules in OVMF."""
    required = {
        "OvmfPkg/Include/Dsc/OvmfTpmComponentsPei.dsc.inc": (
            "SecurityPkg/Tcg/Tcg2Pei/Tcg2Pei.inf",
            "SecurityPkg/Tcg/Tcg2PlatformPei/Tcg2PlatformPei.inf",
        ),
        "OvmfPkg/Include/Dsc/OvmfTpmComponentsDxe.dsc.inc": (
            "SecurityPkg/Tcg/Tcg2Dxe/Tcg2Dxe.inf",
            "SecurityPkg/Tcg/Tcg2PlatformDxe/Tcg2PlatformDxe.inf",
        ),
        "OvmfPkg/Include/Fdf/OvmfTpmDxe.fdf.inc": (
            "SecurityPkg/Tcg/Tcg2Dxe/Tcg2Dxe.inf",
            "SecurityPkg/Tcg/Tcg2PlatformDxe/Tcg2PlatformDxe.inf",
        ),
    }
    missing: list[str] = []
    for relative, markers in required.items():
        path = ovmf_source / relative
        if not path.is_file():
            missing.append(relative)
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        missing.extend(f"{relative}:{marker}" for marker in markers if marker not in text)
    if missing:
        raise AppError(
            "OVMF TPM2 measured-boot/event-log components are incomplete: "
            + ", ".join(missing)
        )


def _enable_fail_fast(text: str) -> str:
    if text.startswith("#!/usr/bin/env bash\n") and "set -e\n" not in text[:80]:
        return text.replace("#!/usr/bin/env bash\n", "#!/usr/bin/env bash\nset -e\n", 1)
    return text


def _replace_assignment(text: str, key: str, value: str) -> str:
    pattern = re.compile(rf"^{re.escape(key)}=.*$", re.MULTILINE)
    replacement = f"{key}={shlex.quote(value)}"
    updated, count = pattern.subn(lambda _: replacement, text, count=1)
    if count != 1:
        raise AppError(f"Legacy patch compatibility check failed: assignment '{key}' was not found exactly once.")
    return updated


def _adapt_qemu_script(text: str, output: Path, hardware: dict[str, str]) -> str:
    text = _enable_fail_fast(text)
    cpu_vendor = hardware["cpu_vendor"]
    suffix = "1022" if cpu_vendor == "amd" else "8086"
    mapping = {
        f"lpc_{suffix}": hardware["lpc"], f"smbus_{suffix}": hardware["smbus"],
        f"hdaudio_{suffix}": hardware["audio"], f"hdaname_{suffix}": hardware["audio_name"],
        f"sata_{suffix}": hardware["storage"], f"rootport_{suffix}": hardware["rootport"],
        f"xhci_{suffix}": hardware["xhci"], f"hostbridge_{suffix}": hardware["hostbridge"],
        f"pcibridge_{suffix}": hardware["pcibridge"],
    }
    for key, value in mapping.items():
        text = _replace_assignment(text, key, value.upper() if key != f"hdaname_{suffix}" else value)
    text = _replace_assignment(text, "QEMU_DEST", str(output / "bin"))
    text = text.replace("read -p $'Continue? [y/\\e[1mN\\e[0m]> ' -n 1 -r", "REPLY=y")
    text = text.replace("sudo mkdir -p /usr/local/share/qemu", f"sudo mkdir -p {output / 'share/qemu'}")
    text = text.replace('"/usr/local/share/qemu"', f'"{output / "share/qemu"}"')
    text, copy_count = re.subn(
        r"^cp -(?:fr|a) qemubackup/\. qemu$",
        "cp -a qemubackup/. qemu", text, count=1, flags=re.MULTILINE,
    )
    text, configure_count = re.subn(
        r"^\./configure --target-list=x86_64-softmmu(?: --disable-rust)?$",
        "./configure --target-list=x86_64-softmmu --disable-rust",
        text, count=1, flags=re.MULTILINE,
    )
    if copy_count != 1 or configure_count != 1:
        raise AppError("Legacy patch compatibility check failed: QEMU copy/configure command was not found exactly once.")
    build_command = 'ninja -j"${KVM_AAVM_BUILD_JOBS}" qemu-system-x86_64'
    updated, count = re.subn(
        r'^(?:make|ninja) -j(?:[ \t]*|"\$KVM_AAVM_BUILD_JOBS" qemu-system-x86_64[ \t]*)$',
        build_command, text, count=1, flags=re.MULTILINE,
    )
    if count != 1:
        raise AppError("Legacy patch compatibility check failed: QEMU build command was not found exactly once.")
    text = updated
    return text


def _adapt_ovmf_script(text: str, output: Path) -> str:
    for flag in ("-D SECURE_BOOT_ENABLE", "-D SMM_REQUIRE", "-D TPM2_ENABLE"):
        if flag not in text:
            raise AppError(f"OVMF build script is missing required flag: {flag}")
    text = _enable_fail_fast(text)
    text = _replace_assignment(text, "EDK2_DEST", str(output / "ovmf"))
    text, count = re.subn(
        r"^cp -(?:fr|a) ovmfbackup/\. ovmf$",
        "cp -a ovmfbackup/. ovmf", text, count=1, flags=re.MULTILINE,
    )
    if count != 1:
        raise AppError("Legacy patch compatibility check failed: OVMF source copy command was not found exactly once.")
    text = text.replace("read -p $'Continue? [y/\\e[1mN\\e[0m]> ' -n 1 -r", "REPLY=y")
    text = text.replace("read -p $'Set EFI variables? [\\e[1mY\\e[0m/n]> ' -n 1 -r", "REPLY=y")
    text = text.replace("read -p $'Renew EFI variables? [y/\\e[1mN\\e[0m]> ' -n 1 -r", "REPLY=n")
    return text


def _source(relative: str) -> Path:
    path = OFFLINE_DIR / "sources" / relative
    if not path.is_dir():
        raise AppError(f"Required offline source is missing: {path}")
    return path


def _stage(vm_name: str, generation: int, profile: dict) -> tuple[Path, Path]:
    root = vm_dir(vm_name)
    work = root / "build" / f"generation-{generation}"
    output = root / "artifacts" / f"generation-{generation}"
    if work.exists():
        shutil.rmtree(work)
    if output.exists():
        shutil.rmtree(output)
    work.mkdir(parents=True)
    output.mkdir(parents=True)
    for filename in LEGACY_FILES:
        source = PROJECT_DIR / filename
        if source.exists():
            shutil.copy2(source, work / filename)
    shutil.copytree(_source("qemu"), work / "qemubackup", symlinks=True)
    shutil.copytree(_source("edk2"), work / "ovmfbackup", symlinks=True)
    # Full rebuilds intentionally generate a new vars.sh in this stage.
    devices = [PciDevice(**item) for item in profile["host"].get("pci", [])]
    hw = device_identity(devices, profile["host"]["cpu"]["vendor"])
    hw["cpu_vendor"] = profile["host"]["cpu"]["vendor"]
    qemu = (work / "qemupatch.sh").read_text(encoding="utf-8")
    ovmf = (work / "ovmfpatch.sh").read_text(encoding="utf-8")
    atomic_write(work / "qemupatch.sh", _adapt_qemu_script(qemu, output, hw), 0o755)
    atomic_write(work / "ovmfpatch.sh", _adapt_ovmf_script(ovmf, output), 0o755)
    return work, output


def build_all(
    vm_name: str, profile: dict, runner: Runner, *, generation: int | None = None,
) -> dict:
    require_root()
    generation = int(profile["identity"]["generation"] if generation is None else generation)
    work, output = _stage(vm_name, generation, profile)
    (output / "bin").mkdir(parents=True, exist_ok=True)
    (output / "share/qemu").mkdir(parents=True, exist_ok=True)
    (output / "ovmf").mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["KVM_AAVM_AUTO_YES"] = "1"
    # A Secure Boot VM keeps the BIOS identity captured with the motherboard
    # host Secure Boot snapshot. Rebuilding on the same host must not randomize
    # Type 0 vendor/version/date or silently diverge from its PK provider.
    firmware = profile.get("identity_firmware", {})
    board = profile.get("identity_board", {})
    if isinstance(firmware, dict):
        for field, variable in (
            ("vendor", "KVM_AAVM_FIRMWARE_VENDOR"),
            ("version", "KVM_AAVM_FIRMWARE_VERSION"),
            ("date", "KVM_AAVM_FIRMWARE_DATE"),
        ):
            value = firmware.get(field)
            if isinstance(value, str) and value and all(char not in value for char in "\x00\r\n\""):
                env[variable] = value
    if isinstance(board, dict):
        for field, variable in (
            ("manufacturer", "KVM_AAVM_BOARD_VENDOR"),
            ("product", "KVM_AAVM_BOARD_PRODUCT"),
        ):
            value = board.get(field)
            if isinstance(value, str) and value and all(char not in value for char in "\x00\r\n\""):
                env[variable] = value
    requested_jobs = env.get("KVM_AAVM_BUILD_JOBS", "").strip()
    if requested_jobs:
        if not requested_jobs.isdigit() or int(requested_jobs) < 1:
            raise AppError("KVM_AAVM_BUILD_JOBS must be a positive integer.")
    else:
        env["KVM_AAVM_BUILD_JOBS"] = str(min(os.cpu_count() or 1, DEFAULT_MAX_BUILD_JOBS))
    print(f"QEMU build parallelism: {env['KVM_AAVM_BUILD_JOBS']} job(s)")
    runner.run(["bash", "qemupatch.sh"], cwd=work, env=env)
    _validate_generated_vars(work / "vars.sh")
    _validate_qemu_firmware_hardening(work / "qemu")
    _validate_qemu_kvm_hypercall_hardening(work / "qemu")
    runner.run(["bash", "ovmfpatch.sh"], cwd=work, env=env)
    _validate_ovmf_firmware_identity(work / "ovmf", profile.get("identity_firmware"))
    _validate_ovmf_measured_boot(work / "ovmf")
    if (work / "vars.sh").exists():
        shutil.copy2(work / "vars.sh", vm_dir(vm_name) / f"vars-generation-{generation}.sh")
    expected = [
        output / "bin/qemu-system-x86_64", output / "bin/ssdt1.aml", output / "bin/ssdt2.aml",
        output / "ovmf/OVMF_CODE_4M.patched.qcow2", output / "ovmf/OVMF_VARS_4M.patched.qcow2",
    ]
    missing = [str(path) for path in expected if not path.exists()]
    if missing:
        raise AppError("Artifact build did not produce:\n- " + "\n- ".join(missing))
    profile["paths"].update({
        "qemu": str(output / "bin/qemu-system-x86_64"),
        "ovmf_code": str(output / "ovmf/OVMF_CODE_4M.patched.qcow2"),
        "ovmf_vars": str(output / "ovmf/OVMF_VARS_4M.patched.qcow2"),
        "ssdt": [str(output / "bin/ssdt1.aml"), str(output / "bin/ssdt2.aml")],
    })
    profile["artifact_generation"] = generation
    return profile
