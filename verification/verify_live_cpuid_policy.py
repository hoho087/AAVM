#!/usr/bin/env python3
"""Read-only checks for Linux 7.2 AMD CPUID/#DB and nested-NPF fastpaths."""

from __future__ import annotations

import hashlib
import re
import struct
import subprocess
import sys
from pathlib import Path


SOURCE_ROOT = Path("/var/lib/kvm-aavm/kernel-build/test-7.2/linux-src-git")
SVM_SOURCE = SOURCE_ROOT / "arch/x86/kvm/svm/svm.c"
SVM_HEADER = SOURCE_ROOT / "arch/x86/kvm/svm/svm.h"
NESTED_SOURCE = SOURCE_ROOT / "arch/x86/kvm/svm/nested.c"
X86_SOURCE = SOURCE_ROOT / "arch/x86/kvm/x86.c"
CPUID_SOURCE = SOURCE_ROOT / "arch/x86/kvm/cpuid.c"
BUILT_MODULE = SOURCE_ROOT / "arch/x86/kvm/kvm-amd.ko"
LOADED_BUILD_ID_NOTE = Path("/sys/module/kvm_amd/notes/.note.gnu.build-id")


def run(*args: str) -> str:
    result = subprocess.run(args, check=True, text=True, capture_output=True)
    return result.stdout.strip()


def run_optional(*args: str) -> str:
    result = subprocess.run(args, check=False, text=True, capture_output=True)
    if result.returncode:
        detail = result.stderr.strip().splitlines()
        return f"unavailable ({detail[-1] if detail else 'command failed'})"
    return result.stdout.strip()


def read_sysfs(path: str) -> str:
    return Path(path).read_text(encoding="utf-8").strip()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def loaded_build_id(path: Path) -> str:
    """Return the GNU build ID exposed by sysfs for the loaded module."""
    note = path.read_bytes()
    if len(note) < 16:
        raise ValueError("truncated GNU build-id note")
    namesz, descsz, note_type = struct.unpack_from("=III", note)
    name_end = 12 + namesz
    desc_start = (name_end + 3) & ~3
    desc_end = desc_start + descsz
    if note_type != 3 or note[12:name_end].rstrip(b"\0") != b"GNU" or desc_end > len(note):
        raise ValueError("invalid GNU build-id note")
    return note[desc_start:desc_end].hex()


def elf_build_id(path: Path) -> str:
    output = run("readelf", "-n", str(path))
    match = re.search(r"Build ID:\s*([0-9a-fA-F]+)", output)
    if match is None:
        raise ValueError(f"GNU build ID missing from {path}")
    return match.group(1).lower()


def source_release(source_root: Path) -> str:
    """Read the release encoded by the source tree's top-level Makefile."""
    makefile = source_root / "Makefile"
    text = makefile.read_text(encoding="utf-8", errors="replace")
    values: dict[str, str] = {}
    for key in ("VERSION", "PATCHLEVEL", "SUBLEVEL", "EXTRAVERSION"):
        match = re.search(rf"^{key}[ \t]*=[ \t]*(.*)$", text, re.MULTILINE)
        if match is None:
            raise ValueError(f"{key} is missing from {makefile}")
        values[key] = match.group(1).strip()
    return f"{values['VERSION']}.{values['PATCHLEVEL']}.{values['SUBLEVEL']}{values['EXTRAVERSION']}"


def main() -> int:
    failures: list[str] = []

    if (not (SOURCE_ROOT / "Makefile").is_file() or
            not SVM_SOURCE.is_file() or not SVM_HEADER.is_file() or
            not NESTED_SOURCE.is_file() or not X86_SOURCE.is_file() or
            not CPUID_SOURCE.is_file()):
        print("svm_source=missing")
        print("svm_header=missing")
        print("nested_source=missing")
        print("x86_source=missing")
        print("cpuid_source=missing")
        print("result=FAIL")
        print(
            "FAIL: patched Linux 7.2 source tree is missing",
            file=sys.stderr,
        )
        return 1

    kernel = run("uname", "-r")
    loaded = read_sysfs("/sys/module/kvm_amd/srcversion")
    module = Path(run("modinfo", "-n", "kvm_amd"))
    vermagic = run("modinfo", "-F", "vermagic", "kvm_amd")
    nested = read_sysfs("/sys/module/kvm_amd/parameters/nested")
    npt = read_sysfs("/sys/module/kvm_amd/parameters/npt")
    avic = read_sysfs("/sys/module/kvm_amd/parameters/avic")
    vm_state = run_optional("virsh", "domstate", "win11").replace("\r", "").splitlines()[0]
    source_version = source_release(SOURCE_ROOT)
    live_build_id = loaded_build_id(LOADED_BUILD_ID_NOTE)
    built_build_id = elf_build_id(BUILT_MODULE) if BUILT_MODULE.is_file() else "missing"

    svm = SVM_SOURCE.read_text(encoding="utf-8")
    svm_header = SVM_HEADER.read_text(encoding="utf-8")
    nested_source = NESTED_SOURCE.read_text(encoding="utf-8")
    x86_source = X86_SOURCE.read_text(encoding="utf-8")
    cpuid_source = CPUID_SOURCE.read_text(encoding="utf-8")
    cpuid_vmcbo1_handoff = (
        "bool svme = vcpu->arch.efer & EFER_SVME;" in svm
        and "svme = svm->vmcb01.ptr->save.efer & EFER_SVME;" in svm
        and "bool cpuid_native_armed;" in svm_header
        and "unsigned long cpuid_native_deadline;" in svm_header
        and "#define KVM_AAVM_CPUID_NATIVE_GRACE_MS\t30000" in svm
        and "svm->cpuid_native_armed = true;" in svm
        and "svm->cpuid_native_armed = false;" in svm
        and "jiffies + msecs_to_jiffies(KVM_AAVM_CPUID_NATIVE_GRACE_MS);" in svm
        and "svme || svm->cpuid_native_armed" in svm
        and "(vcpu->arch.efer & EFER_SVME) || svm->cpuid_native_armed" in svm
        and "static void svm_maybe_enable_cpuid_passthrough(struct kvm_vcpu *vcpu)" in svm
        and "svm->cpuid_native_armed || is_guest_mode(vcpu) ||" in svm
        and "is_sev_guest(vcpu) ||" in svm
        and "time_before(jiffies, svm->cpuid_native_deadline)" in svm
        and re.search(
            r"if \(pre_svm_run\(vcpu\)\) \{[\s\S]{0,600}?\}\s*"
            r"svm_maybe_enable_cpuid_passthrough\(vcpu\);",
            svm,
        ) is not None
        and svm.count("svm_clr_intercept(svm, INTERCEPT_CPUID);") == 3
        and svm.count("svm_set_intercept(svm, INTERCEPT_CPUID);") == 2
        and "native_cpuid" not in svm
        and "else if (!guest_cpu_cap_has(vcpu, X86_FEATURE_SVM))" not in svm
    )
    no_vmcb02_clear = re.search(
        r"vmcb_(?:set|clr)_intercept\(\s*(?:&\s*)?vmcb02"
        r"[^\n]*,\s*INTERCEPT_CPUID\s*\)",
        nested_source,
    ) is None
    vmcb02_cpuid_merge = all(marker in nested_source for marker in (
        "vmcb02->control.intercepts[i] = vmcb01->control.intercepts[i];",
        "vmcb02->control.intercepts[i] |= vmcb12_ctrl->intercepts[i];",
    ))
    amd_cpuid_signature_mask = all(marker in cpuid_source for marker in (
        "AMD/Hygon reserve the Intel mitigation bits in CPUID.7.0.EDX.",
        "if (function == 7 && index == 0 && vcpu->arch.is_amd_compatible)",
        "*edx &= ~(BIT(26) | BIT(27) | BIT(31));",
    ))
    nested_leaf0 = bool(re.search(
        r"case SVM_EXIT_CPUID:\s*\n"
        r"[\s\S]{0,800}?"
        r"if \(kvm_rax_read\(vcpu\) == 0\)\s*\n"
        r"\s*return NESTED_EXIT_HOST;",
        nested_source,
    ))
    no_broad_nested_cpuid = not re.search(
        r"kvm_rax_read\(vcpu\)\s*(?:>=|<=|>|<)",
        nested_source,
    )
    nested_leaf0_fastpath = all(marker in svm for marker in (
        "handle_fastpath_nested_cpuid0",
        "kvm_pmu_is_fastpath_emulation_allowed(vcpu)",
        "kvm_is_cpuid_allowed(vcpu)",
        "kvm_find_cpuid_entry(vcpu, 0)",
        "trace_kvm_nested_vmexit(vcpu, KVM_ISA_SVM)",
        "EXIT_FASTPATH_REENTER_GUEST",
    )) and "} cpuid0;" in svm_header and \
        "EXPORT_TRACEPOINT_SYMBOL_GPL(kvm_cpuid);" in x86_source
    nested_leaf0_short_reentry = all(marker in svm for marker in (
        "static __always_inline bool svm_vcpu_exit_request",
        "xfer_to_guest_mode_prepare();",
        "aavm_nested_cpuid0_reenter:",
        "goto aavm_nested_cpuid0_reenter;",
    ))
    nested_leaf0_direct_skip = all(marker in svm for marker in (
        "svm->vmcb->save.rflags & X86_EFLAGS_TF",
        "kvm_rip_write(vcpu, control->next_rip);",
        "control->int_state &= ~SVM_INTERRUPT_SHADOW_MASK;",
    ))
    nested_leaf0_deferred_tail = all(marker in svm for marker in (
        "svm_can_defer_nested_cpuid0_exit_tail",
        "control->exit_int_info & SVM_EXITINTINFO_VALID",
        "control->event_inj & SVM_EVTINJ_VALID",
        "nested_svm_virtualize_tpr(vcpu)",
        "control->tlb_ctl == TLB_CONTROL_DO_NOTHING",
        "msr_write_intercepted(svm, MSR_AMD64_PERF_CNTR_GLOBAL_CTL)",
        "kvm_clear_available_registers(vcpu, SVM_REGS_LAZY_LOAD_SET)",
        "aavm_nested_cpuid0_finish_full_tail:",
    ))
    nested_db_direct_reflection = all(marker in nested_source for marker in (
        "exit_code == SVM_EXIT_EXCP_BASE + DB_VECTOR",
        "vmcb12_is_intercept(&svm->nested.ctl, exit_code)",
        "kvm_deliver_exception_payload(vcpu, &db);",
        "nested_svm_vmexit(svm);",
    ))
    nested_npf_value_cache = any(marker in nested_source for marker in (
        "nested_svm_cache_nonpresent_npf",
        "nested_svm_try_cached_npf_exit",
        "npf_cache[4]",
    )) or "nested_svm_try_cached_npf_exit(svm)" in svm
    vmcb12_map_reuse = all(marker in nested_source for marker in (
        "nested_svm_release_vmcb12_map",
        "struct kvm_host_map *map = &svm->nested.vmcb12_map;",
        "svm->nested.vmcb12_map_generation != generation",
        "map->gfn != gpa_to_gfn(svm->nested.vmcb12_gpa)",
    )) and all(marker in svm_header for marker in (
        "struct kvm_host_map vmcb12_map;",
        "u64 vmcb12_map_generation;",
    ))

    print(f"kernel={kernel}")
    print(f"source_release={source_version}")
    print(f"loaded_srcversion={loaded}")
    print(f"loaded_build_id={live_build_id}")
    print(f"built_build_id={built_build_id}")
    print(f"module={module}")
    print(f"module_sha256={sha256(module)}")
    print(f"vermagic={vermagic}")
    print(f"module_params=nested={nested},npt={npt},avic={avic}")
    print(f"vm_state={vm_state}")
    print(f"cpuid_vmcbo1_handoff={'present' if cpuid_vmcbo1_handoff else 'absent'}")
    print(f"svme_sticky_arm={'present' if 'cpuid_native_armed' in svm else 'absent'}")
    print(f"amd_cpuid_leaf7_signature_mask={'present' if amd_cpuid_signature_mask else 'absent'}")
    print(f"vmcb02_cpuid_clear={'absent' if no_vmcb02_clear else 'present'}")
    print(f"vmcb02_cpuid_merge={'present' if vmcb02_cpuid_merge else 'absent'}")
    print(f"nested_cpuid_leaf0_l0={'present' if nested_leaf0 else 'absent'}")
    print(f"nested_cpuid_leaf0_irqoff_fastpath={'present' if nested_leaf0_fastpath else 'absent'}")
    print(f"nested_cpuid_leaf0_short_reentry={'present' if nested_leaf0_short_reentry else 'absent'}")
    print(f"nested_cpuid_leaf0_direct_skip={'present' if nested_leaf0_direct_skip else 'absent'}")
    print(f"nested_cpuid_leaf0_deferred_tail={'present' if nested_leaf0_deferred_tail else 'absent'}")
    print(f"nested_db_direct_reflection={'present' if nested_db_direct_reflection else 'absent'}")
    print(f"nested_npf_value_cache={'present' if nested_npf_value_cache else 'absent'}")
    print(f"vmcb12_map_reuse={'present' if vmcb12_map_reuse else 'absent'}")
    print(f"nested_cpuid_broad_range={'absent' if no_broad_nested_cpuid else 'present'}")
    print(f"svm_source_sha256={sha256(SVM_SOURCE)}")
    print(f"svm_header_sha256={sha256(SVM_HEADER)}")
    print(f"nested_source_sha256={sha256(NESTED_SOURCE)}")
    print(f"x86_source_sha256={sha256(X86_SOURCE)}")
    print(f"cpuid_source_sha256={sha256(CPUID_SOURCE)}")

    if not re.match(r"^7\.2\.2-tkg(?:-[A-Za-z0-9_.+-]+)?$", kernel):
        failures.append("running kernel is not the stable 7.2.2-tkg build")
    if source_version != "7.2.2":
        failures.append(f"patched source tree is not Linux 7.2.2 (found {source_version})")
    if not vermagic.startswith(kernel + " "):
        failures.append("kvm_amd vermagic does not match the running kernel")
    if built_build_id == "missing":
        failures.append("built Linux 7.2 kvm-amd.ko is missing")
    elif live_build_id != built_build_id:
        failures.append("loaded kvm_amd build ID does not match the built Linux 7.2 module")
    if nested != "1":
        failures.append("kvm_amd nested parameter is not 1")
    if npt.upper() not in {"Y", "1"}:
        failures.append("kvm_amd npt parameter is disabled")
    if avic.upper() not in {"Y", "1"}:
        failures.append("kvm_amd avic parameter is disabled")
    if not cpuid_vmcbo1_handoff:
        failures.append("Linux 7.2 delayed VMCB01 CPUID handoff source markers are missing")
    if not amd_cpuid_signature_mask:
        failures.append("AMD CPUID leaf 7 EDX signature mask is missing")
    if not no_vmcb02_clear:
        failures.append("nested.c directly clears VMCB02 CPUID intercept")
    if not vmcb02_cpuid_merge:
        failures.append("nested.c is missing the upstream VMCB01/VMCB12 intercept OR merge")
    if not nested_leaf0:
        failures.append("nested.c is missing the measured L2 CPUID leaf-0 L0 route")
    if not nested_leaf0_fastpath:
        failures.append("svm.c/svm.h are missing the cached IRQ-off nested leaf-0 fastpath")
    if not nested_leaf0_short_reentry:
        failures.append("svm.c is missing the request-safe nested leaf-0 short re-entry")
    if not nested_leaf0_direct_skip:
        failures.append("svm.c is missing the TF/PMU-safe direct NRIPS leaf-0 skip")
    if not nested_leaf0_deferred_tail:
        failures.append("svm.c is missing the event-safe nested leaf-0 deferred exit tail")
    if not nested_db_direct_reflection:
        failures.append("nested.c is missing guarded same-pass nested #DB reflection")
    if nested_npf_value_cache:
        failures.append("the measured-regressive nested NPF value cache is still present")
    if not vmcb12_map_reuse:
        failures.append("nested.c/svm.h are missing generation-checked VMCB12 map reuse")
    if not no_broad_nested_cpuid:
        failures.append("nested.c contains a rejected broad CPUID leaf-range route")
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        print("result=FAIL")
        return 1
    print("result=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
