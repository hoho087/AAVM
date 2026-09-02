from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .hardware import cpu_info
from .paths import OFFLINE_DIR, PROJECT_DIR, STATE_DIR
from .util import AppError, Runner, atomic_write, prompt_yes_no, require_root

MOK_CERTIFICATE = Path("/var/lib/shim-signed/mok/MOK.der")
MOK_PRIVATE_KEY = Path("/var/lib/shim-signed/mok/MOK.priv")
KERNEL_MOK_DIRECTORY = STATE_DIR / "secure-boot"
KERNEL_MOK_CERTIFICATE = KERNEL_MOK_DIRECTORY / "kernel-signing.der"
KERNEL_MOK_CERTIFICATE_PEM = KERNEL_MOK_DIRECTORY / "kernel-signing.pem"
KERNEL_MOK_PRIVATE_KEY = KERNEL_MOK_DIRECTORY / "kernel-signing.key"
KERNEL_MOK_COMMON_NAME = "KVM-AAVM Custom Kernel Signing"
KERNEL_SIGNING_HOOK = Path("/etc/kernel/postinst.d/kvm-aavm-sign-custom-kernel")
BOOT_DIR = Path("/boot")
NVIDIA_DKMS_SOURCE_ROOT = Path("/usr/src")


@dataclass(frozen=True)
class KernelProfile:
    """An offline, version-pinned linux-tkg build target."""

    key: str
    label: str
    tkg_version: str
    source_relpath: str
    patch_dirname: str
    patch_suffix: str
    expected_version: tuple[int, int]
    test_release: bool = False


KERNEL_PROFILES = {
    "stable": KernelProfile(
        key="stable",
        label="Linux 6.19 stable deployment kernel",
        tkg_version="6.19-latest",
        source_relpath="sources/linux",
        patch_dirname="linux619-tkg-userpatches",
        patch_suffix="619",
        expected_version=(6, 19),
    ),
    "test-7.2": KernelProfile(
        key="test-7.2",
        label="Linux 7.2.2 experimental HVCI/VBS kernel",
        tkg_version="v7.2.2",
        source_relpath="sources/linux-7.2",
        patch_dirname="linux72-tkg-userpatches",
        patch_suffix="72-test",
        expected_version=(7, 2),
        test_release=True,
    ),
}


def kernel_profile(key: str = "stable") -> KernelProfile:
    try:
        return KERNEL_PROFILES[key]
    except KeyError as exc:
        raise AppError(f"未知的核心 profile：{key}") from exc


def _kernel_source_metadata(source: Path) -> tuple[tuple[int, int], str | None]:
    makefile = source / "Makefile"
    if not makefile.is_file():
        raise AppError(f"Linux source is missing Makefile: {makefile}")
    text = makefile.read_text(encoding="utf-8", errors="replace")
    values: dict[str, str] = {}
    for key in ("VERSION", "PATCHLEVEL", "SUBLEVEL", "EXTRAVERSION"):
        match = re.search(rf"^{key}\s*=\s*(\d+)", text, re.MULTILINE)
        if key in {"VERSION", "PATCHLEVEL"} and match is None:
            raise AppError(f"Linux source Makefile is missing {key}: {makefile}")
        if match is not None:
            values[key] = match.group(1)
        elif key == "EXTRAVERSION":
            # Do not let ``\s*`` consume the newline after an empty
            # EXTRAVERSION and accidentally capture the following Makefile
            # assignment (stable point releases leave this field blank).
            extra = re.search(r"^EXTRAVERSION[ \t]*=[ \t]*(.*)$", text, re.MULTILINE)
            values[key] = extra.group(1).strip() if extra else ""
        else:
            values[key] = "0"
    version = (int(values["VERSION"]), int(values["PATCHLEVEL"]))
    release = f"{values['VERSION']}.{values['PATCHLEVEL']}.{values['SUBLEVEL']}{values['EXTRAVERSION']}"
    tag = None
    if values["EXTRAVERSION"].startswith("-rc"):
        # Linux release candidates use the kernel.org short tag form, e.g.
        # Makefile 7.2.0-rc7 -> git tag v7.2-rc7.
        tag = f"v{values['VERSION']}.{values['PATCHLEVEL']}-{values['EXTRAVERSION'][1:]}"
    elif not values["EXTRAVERSION"] and int(values["SUBLEVEL"]) > 0:
        # Stable point releases use the full tag, e.g. 7.2.2 -> v7.2.2.
        tag = f"v{release}"
    return version, tag


def _kernel_source_version(source: Path) -> tuple[int, int]:
    return _kernel_source_metadata(source)[0]


def _validate_kernel_source(profile: KernelProfile, source: Path) -> None:
    actual = _kernel_source_version(source)
    if actual != profile.expected_version:
        expected = ".".join(str(part) for part in profile.expected_version)
        got = ".".join(str(part) for part in actual)
        raise AppError(f"{profile.label} 需要 Linux {expected} source，收到 Linux {got}：{source}")
    if not profile.test_release:
        return
    _, source_tag = _kernel_source_metadata(source)
    if source_tag is None:
        raise AppError(
            "7.2 實驗 profile 需要可辨識的固定 release tag source；"
            f"實際版本無法辨識：{source}"
        )
    if source_tag != profile.tkg_version:
        raise AppError(
            f"7.2 實驗 profile 固定使用 {profile.tkg_version}，收到 {source_tag}：{source}"
        )
    tag = ""
    # A tarball lives inside the deployer repository and must not accidentally
    # inherit a tag from a parent .git directory.
    if (source / ".git").exists():
        describe = subprocess.run(
            ["git", "-C", str(source), "describe", "--tags", "--exact-match"],
            check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        tag = describe.stdout.strip()
    if tag and tag != source_tag:
        raise AppError(
            f"7.2 source 的 git tag ({tag}) 與 Makefile 版本 ({source_tag}) 不一致：{source}"
        )


def _kernel_patch(profile: KernelProfile) -> Path:
    vendor = "amd" if cpu_info()["vendor"] == "amd" else "intel"
    patch = PROJECT_DIR / f"{vendor}{profile.patch_suffix}.mypatch"
    if not patch.is_file():
        if profile.test_release:
            raise AppError(
                f"{profile.label} 尚未提供 CPU 對應補丁：{patch.name}。"
                "不能把 6.19 補丁直接套到 7.2；請先完成該版本的 port。"
            )
        raise AppError(f"找不到自訂核心補丁：{patch}")
    return patch


def _validate_hypercall_patch(patch: Path) -> None:
    """Require native-invalid hypercalls so VMAware sees the bare-metal #UD."""
    text = patch.read_text(encoding="utf-8", errors="replace")
    if "SVM_EXIT_VMMCALL" in text:
        marker = "SVM_EXIT_VMMCALL"
    elif "EXIT_REASON_VMCALL" in text:
        marker = "EXIT_REASON_VMCALL"
    else:
        raise AppError(
            f"核心補丁缺少 VMCALL/VMMCALL exit handler：{patch.name}。"
        )
    handler = re.compile(
        rf"\[\s*{re.escape(marker)}\s*\]\s*=\s*kvm_handle_invalid_op\b",
        re.MULTILINE,
    )
    if handler.search(text) is None:
        raise AppError(
            f"核心補丁 {patch.name} 未將 {marker} 導向 kvm_handle_invalid_op；"
            "拒絕建置會暴露 KVM hypercall interception 的核心。"
        )


def _validate_amd_cpuid_virtualization_patch(patch: Path) -> None:
    """Require the Linux 7.2 CPUID/#DB and nested-NPF guarded fastpaths.

    Firmware and early Windows bring-up retain KVM CPUID virtualization.  A
    non-confidential L1 may pass CPUID through only after a jiffies-based reset
    grace period, or when it has successfully enabled SVM.  Nested VMCB02 keeps
    the architectural OR-merged L0/L1 intercepts, so this policy must not
    rewrite the hardware intercept from a CPL snapshot.  L2 leaf 0 is handled
    from a precomputed KVM CPUID cache in the IRQ-off VM-Exit fastpath; all
    other leaves retain normal L1 ownership.  The nested special handler is
    retained as the correctness fallback when fastpath emulation is disallowed.
    """
    if not patch.name.startswith("amd"):
        return
    text = patch.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    added_cpuid = [
        line for line in lines
        if line.startswith("+") and not line.startswith("+++")
        and "INTERCEPT_CPUID" in line
    ]
    added_text = "\n".join(
        line[1:] for line in lines
        if line.startswith("+") and not line.startswith("+++")
    )
    patch_context = "\n".join(
        line[1:] for line in lines
        if line.startswith(("+", " ")) and not line.startswith("+++")
    )
    recalc_gated = re.findall(
        r"if \(svme \|\| svm->cpuid_native_armed\)\s*\n"
        r"\s*svm_clr_intercept\(svm, INTERCEPT_CPUID\);\s*\n"
        r"\s*else\s*\n"
        r"\s*svm_set_intercept\(svm, INTERCEPT_CPUID\);",
        added_text,
    )
    init_gated = re.findall(
        r"if \(\(vcpu->arch\.efer & EFER_SVME\) \|\| svm->cpuid_native_armed\)\s*\n"
        r"\s*svm_clr_intercept\(svm, INTERCEPT_CPUID\);\s*\n"
        r"\s*else\s*\n"
        r"\s*svm_set_intercept\(svm, INTERCEPT_CPUID\);",
        added_text,
    )
    nested_l1_efer = re.findall(
        r"if \(is_guest_mode\(vcpu\)\)\s*\n"
        r"\s*svme = svm->vmcb01\.ptr->save\.efer & EFER_SVME;",
        added_text,
    )
    sticky_arm = (
        "bool cpuid_native_armed;" in added_text
        and "svm->cpuid_native_armed = true;" in added_text
        and "svm->cpuid_native_armed = false;" in added_text
    )
    delayed_vmcbo1_handoff = all(marker in added_text for marker in (
        "#define KVM_AAVM_CPUID_NATIVE_GRACE_MS\t30000",
        "unsigned long cpuid_native_deadline;",
        "jiffies + msecs_to_jiffies(KVM_AAVM_CPUID_NATIVE_GRACE_MS);",
        "static void svm_maybe_enable_cpuid_passthrough(struct kvm_vcpu *vcpu)",
        "svm_maybe_enable_cpuid_passthrough(vcpu);",
    )) and re.search(
        r"static void svm_maybe_enable_cpuid_passthrough"
        r"\(struct kvm_vcpu \*vcpu\)"
        r"[\s\S]{0,2200}?if \(svm->cpuid_native_armed \|\| is_guest_mode\(vcpu\) \|\|"
        r"[\s\S]{0,300}?is_sev_guest\(vcpu\) \|\|"
        r"[\s\S]{0,300}?time_before\(jiffies, svm->cpuid_native_deadline\)\)"
        r"[\s\S]{0,300}?svm->cpuid_native_armed = true;"
        r"[\s\S]{0,300}?svm_clr_intercept\(svm, INTERCEPT_CPUID\);",
        added_text,
    ) is not None
    nested_arm_sev_safe = re.findall(
        r"if \(!is_sev_guest\(vcpu\)\)\s*"
        r"\n\s*svm->cpuid_native_armed = true;",
        added_text,
    )
    nested_leaf0 = re.findall(
        r"case SVM_EXIT_CPUID:\s*\n"
        r"[\s\S]{0,800}?"
        r"if \(kvm_rax_read\(vcpu\) == 0\)\s*\n"
        r"\s*return NESTED_EXIT_HOST;",
        added_text,
    )
    nested_leaf0_fastpath = re.findall(
        r"static fastpath_t handle_fastpath_nested_cpuid0"
        r"[\s\S]{0,2000}?kvm_pmu_is_fastpath_emulation_allowed\(vcpu\)"
        r"[\s\S]{0,500}?kvm_is_cpuid_allowed\(vcpu\)"
        r"[\s\S]{0,1000}?EXIT_FASTPATH_REENTER_GUEST;",
        added_text,
    )
    nested_leaf0_cache = re.findall(
        r"entry = kvm_find_cpuid_entry\(vcpu, 0\);"
        r"[\s\S]{0,800}?svm->cpuid0\.valid = true;",
        added_text,
    )
    nested_leaf0_short_reentry = all(marker in added_text for marker in (
        "static __always_inline bool svm_vcpu_exit_request",
        "xfer_to_guest_mode_prepare();",
        "aavm_nested_cpuid0_reenter:",
        "svm_vcpu_exit_request(vcpu)",
        "goto aavm_nested_cpuid0_reenter;",
    ))
    nested_leaf0_direct_skip = re.findall(
        r"static fastpath_t handle_fastpath_nested_cpuid0"
        r"[\s\S]{0,2500}?X86_EFLAGS_TF"
        r"[\s\S]{0,1200}?kvm_rip_write\(vcpu, control->next_rip\);"
        r"[\s\S]{0,500}?control->int_state &= ~SVM_INTERRUPT_SHADOW_MASK;",
        added_text,
    )
    nested_leaf0_deferred_tail = all(marker in added_text for marker in (
        "svm_can_defer_nested_cpuid0_exit_tail",
        "control->exit_int_info & SVM_EXITINTINFO_VALID",
        "control->event_inj & SVM_EVTINJ_VALID",
        "!kvm_event_needs_reinjection(vcpu)",
        "nested_svm_virtualize_tpr(vcpu)",
        "control->tlb_ctl == TLB_CONTROL_DO_NOTHING",
        "msr_write_intercepted(svm, MSR_AMD64_PERF_CNTR_GLOBAL_CTL)",
        "kvm_clear_available_registers(vcpu, SVM_REGS_LAZY_LOAD_SET)",
        "aavm_nested_cpuid0_finish_full_tail:",
    ))
    amd_cpuid_signature_mask = (
        "AMD/Hygon reserve the Intel mitigation bits in CPUID.7.0.EDX." in patch_context
        and re.search(
            r"if \(function == 7 && index == 0 && vcpu->arch\.is_amd_compatible\)\s*"
            r"\n\s*\*edx &= ~\(BIT\(26\) \| BIT\(27\) \| BIT\(31\)\);"
            r"[\s\S]{0,300}?trace_kvm_cpuid\(orig_function, index, \*eax, \*ebx, \*ecx, \*edx, exact,",
            patch_context,
        ) is not None
    )
    nested_db_direct_reflection = re.findall(
        r"exit_code == SVM_EXIT_EXCP_BASE \+ DB_VECTOR"
        r"[\s\S]{0,500}?vmcb12_is_intercept\(&svm->nested\.ctl, exit_code\)"
        r"[\s\S]{0,900}?kvm_deliver_exception_payload\(vcpu, &db\);"
        r"[\s\S]{0,500}?nested_svm_vmexit\(svm\);"
        r"\s*return NESTED_EXIT_DONE;",
        added_text,
    )
    nested_npf_value_cache = any(marker in added_text for marker in (
        "nested_svm_cache_nonpresent_npf",
        "nested_svm_try_cached_npf_exit",
        "npf_cache[4]",
    ))
    nested_vmcb02_merge_note = all(marker in added_text for marker in (
        "KVM-AAVM: CPUID remains governed by the architectural L0/L1 merge.",
        "VMCB01 and VMCB12 both leave the global bit clear",
        "Do not add a direct VMCB02 clear here",
    ))
    vmcb12_map_reuse = all(marker in added_text for marker in (
        "struct kvm_host_map vmcb12_map;",
        "nested_svm_release_vmcb12_map",
        "svm->nested.vmcb12_map_generation != generation",
        "map->gfn != gpa_to_gfn(svm->nested.vmcb12_gpa)",
    ))
    problems = []
    if len(recalc_gated) != 1 or len(init_gated) != 1 or not sticky_arm:
        problems.append(
            "必須在 recalc/init_vmcb 使用 EFER.SVME 加 sticky arm 控制 VMCB01 CPUID intercept"
        )
    if not delayed_vmcbo1_handoff or len(nested_arm_sev_safe) != 1:
        problems.append(
            "必須保留以 jiffies reset grace 驅動、排除 SEV/L2 的 VMCB01 CPUID handoff"
        )
    if len(nested_l1_efer) != 1:
        problems.append("nested active 時必須使用 VMCB01 保存的 L1 EFER.SVME")
    if len(nested_leaf0) != 1:
        problems.append("必須保留 nested L2 CPUID leaf 0 的 L0 fallback handler")
    if len(nested_leaf0_fastpath) != 1:
        problems.append("必須以 PMU/CPUID-fault safe IRQ-off fastpath 處理 nested leaf 0")
    if len(nested_leaf0_cache) != 1:
        problems.append("必須在 set_cpuid 後預先快取 leaf 0，不得在 IRQ-off 路徑查表")
    if not nested_leaf0_short_reentry:
        problems.append("必須保留 request boundary 的 SVM nested leaf-0 short re-entry")
    if len(nested_leaf0_direct_skip) != 1:
        problems.append("nested leaf 0 必須以 TF/PMU guard 直接提交 NRIPS 與 interrupt-shadow")
    if not nested_leaf0_deferred_tail:
        problems.append("必須保留事件/PMU/TLB guard 與完整狀態回存的 leaf-0 deferred exit-tail")
    if not amd_cpuid_signature_mask:
        problems.append("AMD guest 的 CPUID leaf 7 EDX 必須清除 Intel mitigation bits 26/27/31")
    if len(nested_db_direct_reflection) != 1:
        problems.append("必須保留 debugger/NMI fallback 的 nested #DB 同輪直接反射")
    if nested_npf_value_cache:
        problems.append("不得保留已量測為負收益的 nested NPF value cache")
    if not nested_vmcb02_merge_note:
        problems.append("必須保留 VMCB02 的上游 L0/L1 CPUID OR 合併說明")
    if not vmcb12_map_reuse:
        problems.append("必須保留單次 nested run、generation-checked 的 VMCB12 map reuse")
    if not re.search(r"trace_kvm_cpuid\(0, (?:index|kvm_ecx_read\(vcpu\))", added_text) or \
            "EXPORT_TRACEPOINT_SYMBOL_GPL(kvm_cpuid);" not in added_text:
        problems.append("必須匯出並保留 kvm_cpuid tracepoint，以驗證 fastpath 實際命中")
    added_cpuid_ops = re.findall(
        r"svm_(?:set|clr)_intercept\(svm, INTERCEPT_CPUID\);",
        added_text,
    )
    if len(added_cpuid_ops) != 5:
        problems.append("CPUID intercept 變更數量不符 Linux 7.2 policy")
    if re.search(
        r"\bnative_cpuid\b|guest_cpu_cap_has\(vcpu, X86_FEATURE_SVM\)",
        added_text,
    ):
        problems.append("不得因 guest 隱藏 SVM 而讓 VMCB01 原生執行 CPUID")
    direct_vmcb02_cpuid = re.search(
        r"vmcb_(?:set|clr)_intercept\(\s*(?:&\s*)?"
        r"(?:vmcb02\b|[^,\n]*->nested\.vmcb02)[^\n]*,\s*"
        r"INTERCEPT_CPUID\s*\)",
        added_text,
    )
    cpl_cpuid_policy = re.search(
        r"(?:vmcb02->save\.cpl|nested\.save\.cpl|save\.cpl)"
        r"[\s\S]{0,500}?(?:INTERCEPT_CPUID|CPUID)",
        added_text,
        re.IGNORECASE,
    )
    if direct_vmcb02_cpuid or cpl_cpuid_policy or re.search(
        r"vmcb_(?:set|clr)_intercept\([^\n]*INTERCEPT_CPUID",
        added_text,
    ):
        problems.append("nested VMCB02 不得改寫 CPUID intercept，必須保留 L0/L1 merged ownership")
    if "kvm_rax_read(vcpu) == 0" in added_text and "kvm_emulate_cpuid(vcpu)" in added_text:
        problems.append("不得在 svm_handle_exit 繞過 L1 的 nested CPUID exit")
    if "kvm_hv_hypercall_enabled(vcpu)" in added_text:
        problems.append("不得依賴 L2 Hyper-V hypercall state")
    if "svm_is_intercept" in added_text:
        problems.append("不得加入動態 CPUID intercept 探測")
    if problems:
        raise AppError(
            f"核心補丁 {patch.name} 的 CPUID intercept 路徑不符合 Linux 7.2 policy："
            + "；".join(problems)
        )
    dynamic_markers = (
        "KVM_AAVM_NATIVE_CPUID_PORT",
        "KVM_AAVM_NATIVE_CPUID_MAGIC",
        "native_cpuid_active",
        "ExitBootServices",
    )
    present = [marker for marker in dynamic_markers if marker in text]
    if present:
        raise AppError(
            f"核心補丁 {patch.name} 仍包含動態 CPUID 切換："
            + ", ".join(present)
        )


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


def _patch_nvidia_dkms_for_linux_72() -> list[Path]:
    """Port the NVIDIA 595.x process-name helper to Linux 7.2.

    Linux 7.2 no longer declares the deprecated kernel ``strncpy`` helper.
    NVIDIA 595.84 still calls it, so DKMS fails before the custom kernel
    package can finish configuring.  Keep this narrowly scoped to the exact
    call and preserve the vendor source metadata for package updates.
    """
    replacements = {
        "nvidia/os-interface.c": (
            ("strncpy(buf, current->comm, len - 1);", "strscpy(buf, current->comm, len);"),
        ),
        "nvidia/linux_nvswitch.c": (
            (
                "strncpy(regkey_val, regkey_val_start, regkey_val_len);",
                "strscpy(regkey_val, regkey_val_start, regkey_val_len + 1);",
            ),
            ("return strncpy(dest, src, length);", "strscpy(dest, src, length); return dest;"),
        ),
        "nvidia-modeset/nvidia-modeset-linux.c": (
            ("return strncpy(dest, src, n);", "strscpy(dest, src, n); return dest;"),
        ),
        "nvidia-uvm/uvm_pmm_gpu.c": (
            (
                'strncpy(chunk_split_cache[level].name, "uvm_gpu_chunk_t", '
                'sizeof(chunk_split_cache[level].name) - 1);',
                'strscpy(chunk_split_cache[level].name, "uvm_gpu_chunk_t", '
                'sizeof(chunk_split_cache[level].name));',
            ),
        ),
    }
    patched: list[Path] = []
    for source in sorted(NVIDIA_DKMS_SOURCE_ROOT.glob("nvidia-*")):
        for relative, entries in replacements.items():
            target = source / relative
            if not target.is_file():
                continue
            text = target.read_text(encoding="utf-8", errors="replace")
            updated = text
            for old, new in entries:
                updated = updated.replace(old, new, 1)
            if updated == text:
                continue
            backup = target.with_name(f"{target.name}.kvm-aavm.orig")
            if not backup.exists():
                shutil.copy2(target, backup)
            stat = target.stat()
            fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    stream.write(updated)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.chmod(temporary, stat.st_mode & 0o7777)
                try:
                    os.chown(temporary, stat.st_uid, stat.st_gid)
                except PermissionError:
                    pass
                os.replace(temporary, target)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            patched.append(target)
    return patched


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


def _prepare_kernel_mirror(runner: Runner, source: Path, mirror: Path, tag: str) -> None:
    """Create the local mirror linux-tkg expects, including tarball sources."""
    if (source / ".git").is_dir():
        runner.run(["git", "clone", "--bare", str(source), str(mirror)])
        runner.run(["git", "--git-dir", str(mirror), "tag", "-f", tag])
        return
    runner.run(["git", "init", "--bare", str(mirror)])
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "KVM-AAVM offline source",
        "GIT_AUTHOR_EMAIL": "kvm-aavm@localhost",
        "GIT_COMMITTER_NAME": "KVM-AAVM offline source",
        "GIT_COMMITTER_EMAIL": "kvm-aavm@localhost",
    }
    runner.run([
        "git", "--git-dir", str(mirror), "--work-tree", str(source), "add", "-A",
    ], env=env)
    runner.run([
        "git", "--git-dir", str(mirror), "--work-tree", str(source),
        "commit", "--allow-empty", "-m", f"Import offline Linux source {tag}",
    ], env=env)
    runner.run(["git", "--git-dir", str(mirror), "tag", "-f", tag], env=env)


def build_kernel(runner: Runner, profile_key: str = "stable") -> None:
    require_root()
    profile = kernel_profile(profile_key)
    source = OFFLINE_DIR / "sources/linux-tkg"
    linux = OFFLINE_DIR / profile.source_relpath
    if not source.is_dir():
        raise AppError(f"Offline linux-tkg source is missing: {source}")
    if not linux.is_dir():
        if profile.test_release:
            raise AppError(
                f"找不到 Linux 7.2.2 測試核心離線 source：{linux}。"
                "請在準備部署包的連網 Ubuntu 上執行 tools/prepare_offline.sh，"
                "再把完整 offline 目錄帶到這台機器。"
            )
        raise AppError(f"Offline Linux source is missing: {linux}")
    _validate_kernel_source(profile, linux)
    patch = _kernel_patch(profile)
    _validate_hypercall_patch(patch)
    if profile.test_release and patch.name.startswith("amd"):
        _validate_amd_cpuid_virtualization_patch(patch)
    work = STATE_DIR / f"kernel-build/{profile.key}"
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(source, work, symlinks=True)
    # Keep the source immutable and make a local bare mirror for linux-tkg's
    # offline worktree setup.  This also imports tarball sources without
    # requiring a .git directory and prevents any network fetch.
    _, source_tag = _kernel_source_metadata(linux)
    mirror_tag = source_tag if profile.test_release else "v6.19"
    _prepare_kernel_mirror(runner, linux, work / "linux-kernel.git", mirror_tag or profile.tkg_version)
    secure_boot = _secure_boot_enabled(runner)
    if secure_boot:
        _ensure_kernel_mok(runner)
        _install_kernel_signing_hook()
    cfg = work / "customization.cfg"
    text = cfg.read_text(encoding="utf-8")
    options = {
        "_distro": "Ubuntu", "_version": profile.tkg_version, "_offline": "true",
        "_menunconfig": "false",
        "_diffconfig": "false", "_cpusched": "eevdf", "_compiler": "gcc",
        "_processor_opt": "native", "_timer_freq": "1000", "_tickless": "2",
        "_acs_override": "false",
        "_install_after_building": "no", "_user_patches_no_confirm": "true",
        "_config_fragments_no_confirm": "true",
    }
    for key, value in options.items():
        text = _set_cfg(text, key, value)
    cfg.write_text(text, encoding="utf-8")
    (work / "kvm-aavm-ubuntu.myfrag").write_text(
        _ubuntu_kernel_fragment(), encoding="utf-8",
    )
    patch_dir = work / profile.patch_dirname
    patch_dir.mkdir(exist_ok=True)
    shutil.copy2(patch, patch_dir / patch.name)
    runner.run(["bash", "install.sh", "install"], cwd=work, env={**os.environ, "_distro": "Ubuntu"})
    debs = sorted((work / "DEBS").glob("*.deb"))
    if not debs:
        raise AppError("linux-tkg did not produce Ubuntu DEB packages.")
    if profile.test_release:
        patched = _patch_nvidia_dkms_for_linux_72()
        if patched:
            print("已套用 Linux 7.2 的 NVIDIA DKMS strscpy 相容修補：")
            for path in patched:
                print(f"  - {path}")
    # Rebuilds can produce an older Debian revision for the same kernel ABI.
    # These are explicit local artifacts, so allow APT to replace a newer
    # installed revision with the requested build instead of failing under
    # its default downgrade protection.
    runner.run([
        "apt-get", "install", "-y", "--reinstall", "--allow-downgrades",
        "--allow-change-held-packages", *debs,
    ])
    # Validate exactly the non-debug image package produced by this build.
    # Older recovery kernels can intentionally have a different LSM policy and
    # must not make an otherwise valid new profile fail after APT installed it.
    image_debs = [
        deb for deb in debs
        if deb.name.startswith("linux-image-") and "-dbg_" not in deb.name
    ]
    if len(image_debs) != 1:
        raise AppError("linux-tkg 產物無法唯一辨識非 debug 核心映像套件。")
    built_version = image_debs[0].name.split("_", 1)[0].removeprefix("linux-image-")
    _validate_tkg_boot_config(built_version)
    if secure_boot:
        _sign_installed_tkg_kernels(runner)
    _prepare_tkg_external_modules(runner, secure_boot)
    if secure_boot:
        _queue_kernel_mok_enrollment(runner)
    runner.run(["update-initramfs", "-u", "-k", "all"])
    runner.run(["update-grub"])
    print(f"已建置並安裝 {profile.label}。穩定 Ubuntu 核心仍保留為回復入口。")


def cleanup_kernel_build(runner: Runner, profile_key: str = "test-7.2") -> None:
    """Remove completed kernel source worktrees while retaining recovery DEBs."""
    require_root()
    profile = kernel_profile(profile_key)
    work = STATE_DIR / f"kernel-build/{profile.key}"
    targets = [work / "linux-src-git", work / "linux-kernel.git"]
    existing = [path for path in targets if path.is_dir()]
    if not existing:
        print(f"沒有可清理的 {profile.label} 建置 source。")
        return
    print("將刪除以下已完成建置的暫存 source/mirror（保留 DEBS 與已安裝核心）：")
    for path in existing:
        print(f"  - {path}")
    if not prompt_yes_no("確認清理這些建置暫存", False):
        print("已取消清理。")
        return
    for path in existing:
        shutil.rmtree(path)
    runner.run(["apt-get", "clean"])
    print("核心建置暫存已清理；DEBS、DKMS、/boot 核心與離線 source 均保留。")


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
