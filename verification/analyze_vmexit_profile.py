#!/usr/bin/env python3
"""Classify AMD CPUID paths in a VMEXIT_PROFILE.sh aggregate report."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path


AMD_CPUID_EXIT = 114
AMD_DB_EXIT = 65
AMD_NPF_EXIT = 1024
MAP_ENTRY = re.compile(
    r"^@(?P<name>[a-zA-Z0-9_]+)\[(?P<keys>[^]]*)\]:\s*(?P<count>[0-9]+)\s*$"
)


def parse_maps(text: str) -> dict[str, Counter[tuple[int, ...]]]:
    maps: dict[str, Counter[tuple[int, ...]]] = {}
    for line in text.splitlines():
        match = MAP_ENTRY.match(line.strip())
        if match is None:
            continue
        keys = tuple(int(value.strip(), 0) for value in match.group("keys").split(","))
        maps.setdefault(match.group("name"), Counter())[keys] += int(match.group("count"))
    return maps


def analyze(path: Path) -> str:
    text = path.read_text(encoding="utf-8", errors="replace")
    npf_only = "profile_mode=npf" in text
    maps = parse_maps(text)
    exits = maps.get("kvm_exit", Counter())
    nested = maps.get("kvm_nested_vmexit", Counter())
    injected = maps.get("kvm_nested_vmexit_inject", Counter())
    cpuid = maps.get("kvm_cpuid", Counter())
    nested_l0 = maps.get("nested_cpuid_l0_emulation", Counter())
    nested_observed = maps.get("nested_cpuid_observed", Counter())
    nested_npf_gpas = maps.get("nested_npf_injected_gpa", Counter())
    nested_npf_details = maps.get("nested_npf_injected_detail", Counter())
    page_fault_details = maps.get("kvm_page_fault_detail", Counter())

    hardware = exits[(AMD_CPUID_EXIT,)]
    nested_events = nested[(AMD_CPUID_EXIT,)]
    emulated = sum(cpuid.values())
    correlated_l0 = sum(nested_l0.values())
    correlation_available = (
        not npf_only and "cpuid_path_correlation=enabled" in text
    )

    if npf_only:
        context = "NOT_COLLECTED_NPF_MODE"
    elif hardware == 0:
        context = "NO_CPUID_EXITS"
    elif nested_events == hardware:
        context = "ALL_HARDWARE_EXITS_FROM_L2"
    elif abs(nested_events - hardware) == 1:
        context = "ALL_HARDWARE_EXITS_FROM_L2_BOUNDARY_DELTA"
    elif nested_events > hardware:
        context = "TRACEPOINT_COUNT_MISMATCH"
    elif nested_events:
        context = "MIXED_L1_AND_L2_HARDWARE_EXITS"
    else:
        context = "NO_L2_HARDWARE_EXITS"

    if npf_only:
        forwarded_candidates = 0
        l0_percent = 0.0
        path_result = "NOT_COLLECTED_NPF_MODE"
    elif correlation_available:
        correlated_l0 = min(correlated_l0, nested_events)
        forwarded_candidates = max(nested_events - correlated_l0, 0)
        l0_percent = correlated_l0 * 100.0 / nested_events if nested_events else 0.0
        path_result = "CORRELATED"
    else:
        forwarded_candidates = 0
        l0_percent = 0.0
        path_result = "UNRESOLVED_LEGACY_PROFILE"

    lines = [
        "=== cpuid_path_analysis ===",
        f"cpuid_hardware_exits={hardware}",
        f"cpuid_l2_exit_events={nested_events}",
        f"kvm_cpuid_emulations={emulated}",
        f"cpuid_context={context}",
        f"cpuid_path_correlation={'available' if correlation_available else 'unavailable'}",
        f"cpuid_l2_l0_emulations={correlated_l0 if correlation_available else 'not_collected' if npf_only else 'unknown'}",
        f"cpuid_l2_forwarded_candidates={forwarded_candidates if correlation_available else 'not_collected' if npf_only else 'unknown'}",
        f"cpuid_l2_l0_emulation_percent={f'{l0_percent:.2f}' if correlation_available else 'not_collected' if npf_only else 'unknown'}",
        f"cpuid_path_result={path_result}",
        "=== nested_latency_path_analysis ===",
        f"db_hardware_exits={'not_collected' if npf_only else exits[(AMD_DB_EXIT,)]}",
        f"db_l2_exit_events={'not_collected' if npf_only else nested[(AMD_DB_EXIT,)]}",
        f"db_reflections_to_l1={'not_collected' if npf_only else injected[(AMD_DB_EXIT,)]}",
        f"npf_hardware_exits={'not_collected' if npf_only else exits[(AMD_NPF_EXIT,)]}",
        f"npf_l2_exit_events={'not_collected' if npf_only else nested[(AMD_NPF_EXIT,)]}",
        f"npf_reflections_to_l1={sum(nested_npf_gpas.values()) if npf_only else injected[(AMD_NPF_EXIT,)]}",
    ]
    for (function, index), count in cpuid.most_common(10):
        lines.append(
            f"cpuid_emulation_top=function=0x{function:x},index=0x{index:x},count={count}"
        )

    for (function, index), count in nested_l0.most_common(10):
        lines.append(
            f"nested_l0_top=function=0x{function:x},index=0x{index:x},count={count}"
        )

    for (function, index), count in nested_observed.most_common(10):
        lines.append(
            f"nested_observed_top=function=0x{function:x},index=0x{index:x},count={count}"
        )

    for (gpa,), count in nested_npf_gpas.most_common(10):
        lines.append(f"nested_npf_top=gpa=0x{gpa:x},count={count}")

    for (gpa, error_code), count in nested_npf_details.most_common(10):
        lines.append(
            f"nested_npf_detail_top=gpa=0x{gpa:x},error=0x{error_code:x},count={count}"
        )

    for (gpa, error_code), count in page_fault_details.most_common(10):
        lines.append(
            f"page_fault_detail_top=gpa=0x{gpa:x},error=0x{error_code:x},count={count}"
        )

    if npf_only:
        lines.append(
            "cpuid_conclusion=CPUID tracepoints were intentionally omitted in low-noise NPF mode"
        )
    elif not correlation_available:
        lines.append(
            "cpuid_conclusion=kvm_nested_vmexit is emitted before "
            "nested_svm_exit_special; this legacy report proves L2 hardware "
            "exits, not whether L0 handled or forwarded them"
        )
    elif context == "TRACEPOINT_COUNT_MISMATCH":
        lines.append(
            "cpuid_conclusion=nested exit count exceeds hardware exits; repeat with only "
            "win11 running"
        )
    elif hardware == 0:
        lines.append("cpuid_conclusion=no hardware CPUID exit was observed in this window")
    elif correlated_l0:
        lines.append(
            "cpuid_conclusion=correlation proves that some L2 CPUID exits reached "
            "the L0 cached CPUID handler before the next guest entry"
        )
    else:
        lines.append(
            "cpuid_conclusion=no observed L2 CPUID exit reached the L0 CPUID handler "
            "before the next guest entry; forwarding to L1 is the remaining candidate"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("profile", type=Path)
    args = parser.parse_args()
    if not args.profile.is_file():
        parser.error(f"profile does not exist: {args.profile}")
    print(analyze(args.profile))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
