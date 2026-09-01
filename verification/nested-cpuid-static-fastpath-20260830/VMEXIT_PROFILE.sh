#!/usr/bin/env bash
set -euo pipefail

# Count KVM events in BPF maps. Unlike an enabled tracefs event, this does not
# stream tens of thousands of records per second into the tracing ring buffer.

TRACEFS=/sys/kernel/tracing
STATE_DIR=/run/kvm-aavm-vmexit-profile
BPFTRACE=${BPFTRACE:-/usr/bin/bpftrace}
GDB=${GDB:-/usr/bin/gdb}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ANALYZER="$SCRIPT_DIR/../analyze_vmexit_profile.py"
KVM_AMD_DEBUG=${KVM_AMD_DEBUG:-/var/lib/kvm-aavm/kernel-build/test-7.2/linux-src-git/arch/x86/kvm/kvm-amd.ko}

die() {
    echo "error=$*" >&2
    exit 2
}

require_root() {
    [ "$(id -u)" -eq 0 ] || die 'run as root'
    [ -x "$BPFTRACE" ] || die 'bpftrace unavailable'
    for event in kvm_entry kvm_exit kvm_nested_vmexit kvm_nested_vmexit_inject kvm_cpuid kvm_msr kvm_page_fault; do
        [ -r "$TRACEFS/events/kvm/$event/format" ] || die "tracepoint missing: $event"
    done
}

resolve_vcpu_regs_offset() {
    local built_id loaded_id offset
    [ -x "$GDB" ] || return 1
    [ -r "$KVM_AMD_DEBUG" ] || return 1
    [ -r /sys/module/kvm_amd/notes/.note.gnu.build-id ] || return 1
    built_id=$(readelf -n "$KVM_AMD_DEBUG" 2>/dev/null |
        awk '/Build ID:/ { print $3; exit }')
    loaded_id=$(od -An -v -tx1 -j16 /sys/module/kvm_amd/notes/.note.gnu.build-id |
        tr -d ' \n')
    [ -n "$built_id" ] && [ "$built_id" = "$loaded_id" ] || return 1
    offset=$("$GDB" -q -nx -batch "$KVM_AMD_DEBUG" \
        -ex 'p/x &((struct vcpu_svm *)0)->vcpu.arch.regs' 2>/dev/null |
        awk '/^\$1 = 0x[0-9a-fA-F]+$/ { print $3; exit }')
    case "$offset" in
        0x[0-9a-fA-F]*) printf '%d\n' "$((offset))" ;;
        *) return 1 ;;
    esac
}

append_cpuid_leaf_probe() {
    local regs_offset="$1"
    [ -n "$regs_offset" ] || return 0
    cat >> "$STATE_DIR/program.bt" <<BPF

/*
 * kvm_nested_vmexit fires before KVM decides whether L0 consumes CPUID or
 * reflects it to L1.  The leaf-0 IRQ-off fastpath never reaches this kprobe;
 * entries here identify the remaining generic nested CPUID path.  The register
 * offset is resolved from the exact loaded module's matching DWARF image.
 */
kprobe:nested_svm_exit_special
/@pending_nested_cpuid[tid]/
{
    @nested_cpuid_observed[*(uint64 *)(arg0 + $regs_offset),
                           *(uint64 *)(arg0 + $((regs_offset + 8)))] = count();
}
BPF
}

write_program() {
    local mode="$1" regs_offset="$2"
    if [ "$mode" = cpuid ]; then
        cat > "$STATE_DIR/program.bt" <<'BPF'
BEGIN
{
    printf("bpf_ready=1\n");
}

tracepoint:kvm:kvm_exit
/args.exit_reason == 114/
{
    @kvm_exit[args.exit_reason] = count();
}

tracepoint:kvm:kvm_nested_vmexit
/args.exit_reason == 114/
{
    @kvm_nested_vmexit[args.exit_reason] = count();
    @pending_nested_cpuid[tid] = 1;
}

tracepoint:kvm:kvm_cpuid
{
    @kvm_cpuid[args.function, args.index] = count();
    if (@pending_nested_cpuid[tid]) {
        @nested_cpuid_l0_emulation[args.function, args.index] = count();
        delete(@pending_nested_cpuid[tid]);
    }
}

tracepoint:kvm:kvm_entry
{
    delete(@pending_nested_cpuid[tid]);
}
BPF
        append_cpuid_leaf_probe "$regs_offset"
        return
    fi

    if [ "$mode" = npf ]; then
        cat > "$STATE_DIR/program.bt" <<'BPF'
BEGIN
{
    printf("bpf_ready=1\n");
}

/*
 * Low-noise nested-NPF stage profiler.  Keep the hardware-exit timestamp
 * until KVM re-enters L1, but only arm the detailed probes after the stock
 * MMU path has classified the fault as L1-owned.
 */
tracepoint:kvm:kvm_exit
/args.exit_reason == 1024/
{
    @nested_latency_start[tid] = nsecs;
    @nested_latency_gpa[tid] = args.info2;
}

tracepoint:kvm:kvm_nested_vmexit_inject
/args.exit_code == 1024/
{
    @nested_npf_injected_gpa[args.exit_info2] = count();
    @nested_npf_injected_detail[args.exit_info2, args.exit_info1] = count();
}

kprobe:nested_svm_inject_npf_exit
/@nested_latency_start[tid]/
{
    @nested_npf_l1_confirmed = count();
    @npf_exit_to_l1_confirmed_ns = hist(nsecs - @nested_latency_start[tid]);
    @nested_npf_l1_owned[tid] = 1;
}

kprobe:nested_svm_vmexit
/@nested_npf_l1_owned[tid]/
{
    @nested_vmexit_start[tid] = nsecs;
}

kretprobe:nested_svm_vmexit
/@nested_vmexit_start[tid]/
{
    @nested_vmexit_ns = hist(nsecs - @nested_vmexit_start[tid]);
    @nested_vmexit_done[tid] = nsecs;
    @nested_npf_post_vmexit[tid] = 1;
    delete(@nested_vmexit_start[tid]);
    delete(@nested_npf_l1_owned[tid]);
}

/* KVM_REQ_MMU_SYNC is serviced first in vcpu_enter_guest(). */
kprobe:kvm_mmu_sync_roots
/@nested_npf_post_vmexit[tid]/
{
    @mmu_sync_start[tid] = nsecs;
    @post_vmexit_mmu_sync_seen = count();
    @vmexit_done_to_mmu_sync_start_ns =
        hist(nsecs - @nested_vmexit_done[tid]);
}

kretprobe:kvm_mmu_sync_roots
/@mmu_sync_start[tid]/
{
    @mmu_sync_roots_ns = hist(nsecs - @mmu_sync_start[tid]);
    @mmu_sync_done[tid] = nsecs;
    delete(@mmu_sync_start[tid]);
}

/* KVM_REQ_TLB_FLUSH_CURRENT is serviced immediately after MMU sync. */
kprobe:kvm_service_local_tlb_flush_requests
/@nested_npf_post_vmexit[tid]/
{
    @local_tlb_start[tid] = nsecs;
    @post_vmexit_local_tlb_seen = count();
    @vmexit_done_to_local_tlb_start_ns =
        hist(nsecs - @nested_vmexit_done[tid]);
    if (@mmu_sync_done[tid]) {
        @mmu_sync_done_to_local_tlb_start_ns =
            hist(nsecs - @mmu_sync_done[tid]);
    }
}

kprobe:svm_flush_tlb_current
/@nested_npf_post_vmexit[tid]/
{
    @svm_tlb_flush_start[tid] = nsecs;
    @post_vmexit_svm_tlb_flush_seen = count();
    if (@local_tlb_start[tid]) {
        @local_tlb_start_to_svm_flush_start_ns =
            hist(nsecs - @local_tlb_start[tid]);
    }
}

kretprobe:svm_flush_tlb_current
/@svm_tlb_flush_start[tid]/
{
    @svm_flush_tlb_current_ns = hist(nsecs - @svm_tlb_flush_start[tid]);
    @svm_tlb_flush_done[tid] = nsecs;
    delete(@svm_tlb_flush_start[tid]);
}

kretprobe:kvm_service_local_tlb_flush_requests
/@local_tlb_start[tid]/
{
    @local_tlb_service_ns = hist(nsecs - @local_tlb_start[tid]);
    @local_tlb_done[tid] = nsecs;
    delete(@local_tlb_start[tid]);
}

tracepoint:kvm:kvm_entry
/@nested_npf_post_vmexit[tid]/
{
    @post_vmexit_entries = count();
    @nested_vmexit_done_to_entry_ns =
        hist(nsecs - @nested_vmexit_done[tid]);
    @nested_npf_exit_to_entry_ns[@nested_latency_gpa[tid]] =
        hist(nsecs - @nested_latency_start[tid]);
    if (@mmu_sync_done[tid]) {
        @mmu_sync_done_to_entry_ns = hist(nsecs - @mmu_sync_done[tid]);
    }
    if (@svm_tlb_flush_done[tid]) {
        @svm_tlb_flush_done_to_entry_ns =
            hist(nsecs - @svm_tlb_flush_done[tid]);
    }
    if (@local_tlb_done[tid]) {
        @local_tlb_done_to_entry_ns = hist(nsecs - @local_tlb_done[tid]);
    }
    delete(@nested_latency_start[tid]);
    delete(@nested_latency_gpa[tid]);
    delete(@nested_vmexit_done[tid]);
    delete(@nested_npf_post_vmexit[tid]);
    delete(@mmu_sync_start[tid]);
    delete(@mmu_sync_done[tid]);
    delete(@local_tlb_start[tid]);
    delete(@svm_tlb_flush_start[tid]);
    delete(@svm_tlb_flush_done[tid]);
    delete(@local_tlb_done[tid]);
}
BPF
        return
    fi

    cat > "$STATE_DIR/program.bt" <<'BPF'
BEGIN
{
    printf("bpf_ready=1\n");
}

tracepoint:kvm:kvm_exit
{
    @kvm_exit[args.exit_reason] = count();
    if (args.exit_reason == 65 || args.exit_reason == 1024) {
        @nested_latency_start[tid] = nsecs;
        @nested_latency_reason[tid] = args.exit_reason;
        if (args.exit_reason == 1024) {
            @nested_latency_gpa[tid] = args.info2;
        }
    }
}

tracepoint:kvm:kvm_nested_vmexit
{
    @kvm_nested_vmexit[args.exit_reason] = count();
    if (args.exit_reason == 114) {
        @pending_nested_cpuid[tid] = 1;
    }
}

tracepoint:kvm:kvm_nested_vmexit_inject
{
    @kvm_nested_vmexit_inject[args.exit_code] = count();
    if (args.exit_code == 1024) {
        @nested_npf_injected_gpa[args.exit_info2] = count();
        @nested_npf_injected_detail[args.exit_info2, args.exit_info1] = count();
    }
}

tracepoint:kvm:kvm_cpuid
{
    @kvm_cpuid[args.function, args.index] = count();
    if (@pending_nested_cpuid[tid]) {
        @nested_cpuid_l0_emulation[args.function, args.index] = count();
        delete(@pending_nested_cpuid[tid]);
    }
}

tracepoint:kvm:kvm_entry
{
    delete(@pending_nested_cpuid[tid]);
    if (@nested_latency_start[tid]) {
        if (@nested_latency_reason[tid] == 1024) {
            @nested_npf_exit_to_entry_ns[@nested_latency_gpa[tid]] =
                hist(nsecs - @nested_latency_start[tid]);
            delete(@nested_latency_gpa[tid]);
        }
        @nested_exit_to_entry_ns[@nested_latency_reason[tid]] =
            hist(nsecs - @nested_latency_start[tid]);
        delete(@nested_latency_start[tid]);
        delete(@nested_latency_reason[tid]);
    }
}

tracepoint:kvm:kvm_msr
{
    @kvm_msr[args.write, args.ecx] = count();
}

tracepoint:kvm:kvm_page_fault
{
    @kvm_page_fault[args.error_code] = count();
    @kvm_page_fault_gpa[args.fault_address] = count();
    @kvm_page_fault_detail[args.fault_address, args.error_code] = count();
}

/*
 * Break down a hardware nested NPF only after KVM's normal MMU path has
 * classified it.  No probe changes the fault or nested-VMEXIT semantics.
 * nested_svm_vmexit() performs the VMCB12 map/write/unmap for an L1-owned
 * fault, so scope the generic map probes to that call and vCPU thread.
 */
kprobe:npf_interception
/@nested_latency_reason[tid] == 1024/
{
    @npf_handler_start[tid] = nsecs;
}

kretprobe:npf_interception
/@npf_handler_start[tid]/
{
    @npf_handler_ns = hist(nsecs - @npf_handler_start[tid]);
    delete(@npf_handler_start[tid]);
}

kprobe:nested_svm_inject_npf_exit
/@nested_latency_reason[tid] == 1024/
{
    @nested_npf_l1_confirmed = count();
    @npf_exit_to_l1_confirmed_ns = hist(nsecs - @nested_latency_start[tid]);
    @nested_npf_l1_owned[tid] = 1;
}

kprobe:nested_svm_vmexit
/@nested_npf_l1_owned[tid]/
{
    @nested_vmexit_start[tid] = nsecs;
    @nested_vmexit_active[tid] = 1;
}

kprobe:__kvm_vcpu_map
/@nested_vmexit_active[tid]/
{
    @vmcb12_map_start[tid] = nsecs;
}

kretprobe:__kvm_vcpu_map
/@vmcb12_map_start[tid]/
{
    @vmcb12_map_ns = hist(nsecs - @vmcb12_map_start[tid]);
    @vmcb12_map_done[tid] = nsecs;
    delete(@vmcb12_map_start[tid]);
}

kprobe:kvm_vcpu_unmap
/@nested_vmexit_active[tid] && @vmcb12_map_done[tid]/
{
    @vmcb12_mapped_write_ns = hist(nsecs - @vmcb12_map_done[tid]);
    delete(@vmcb12_map_done[tid]);
}

kprobe:kvm_vcpu_unmap
/@nested_vmexit_active[tid] && !@vmcb12_map_done[tid]/
{
    @vmcb12_reused_write_ns = hist(nsecs - @nested_vmexit_start[tid]);
}

kretprobe:nested_svm_vmexit
/@nested_vmexit_start[tid]/
{
    @nested_vmexit_ns = hist(nsecs - @nested_vmexit_start[tid]);
    delete(@nested_vmexit_start[tid]);
    delete(@nested_vmexit_active[tid]);
    delete(@nested_npf_l1_owned[tid]);
    delete(@vmcb12_map_start[tid]);
    delete(@vmcb12_map_done[tid]);
}
BPF
    append_cpuid_leaf_probe "$regs_offset"
}

start_profile() {
    local output="$1" mode="$2" pid regs_offset="" leaf_probe=unavailable
    [ ! -e "$STATE_DIR/pid" ] || die 'profile already active'
    [ -z "$(virsh list --state-running --name | grep -v '^win11$' || true)" ] || \
        die 'another libvirt VM is running'
    output=$(readlink -m -- "$output")
    mkdir -p -- "$(dirname -- "$output")" "$STATE_DIR"
    chmod 700 "$STATE_DIR"
    : > "$output"
    chmod 600 "$output"
    printf '%s\n' "$output" > "$STATE_DIR/output"
    if regs_offset=$(resolve_vcpu_regs_offset); then
        leaf_probe=enabled
    fi
    write_program "$mode" "$regs_offset"

    {
        echo "profile_start=$(date --iso-8601=seconds)"
        echo 'collector=bpftrace aggregate maps (diagnostic instrumentation enabled)'
        echo "profile_mode=$mode"
        if [ "$mode" = full ] || [ "$mode" = npf ]; then
            echo 'npf_stage_timing=enabled'
        fi
        if [ "$mode" = npf ]; then
            echo 'npf_post_vmexit_tlb_timing=enabled'
            echo 'profile_scope=low-noise L1-owned nested NPF stages only'
        fi
        if [ "$mode" = npf ]; then
            echo 'cpuid_path_correlation=not-collected'
        else
            echo 'cpuid_path_correlation=enabled'
        fi
        echo "cpuid_leaf_probe=$leaf_probe"
        [ -z "$regs_offset" ] || echo "cpuid_regs_offset=$regs_offset"
        echo 'timing_values_valid=no'
        echo 'timing_warning=do not compare VMAware TIMER ratios while this profiler is active'
        echo 'scope=all KVM events; only win11 may be running'
        echo "vm_state=$(virsh domstate win11 | tr -d '\r' | head -1)"
        echo "loaded_srcversion=$(cat /sys/module/kvm_amd/srcversion)"
        echo 'amd_exit_reason_map=65:db,114:cpuid,124:msr,128:vmrun,129:hypercall,1024:npf,1025:avic_incomplete_ipi,1026:avic_unaccelerated_access'
    } >> "$output"

    setsid "$BPFTRACE" -q -o "$STATE_DIR/bpf.out" "$STATE_DIR/program.bt" \
        > "$STATE_DIR/launch.out" 2>&1 < /dev/null &
    pid=$!
    printf '%s\n' "$pid" > "$STATE_DIR/pid"

    # bpftrace buffers BEGIN output when -o is used, so liveness after its
    # compile/attach interval is the reliable readiness signal.
    sleep 2
    if ! kill -0 "$pid" 2>/dev/null; then
        cat "$STATE_DIR/launch.out" >&2 || true
        chmod 644 "$output"
        rm -rf -- "$STATE_DIR"
        die 'bpftrace exited before attach completed'
    fi
    echo 'profile_status=ACTIVE'
    echo "profile_pid=$pid"
    echo "profile_output=$output"
    echo "profile_mode=$mode"
    echo 'warning=diagnostic tracing changes VMEXIT latency; measure TIMER ratios separately with profiler stopped'
}

stop_profile() {
    local output pid tick stopped=no
    [ -r "$STATE_DIR/output" ] || die 'no active profile'
    [ -r "$STATE_DIR/pid" ] || die 'active profile PID missing'
    output=$(head -1 "$STATE_DIR/output")
    pid=$(head -1 "$STATE_DIR/pid")
    kill -INT "$pid" 2>/dev/null || true
    for tick in $(seq 1 100); do
        if ! kill -0 "$pid" 2>/dev/null; then
            stopped=yes
            break
        fi
        sleep 0.1
    done
    if [ "$stopped" != yes ]; then
        kill -TERM "$pid" 2>/dev/null || true
        sleep 1
    fi

    {
        echo "profile_stop=$(date --iso-8601=seconds)"
        echo "vm_state_at_stop=$(virsh domstate win11 | tr -d '\r' | head -1)"
        echo '=== bpf_aggregate ==='
        cat "$STATE_DIR/bpf.out" 2>/dev/null || true
        echo '=== bpf_launch_diagnostics ==='
        cat "$STATE_DIR/launch.out" 2>/dev/null || true
    } >> "$output"
    if [ -x "$ANALYZER" ]; then
        "$ANALYZER" "$output" >> "$output"
    else
        echo "cpuid_ownership_analysis=unavailable ($ANALYZER missing or not executable)" >> "$output"
    fi
    chmod 644 "$output"
    rm -rf -- "$STATE_DIR"
    echo 'profile_status=STOPPED'
    echo "profile_output=$output"
    echo 'profile_result=PASS'
}

status_profile() {
    local pid
    if [ -r "$STATE_DIR/pid" ]; then
        pid=$(head -1 "$STATE_DIR/pid")
        if kill -0 "$pid" 2>/dev/null; then
            echo 'profile_status=ACTIVE'
            echo "profile_pid=$pid"
            echo "profile_output=$(head -1 "$STATE_DIR/output")"
            exit 0
        fi
        echo 'profile_status=DEAD'
        exit 1
    fi
    echo 'profile_status=INACTIVE'
}

require_root
case "${1:-}" in
    start)
        [ "$#" -ge 2 ] && [ "$#" -le 3 ] || \
            die 'usage: VMEXIT_PROFILE.sh start OUTPUT [cpuid|full|npf]'
        mode="${3:-cpuid}"
        case "$mode" in
            cpuid|full|npf) ;;
            *) die 'profile mode must be cpuid, full or npf' ;;
        esac
        start_profile "$2" "$mode"
        ;;
    stop)
        [ "$#" -eq 1 ] || die 'usage: VMEXIT_PROFILE.sh stop'
        stop_profile
        ;;
    status)
        [ "$#" -eq 1 ] || die 'usage: VMEXIT_PROFILE.sh status'
        status_profile
        ;;
    *)
        die 'usage: VMEXIT_PROFILE.sh start OUTPUT [cpuid|full|npf] | stop | status'
        ;;
esac
