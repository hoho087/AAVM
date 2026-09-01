#!/usr/bin/env bash
set -uo pipefail

DOMAIN="${1:-win11}"
LIMIT_SECONDS="${2:-45}"
OUTPUT_ROOT="${3:-/tmp/kvm-aavm-boot-debug}"
STOP_AFTER_LIMIT="${4:-keep-running}"

if [[ "$DOMAIN" == "--self-test" ]]; then
    printf '%s\n' 'boot_debug_script=ready'
    exit 0
fi

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    printf '%s\n' 'run_as_root=yes'
    exit 2
fi

if ! [[ "$LIMIT_SECONDS" =~ ^[0-9]+$ ]] || (( LIMIT_SECONDS < 5 )); then
    printf '%s\n' 'limit_seconds_invalid=yes'
    exit 2
fi

timestamp=$(date +%Y%m%d-%H%M%S)
OUT="$OUTPUT_ROOT/${DOMAIN}-${timestamp}"
mkdir -p "$OUT"

QEMU_LOG="/var/log/libvirt/qemu/${DOMAIN}.log"
HOOK_LOG="/var/log/libvirt/qemu/${DOMAIN}-gpu-hook.log"
SWTPM_LOG="/var/log/swtpm/libvirt/qemu/${DOMAIN}-swtpm.log"

file_size() {
    stat -c %s "$1" 2>/dev/null || printf '0\n'
}

copy_delta() {
    local source=$1 offset=$2 destination=$3 size
    size=$(file_size "$source")
    if (( size < offset )); then
        offset=0
    fi
    if [[ -r "$source" ]]; then
        dd if="$source" of="$destination" bs=1 skip="$offset" status=none 2>/dev/null || true
    else
        : > "$destination"
    fi
}

device_snapshot() {
    local destination=$1 dev
    {
        for dev in 01:00.0 01:00.1 0a:00.0 0c:00.4; do
            printf '%s\n' "--- $dev"
            lspci -nnk -s "$dev" 2>&1 || true
            printf 'driver=%s\n' "$(basename "$(readlink -f "/sys/bus/pci/devices/0000:${dev}/driver" 2>/dev/null)" 2>/dev/null || printf none)"
        done
    } > "$destination"
}

START_EPOCH=$(date +%s)
START_ISO=$(date --iso-8601=seconds)
QEMU_OFFSET=$(file_size "$QEMU_LOG")
HOOK_OFFSET=$(file_size "$HOOK_LOG")
SWTPM_OFFSET=$(file_size "$SWTPM_LOG")

{
    printf 'domain=%s\n' "$DOMAIN"
    printf 'start_iso=%s\n' "$START_ISO"
    printf 'boot_id=%s\n' "$(cat /proc/sys/kernel/random/boot_id)"
    printf 'kernel=%s\n' "$(uname -a)"
    printf 'initial_state=%s\n' "$(virsh domstate "$DOMAIN" --reason 2>&1 | tr '\n' ' ')"
    printf 'qemu_log_offset=%s\n' "$QEMU_OFFSET"
    printf 'hook_log_offset=%s\n' "$HOOK_OFFSET"
    printf 'swtpm_log_offset=%s\n' "$SWTPM_OFFSET"
} > "$OUT/metadata.txt"

virsh dumpxml "$DOMAIN" > "$OUT/domain-before.xml" 2>&1 || true
virsh dominfo "$DOMAIN" > "$OUT/dominfo-before.txt" 2>&1 || true
device_snapshot "$OUT/devices-before.txt"
systemctl status display-manager --no-pager > "$OUT/display-before.txt" 2>&1 || true

timeout "$((LIMIT_SECONDS + 20))" virsh event "$DOMAIN" --all --loop --timestamp \
    > "$OUT/libvirt-events.txt" 2>&1 &
EVENT_PID=$!
sleep 1

virsh start "$DOMAIN" > "$OUT/start-command-output.txt" 2>&1
START_STATUS=$?
{
    printf 'command=virsh start %s\n' "$DOMAIN"
    cat "$OUT/start-command-output.txt"
    printf 'exit_status=%s\n' "$START_STATUS"
} > "$OUT/start-command.txt"

: > "$OUT/state-timeline.txt"
: > "$OUT/qmp-status.txt"
for ((tick=0; tick <= LIMIT_SECONDS * 2; tick++)); do
    now=$(date --iso-8601=seconds)
    state=$(virsh domstate "$DOMAIN" --reason 2>&1 | tr '\n' ' ')
    printf '%s tick=%s state=%s\n' "$now" "$tick" "$state" >> "$OUT/state-timeline.txt"
    if grep -qE 'running|paused|idle|in shutdown|pmsuspended' <<<"$state"; then
        if (( tick % 2 == 0 )); then
            {
                printf '%s\n' "--- $now"
                virsh qemu-monitor-command "$DOMAIN" --pretty '{"execute":"query-status"}' 2>&1 || true
            } >> "$OUT/qmp-status.txt"
        fi
    elif (( tick > 0 )); then
        break
    fi
    sleep 0.5
done

POST_LOOP_STATE=$(virsh domstate "$DOMAIN" --reason 2>&1 | tr '\n' ' ')
if [[ "$STOP_AFTER_LIMIT" == "stop" ]] && grep -qE 'running|paused|idle|in shutdown|pmsuspended' <<<"$POST_LOOP_STATE"; then
    {
        printf 'command=virsh destroy %s\n' "$DOMAIN"
        virsh destroy "$DOMAIN"
        printf 'exit_status=%s\n' "$?"
    } > "$OUT/controlled-stop.txt" 2>&1
fi

sleep 8
kill "$EVENT_PID" 2>/dev/null || true
wait "$EVENT_PID" 2>/dev/null || true

END_ISO=$(date --iso-8601=seconds)
FINAL_STATE=$(virsh domstate "$DOMAIN" --reason 2>&1 | tr '\n' ' ')
copy_delta "$QEMU_LOG" "$QEMU_OFFSET" "$OUT/qemu-delta.log"
copy_delta "$HOOK_LOG" "$HOOK_OFFSET" "$OUT/hook-delta.log"
copy_delta "$SWTPM_LOG" "$SWTPM_OFFSET" "$OUT/swtpm-delta.log"
journalctl -b --since "@$START_EPOCH" --until "$END_ISO" --no-pager -o short-iso \
    > "$OUT/journal-all.log" 2>&1 || true
grep -Ei 'win11|libvirt|virtqemu|qemu|vfio|nvidia|swtpm|kvm|iommu|amd-vi|hook|display-manager|gdm' \
    "$OUT/journal-all.log" > "$OUT/journal-filtered.log" 2>/dev/null || true
virsh dumpxml "$DOMAIN" > "$OUT/domain-after.xml" 2>&1 || true
virsh dominfo "$DOMAIN" > "$OUT/dominfo-after.txt" 2>&1 || true
device_snapshot "$OUT/devices-after.txt"
systemctl status display-manager --no-pager > "$OUT/display-after.txt" 2>&1 || true

{
    printf 'domain=%s\n' "$DOMAIN"
    printf 'start_iso=%s\n' "$START_ISO"
    printf 'end_iso=%s\n' "$END_ISO"
    printf 'start_command_exit=%s\n' "$START_STATUS"
    printf 'post_loop_state=%s\n' "$POST_LOOP_STATE"
    printf 'stop_after_limit=%s\n' "$STOP_AFTER_LIMIT"
    printf 'final_state=%s\n' "$FINAL_STATE"
    printf 'output_dir=%s\n' "$OUT"
    printf '%s\n' '--- lifecycle ---'
    tail -40 "$OUT/libvirt-events.txt" 2>/dev/null || true
    printf '%s\n' '--- qemu delta ---'
    tail -60 "$OUT/qemu-delta.log" 2>/dev/null || true
    printf '%s\n' '--- hook delta ---'
    tail -60 "$OUT/hook-delta.log" 2>/dev/null || true
    printf '%s\n' '--- swtpm delta ---'
    tail -40 "$OUT/swtpm-delta.log" 2>/dev/null || true
    printf '%s\n' '--- state timeline ---'
    cat "$OUT/state-timeline.txt"
} > "$OUT/SUMMARY.txt"

cat "$OUT/SUMMARY.txt"
exit 0
