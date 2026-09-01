#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
OFFLINE_DIR="${PROJECT_DIR}/offline"
SOURCE_DIR="${OFFLINE_DIR}/sources/libtpms"
PATCH_FILE="${PROJECT_DIR}/patches/libtpms-amd-ftpm-v0.9.3.patch"
DEB_DIR="${KVM_AAVM_LIBTPMS_DEB_DIR:-${OFFLINE_DIR}/debs}"
SOURCE_REVISION="a63c51805eb11390f7e1210e4b6cec59dee1dcc1"

[[ -d "$SOURCE_DIR/.git" ]] || { echo "Missing libtpms source: $SOURCE_DIR" >&2; exit 1; }
[[ -f "$PATCH_FILE" ]] || { echo "Missing libtpms AMD profile patch: $PATCH_FILE" >&2; exit 1; }
[[ "$(git -C "$SOURCE_DIR" rev-parse HEAD)" == "$SOURCE_REVISION" ]] || {
  echo "libtpms source must be pinned to $SOURCE_REVISION" >&2
  exit 1
}

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/kvm-aavm-libtpms.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT
cp -a "$SOURCE_DIR" "$WORK_DIR/libtpms"
cd "$WORK_DIR/libtpms"

git apply --check "$PATCH_FILE"
git apply "$PATCH_FILE"
DEBFULLNAME="KVM-AntiAntiVM" DEBEMAIL="noreply@kvm-aavm.local" \
  dch --newversion "0.9.3+kvm-aavm1" --distribution noble --urgency medium \
  "Apply the AMD fTPM TPM 2.0 capability profile."
dpkg-buildpackage -us -uc -b

package="$(find "$WORK_DIR" -maxdepth 1 -type f -name 'libtpms0_*_amd64.deb' -print -quit)"
[[ -n "$package" ]] || { echo "libtpms0 package was not produced" >&2; exit 1; }
[[ "$(dpkg-deb -f "$package" Package)" == "libtpms0" ]] || {
  echo "Unexpected package output: $package" >&2
  exit 1
}
[[ "$(dpkg-deb -f "$package" Version)" == *"+kvm-aavm1" ]] || {
  echo "AMD-profile package version marker is missing" >&2
  exit 1
}
mkdir -p "$DEB_DIR"
cp -f "$package" "$DEB_DIR/"
echo "Built AMD fTPM libtpms package: $(basename "$package")"
