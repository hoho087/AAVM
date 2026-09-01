#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
OFFLINE_DIR="${PROJECT_DIR}/offline"
DEB_DIR="${OFFLINE_DIR}/debs"
SOURCE_DIR="${OFFLINE_DIR}/sources"
BOOTSTRAP_DIR="${OFFLINE_DIR}/.bootstrap"
KERNEL_TEST_VERSION="7.2.2"
KERNEL_TEST_ARCHIVE_NAME="linux-${KERNEL_TEST_VERSION}.tar.xz"
KERNEL_TEST_ARCHIVE_URL="https://cdn.kernel.org/pub/linux/kernel/v7.x/${KERNEL_TEST_ARCHIVE_NAME}"
KERNEL_TEST_ARCHIVE_SHA256="7d0e7ce14f98c43efe880cffbf354a59be45928fdf7170d7333c374ae91c0d83"
KERNEL_TEST_ARCHIVE="${SOURCE_DIR}/${KERNEL_TEST_ARCHIVE_NAME}"
KERNEL_TEST_TOPDIR="linux-${KERNEL_TEST_VERSION}"
KERNEL_TEST_SOURCE="${SOURCE_DIR}/linux-7.2"

if [[ "$({ . /etc/os-release; printf '%s' "${ID}:${VERSION_ID}"; })" != "ubuntu:24.04" ]]; then
  echo "This bundle must be prepared on Ubuntu 24.04." >&2
  exit 1
fi
if [[ "$(dpkg --print-architecture)" != "amd64" ]]; then
  echo "Only amd64 is supported." >&2
  exit 1
fi

packages=(
  openssh-server
  qemu-system-x86 qemu-system-gui qemu-system-modules-spice
  qemu-utils qemu-block-extra
  virt-viewer
  libvirt-daemon-system libvirt-clients virt-manager virtinst
  gir1.2-spiceclientglib-2.0 gir1.2-spiceclientgtk-3.0
  libxml2-utils ovmf
  swtpm swtpm-tools libtpms0 bridge-utils cpu-checker dnsmasq-base
  pciutils usbutils dmidecode acpica-tools python3-virt-firmware
  git ca-certificates curl wget dkms mokutil shim-signed openssl
  linux-headers-generic
  build-essential gcc g++ make nasm uuid-dev python3 python3-venv python3-pip
  meson ninja-build pkg-config flex bison gettext texinfo
  libglib2.0-dev libfdt-dev libpixman-1-dev libusb-1.0-0-dev
  libspice-server-dev libusbredirparser-dev libpipewire-0.3-dev
  libsdl2-image-dev zlib1g-dev libbz2-dev libcap-ng-dev libaio-dev
  libslirp-dev liburing-dev libepoxy-dev libdrm-dev libgbm-dev
  libgtk-3-dev libncurses-dev libssl-dev libelf-dev bc cpio fakeroot
  devscripts debhelper dh-exec libtool gawk rsync kmod initramfs-tools grub2-common
)

printf '%s\n' "${packages[@]}" > "$OFFLINE_DIR/roots.txt"
mkdir -p "$DEB_DIR" "$SOURCE_DIR" "$BOOTSTRAP_DIR"
python3 "$SCRIPT_DIR/resolve_debs.py" "$DEB_DIR" "${packages[@]}"
python3 "$SCRIPT_DIR/download_optional_nvidia_dkms.py" "$DEB_DIR"
python3 "$SCRIPT_DIR/prune_superseded_debs.py" "$DEB_DIR"
python3 "$SCRIPT_DIR/generate_deb_index.py" "$DEB_DIR"

if command -v git >/dev/null 2>&1; then
  GIT_BIN="$(command -v git)"
  GIT_ENV=()
else
  git_deb="$(find "$DEB_DIR" -maxdepth 1 -type f -name 'git_*_amd64.deb' | head -n 1)"
  [[ -n "$git_deb" ]] || { echo "Downloaded Git DEB not found." >&2; exit 1; }
  dpkg-deb -x "$git_deb" "$BOOTSTRAP_DIR"
  GIT_BIN="$BOOTSTRAP_DIR/usr/bin/git"
  GIT_ENV=(env "GIT_EXEC_PATH=$BOOTSTRAP_DIR/usr/lib/git-core")
fi

git_run() {
  "${GIT_ENV[@]}" "$GIT_BIN" "$@"
}

clone_or_reuse() {
  local path="$1"
  local remote="$2"
  local ref="$3"
  shift 3
  if [[ -e "$path" ]]; then
    if ! git_run -C "$path" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      echo "Existing source is not a Git worktree: $path" >&2
      exit 1
    fi
    if [[ "$(git_run -C "$path" remote get-url origin)" != "$remote" ]]; then
      echo "Existing source has an unexpected origin: $path" >&2
      exit 1
    fi
    if [[ -n "$(git_run -C "$path" status --porcelain)" ]]; then
      echo "Existing source has uncommitted changes: $path" >&2
      exit 1
    fi
    if [[ -n "$ref" ]] && ! git_run -C "$path" merge-base --is-ancestor "$ref" HEAD; then
      echo "Existing source does not contain required ref '$ref': $path" >&2
      exit 1
    fi
    echo "Reusing verified source: $path"
    return
  fi
  git_run clone "$@" "$remote" "$path"
}

kernel_722_makefile_is_valid() {
  local makefile="$1"
  [[ -f "$makefile" ]] || return 1

  awk '
    /^VERSION[[:space:]]*=/ {
      sub(/^[^=]*=[[:space:]]*/, "")
      version = $0
    }
    /^PATCHLEVEL[[:space:]]*=/ {
      sub(/^[^=]*=[[:space:]]*/, "")
      patchlevel = $0
    }
    /^SUBLEVEL[[:space:]]*=/ {
      sub(/^[^=]*=[[:space:]]*/, "")
      sublevel = $0
    }
    /^EXTRAVERSION[[:space:]]*=/ {
      sub(/^[^=]*=[[:space:]]*/, "")
      extraversion = $0
    }
    END {
      exit !(version == "7" && patchlevel == "2" && sublevel == "2" && extraversion == "")
    }
  ' "$makefile"
}

kernel_722_archive_is_valid() {
  local archive="$1"
  local archive_makefile

  [[ -f "$archive" ]] || return 1
  [[ "$(sha256sum "$archive" | awk '{print $1}')" == "$KERNEL_TEST_ARCHIVE_SHA256" ]] || return 1
  tar -tJf "$archive" | awk -v topdir="$KERNEL_TEST_TOPDIR" '
    $0 == topdir "/Makefile" { makefile = 1 }
    $0 != topdir && index($0, topdir "/") != 1 { unexpected = 1 }
    END { exit !(makefile && !unexpected) }
  ' || return 1

  archive_makefile="$(mktemp "${SOURCE_DIR}/.${KERNEL_TEST_TOPDIR}-Makefile.XXXXXX")"
  if ! tar -xJOf "$archive" "${KERNEL_TEST_TOPDIR}/Makefile" > "$archive_makefile" \
      || ! kernel_722_makefile_is_valid "$archive_makefile"; then
    rm -f -- "$archive_makefile"
    return 1
  fi
  rm -f -- "$archive_makefile"
}

ensure_linux_722_archive() {
  local temporary

  if kernel_722_archive_is_valid "$KERNEL_TEST_ARCHIVE"; then
    echo "Reusing verified Linux ${KERNEL_TEST_VERSION} archive: $KERNEL_TEST_ARCHIVE"
    return
  fi

  temporary="$(mktemp "${SOURCE_DIR}/.${KERNEL_TEST_ARCHIVE_NAME}.XXXXXX")"
  if ! curl --fail --location --retry 3 --output "$temporary" "$KERNEL_TEST_ARCHIVE_URL" \
      || ! kernel_722_archive_is_valid "$temporary"; then
    rm -f -- "$temporary"
    echo "Could not download a valid Linux ${KERNEL_TEST_VERSION} archive." >&2
    exit 1
  fi
  mv -f -- "$temporary" "$KERNEL_TEST_ARCHIVE"
  echo "Downloaded verified Linux ${KERNEL_TEST_VERSION} archive: $KERNEL_TEST_ARCHIVE"
}

extract_linux_722_source() {
  local temporary_dir
  local extracted_source

  if [[ -e "$KERNEL_TEST_SOURCE" ]]; then
    if ! kernel_722_makefile_is_valid "$KERNEL_TEST_SOURCE/Makefile"; then
      echo "Existing Linux 7.2 source is not v${KERNEL_TEST_VERSION}: $KERNEL_TEST_SOURCE" >&2
      exit 1
    fi
    echo "Reusing verified content-only source: $KERNEL_TEST_SOURCE"
    return
  fi

  temporary_dir="$(mktemp -d "${SOURCE_DIR}/.linux-7.2.XXXXXX")"
  extracted_source="${temporary_dir}/${KERNEL_TEST_TOPDIR}"
  if ! tar -xJf "$KERNEL_TEST_ARCHIVE" --no-same-owner --directory="$temporary_dir" \
      || ! kernel_722_makefile_is_valid "$extracted_source/Makefile"; then
    rm -rf -- "$temporary_dir"
    echo "Could not extract a valid Linux ${KERNEL_TEST_VERSION} source tree." >&2
    exit 1
  fi
  mv -- "$extracted_source" "$KERNEL_TEST_SOURCE"
  rmdir -- "$temporary_dir"
  echo "Extracted Linux ${KERNEL_TEST_VERSION} source: $KERNEL_TEST_SOURCE"
}

clone_or_reuse "$SOURCE_DIR/qemu" https://github.com/qemu/qemu.git stable-11.0 --depth 1 --single-branch --branch stable-11.0
clone_or_reuse "$SOURCE_DIR/edk2" https://github.com/tianocore/edk2.git edk2-stable202602 --depth 1 --recursive --shallow-submodules --single-branch --branch edk2-stable202602
clone_or_reuse "$SOURCE_DIR/linux-tkg" https://github.com/Frogging-Family/linux-tkg.git "" --depth 1
clone_or_reuse "$SOURCE_DIR/linux" https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git v6.19 --depth 1 --single-branch --branch v6.19
ensure_linux_722_archive
extract_linux_722_source
clone_or_reuse "$SOURCE_DIR/libtpms" https://github.com/stefanberger/libtpms.git v0.9.3 --depth 1 --single-branch --branch v0.9.3

curl --fail --location --output "$OFFLINE_DIR/memflow-source-only.dkms.tar.gz" \
  https://github.com/memflow/memflow-kvm/releases/download/bin-kernel-6.19/memflow-source-only.dkms.tar.gz

python3 "$SCRIPT_DIR/generate_manifest.py" "$OFFLINE_DIR"
echo "Offline bundle complete: $OFFLINE_DIR"
