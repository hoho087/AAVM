#!/usr/bin/env bash
set -euo pipefail

# Resource preparation is intentionally rootless.
exec "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/prepare_offline_rootless.sh" "$@"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
OFFLINE_DIR="${PROJECT_DIR}/offline"
DEB_DIR="${OFFLINE_DIR}/debs"
SOURCE_DIR="${OFFLINE_DIR}/sources"

if [[ "$(. /etc/os-release; printf '%s' "${ID}:${VERSION_ID}")" != "ubuntu:24.04" ]]; then
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
  swtpm swtpm-tools bridge-utils cpu-checker dnsmasq-base
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
  devscripts debhelper rsync kmod initramfs-tools grub2-common
)

sudo apt-get update
sudo mkdir -p "$DEB_DIR/partial" "$SOURCE_DIR"
sudo apt-get -y --download-only \
  -o "Dir::Cache::archives=${DEB_DIR}" \
  -o APT::Keep-Downloaded-Packages=true \
  install "${packages[@]}"
sudo apt-get install -y git ca-certificates curl
sudo chown -R "$(id -u):$(id -g)" "$OFFLINE_DIR"

clone_clean() {
  local path="$1"
  shift
  if [[ -e "$path" ]]; then
    echo "Refusing to overwrite existing source: $path" >&2
    exit 1
  fi
  git clone "$@" "$path"
}

clone_clean "$SOURCE_DIR/qemu" --depth 1 --single-branch --branch stable-11.0 https://github.com/qemu/qemu.git
clone_clean "$SOURCE_DIR/edk2" --depth 1 --recursive --shallow-submodules --single-branch --branch edk2-stable202602 https://github.com/tianocore/edk2.git
clone_clean "$SOURCE_DIR/linux-tkg" --depth 1 https://github.com/Frogging-Family/linux-tkg.git
clone_clean "$SOURCE_DIR/linux" --depth 1 --single-branch --branch v6.19 https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git

curl --fail --location --output "$OFFLINE_DIR/memflow-source-only.dkms.tar.gz" \
  https://github.com/memflow/memflow-kvm/releases/download/bin-kernel-6.19/memflow-source-only.dkms.tar.gz

python3 "$SCRIPT_DIR/generate_manifest.py" "$OFFLINE_DIR"
echo "Offline bundle complete: $OFFLINE_DIR"
echo "Copy the complete project directory to the offline Ubuntu 24.04 amd64 host."
