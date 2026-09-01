# Offline bundle placeholder

Run `tools/prepare_offline.sh` **once on an online, clean Ubuntu 24.04 amd64
machine**. It fills this directory with the complete DEB dependency closure,
fixed QEMU/OVMF/Linux source trees, the optional Linux `v7.2.2` test archive
from kernel.org and its extracted test source,
the pinned `libtpms v0.9.3` source used for the AMD fTPM capability profile,
memflow DKMS archive, and `manifest.json` checksums.
The deployer profile is currently pinned to `v7.2.2`; preparing another point
release requires a matching port patch and an intentional profile update before
it can be installed.

The deployment side never downloads missing files. `validate-offline` fails
closed when a required file or checksum is missing.

The preparation host must run `apt-get update` immediately before rebuilding
the bundle.  Rebuilding in place downloads the current Ubuntu 24.04 security
revisions and removes older revisions of the same package/architecture before
the `Packages` index is generated.  This is required for exact-version pairs
such as `curl`/`libcurl4t64` and `libssl-dev`/`libssl3t64`; copying only one
member of either pair creates an uninstallable offline repository.

`install-offline` installs the offline build dependencies, then builds and installs the
tracked AMD profile patch as a local `libtpms0` package. This step happens after manifest
validation so the generated package is not itself part of the portable bundle checksum.
It also installs the managed `swtpm_setup` PCR-bank policy matching the host's active TPM
banks (or `sha1,sha256` when no host TPM is visible) and AMD platform metadata used for newly
manufactured EK/platform certificates. Existing VM
TPM state is deliberately preserved and is never silently reinitialized by deployment.

The 7.2 source is optional for normal deployment but required by the deployer
menu's experimental 7.2 kernel action. That action also requires a separately
ported `amd72-test.mypatch` or `intel72-test.mypatch`; the stable 6.19 patches
are never reused automatically.

The bundle retains `sources/linux-7.2.2.tar.xz` from
`https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.2.2.tar.xz` and extracts
it to `sources/linux-7.2` for the kernel builder. Its SHA-256 is pinned to
`7d0e7ce14f98c43efe880cffbf354a59be45928fdf7170d7333c374ae91c0d83`.
Both are verified during
preparation and covered by `manifest.json`, so deployment remains network-free.
