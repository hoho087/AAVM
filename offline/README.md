# Offline bundle placeholder

Run `tools/prepare_offline.sh` **once on an online, clean Ubuntu 24.04 amd64
machine**. It fills this directory with the complete DEB dependency closure,
fixed source trees, memflow DKMS archive, and `manifest.json` checksums.

The deployment side never downloads missing files. `validate-offline` fails
closed when a required file or checksum is missing.
