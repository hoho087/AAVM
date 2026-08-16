from __future__ import annotations

import os
from pathlib import Path

PROJECT_DIR = Path(os.environ.get("KVM_AAVM_PROJECT_DIR", Path(__file__).resolve().parent.parent))
PREFIX = Path(os.environ.get("KVM_AAVM_PREFIX", "/opt/kvm-aavm"))
_DEFAULT_STATE = "/var/lib/kvm-aavm" if os.geteuid() == 0 or Path("/var/lib/kvm-aavm").exists() else str(PROJECT_DIR / ".state")
STATE_DIR = Path(os.environ.get("KVM_AAVM_STATE_DIR", _DEFAULT_STATE))
VM_IMAGE_DIR = Path(os.environ.get("KVM_AAVM_IMAGE_DIR", "/var/lib/libvirt/images"))
OFFLINE_DIR = Path(os.environ.get("KVM_AAVM_OFFLINE_DIR", PROJECT_DIR / "offline"))
VM_DIR = STATE_DIR / "vms"
BACKUP_DIR = STATE_DIR / "backups"
LOG_DIR = STATE_DIR / "logs"
PENDING_DIR = STATE_DIR / "pending"


def vm_dir(name: str) -> Path:
    return VM_DIR / name


def ensure_state_dirs() -> None:
    for path in (STATE_DIR, VM_DIR, BACKUP_DIR, LOG_DIR, PENDING_DIR):
        path.mkdir(parents=True, exist_ok=True)
