from __future__ import annotations

import fcntl
import time
from contextlib import contextmanager
from pathlib import Path

from .paths import PENDING_DIR, STATE_DIR, ensure_state_dirs, vm_dir
from .util import AppError, read_json, valid_vm_name, write_json


def profile_path(name: str) -> Path:
    return vm_dir(valid_vm_name(name)) / "profile.json"


def load_profile(name: str) -> dict:
    profile = read_json(profile_path(name))
    if not profile:
        raise AppError(f"No managed profile exists for VM '{name}'.")
    return profile


def save_profile(name: str, profile: dict) -> None:
    ensure_state_dirs()
    path = profile_path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    write_json(path, profile)


@contextmanager
def vm_lock(name: str):
    ensure_state_dirs()
    lock_path = vm_dir(valid_vm_name(name)) / ".lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def mark_pending(name: str) -> None:
    ensure_state_dirs()
    write_json(PENDING_DIR / f"{valid_vm_name(name)}.json", {"vm": name, "marked_at": int(time.time())})


def clear_pending(name: str) -> None:
    (PENDING_DIR / f"{valid_vm_name(name)}.json").unlink(missing_ok=True)


def pending_names() -> list[str]:
    ensure_state_dirs()
    return sorted(path.stem for path in PENDING_DIR.glob("*.json"))


def load_host_state() -> dict:
    return read_json(STATE_DIR / "host.json", {})


def update_host_state(**values) -> None:
    state = load_host_state()
    state.update(values)
    write_json(STATE_DIR / "host.json", state)
