from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


class AppError(RuntimeError):
    pass


@dataclass
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str


class Runner:
    def __init__(self, dry_run: bool = False, verbose: bool = True):
        self.dry_run = dry_run
        self.verbose = verbose

    def run(
        self,
        args: Iterable[str | os.PathLike[str]],
        *,
        check: bool = True,
        capture: bool = False,
        input_text: str | None = None,
        env: dict[str, str] | None = None,
        cwd: Path | None = None,
    ) -> CommandResult:
        argv = [str(x) for x in args]
        if self.verbose:
            print("+", " ".join(shlex_quote(x) for x in argv))
        if self.dry_run:
            return CommandResult(argv, 0, "", "")
        proc = subprocess.run(
            argv,
            check=False,
            text=True,
            input=input_text,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            env=env,
            cwd=cwd,
        )
        result = CommandResult(argv, proc.returncode, proc.stdout or "", proc.stderr or "")
        if check and proc.returncode:
            detail = result.stderr.strip() or result.stdout.strip()
            raise AppError(f"Command failed ({proc.returncode}): {' '.join(argv)}\n{detail}")
        return result


def shlex_quote(value: str) -> str:
    import shlex
    return shlex.quote(value)


def require_root() -> None:
    if os.geteuid() != 0:
        raise AppError("This action changes the host and must be run with sudo.")


def atomic_write(path: Path, data: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_json(path: Path, default=None):
    if not path.exists():
        return default
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def write_json(path: Path, value) -> None:
    atomic_write(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def valid_vm_name(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", value):
        raise AppError("VM name must be 1-64 ASCII letters, digits, '.', '_' or '-'.")
    return value


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def prompt(text: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    value = input(f"{text}{suffix}: ").strip()
    return value or (default if default is not None else "")


def prompt_int(text: str, default: int, minimum: int, maximum: int) -> int:
    while True:
        value = prompt(text, str(default))
        try:
            number = int(value)
        except ValueError:
            print("請輸入整數。")
            continue
        if minimum <= number <= maximum:
            return number
        print(f"數值必須介於 {minimum} 與 {maximum} 之間。")


def prompt_yes_no(text: str, default: bool = False) -> bool:
    mark = "Y/n" if default else "y/N"
    value = input(f"{text} [{mark}]: ").strip().lower()
    if not value:
        return default
    return value in {"y", "yes", "1", "true", "是"}
