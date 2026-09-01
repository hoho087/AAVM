from __future__ import annotations

import random
import secrets
import string
import uuid


AMD_VENDORS = [
    ("ASUSTeK COMPUTER INC.", "TUF GAMING B850-PLUS WIFI"),
    ("Gigabyte Technology Co., Ltd.", "B650 AORUS ELITE AX"),
    ("Micro-Star International Co., Ltd.", "PRO B650-P WIFI"),
]
INTEL_VENDORS = [
    ("ASUSTeK COMPUTER INC.", "PRIME-B760-PLUS"),
    ("Micro-Star International Co., Ltd.", "PRO Z790-P WIFI"),
    ("Dell Inc.", "XPS 8960"),
    ("LENOVO", "Legion T5 26IRB8"),
]
MEMORY = ["Samsung", "Kingston", "Crucial", "SK Hynix"]
DISKS = ["Samsung SSD 870 EVO", "Crucial MX500", "KINGSTON SA400S37", "SanDisk SSD PLUS"]


def token(length: int, alphabet: str = string.ascii_uppercase + string.digits) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(length))


def mac_address() -> str:
    # Locally administered, unicast address.
    first = (secrets.randbits(8) | 0x02) & 0xFE
    return ":".join(f"{x:02x}" for x in [first, *[secrets.randbits(8) for _ in range(5)]])


def wwn() -> str:
    return "0x" + secrets.token_hex(8)


def _board_fields(board: dict) -> tuple[str, str, str]:
    """Validate the persistent motherboard identity used by SMBIOS types 1-3."""
    if not isinstance(board, dict):
        raise ValueError("Identity board pin must be an object.")
    values = []
    for name in ("manufacturer", "product", "version"):
        value = str(board.get(name, "")).strip()
        if not value or "\x00" in value or "\n" in value or "\r" in value:
            raise ValueError(f"Identity board pin has an invalid {name}.")
        values.append(value)
    if "," in values[2]:
        raise ValueError("Identity board pin version cannot contain a comma.")
    return tuple(values)  # type: ignore[return-value]


def apply_board_identity(identity: dict, board: dict) -> dict:
    """Set OEM board fields without copying host-unique serial identifiers."""
    manufacturer, product, version = _board_fields(board)
    updated = dict(identity)
    updated.update({
        "manufacturer": manufacturer,
        "product": product,
        "baseboard_product": product,
        "version": version,
    })
    return updated


def generate(cpu: dict, generation: int = 1, board: dict | None = None) -> dict:
    platforms = AMD_VENDORS if cpu.get("vendor") == "amd" else INTEL_VENDORS
    manufacturer, product = secrets.choice(platforms)
    version = f"{random.randint(1, 9)}.{random.randint(10, 99)}"
    identity = {
        "generation": generation,
        "domain_uuid": str(uuid.uuid4()),
        "mac": mac_address(),
        "disk_serial": token(16),
        "disk_wwn": wwn(),
        "manufacturer": manufacturer,
        "product": product,
        "version": version,
        "system_serial": token(14),
        "system_uuid": str(uuid.uuid4()),
        "baseboard_product": product,
        "baseboard_serial": token(14),
        "chassis_serial": token(14),
        "cpu_manufacturer": "Advanced Micro Devices, Inc." if cpu.get("vendor") == "amd" else "Intel Corporation",
        "cpu_version": cpu.get("model", "Processor"),
        "memory_manufacturer": secrets.choice(MEMORY),
        "memory_part": token(12),
        "memory_serial": token(8),
        "disk_model": secrets.choice(DISKS),
    }
    return apply_board_identity(identity, board) if board is not None else identity


def rerandomize(profile: dict) -> dict:
    identity = generate(
        profile["host"]["cpu"],
        int(profile.get("identity", {}).get("generation", 0)) + 1,
        profile.get("identity_board"),
    )
    updated = dict(profile)
    updated["identity"] = identity
    return updated
