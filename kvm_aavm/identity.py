from __future__ import annotations

import random
import secrets
import string
import uuid


VENDORS = [
    ("ASUSTeK COMPUTER INC.", "PRIME-B760-PLUS"),
    ("Gigabyte Technology Co., Ltd.", "B650 AORUS ELITE AX"),
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


def generate(cpu: dict, generation: int = 1) -> dict:
    manufacturer, product = secrets.choice(VENDORS)
    version = f"{random.randint(1, 9)}.{random.randint(10, 99)}"
    return {
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


def rerandomize(profile: dict) -> dict:
    identity = generate(profile["host"]["cpu"], int(profile.get("identity", {}).get("generation", 0)) + 1)
    updated = dict(profile)
    updated["identity"] = identity
    return updated
