"""Honda EPS security-access key (39990-TJB-A030 / openpilot eps-update style)."""

from __future__ import annotations

import struct


def hex_to_sa_const(hex_str: str) -> bytes:
    """Parse RWD security-key field, e.g. ``0x011101121120`` -> 6 bytes."""
    s = hex_str.strip().replace("0x", "").replace(",", "").replace(" ", "")
    if len(s) % 2 == 1:
        s = "0" + s
    raw = bytes.fromhex(s)
    if len(raw) != 6:
        raise ValueError(f"SA const must be 6 bytes, got {len(raw)} from {hex_str!r}")
    return raw


def calculate_honda_session_key(const_bytes: bytes, seed_bytes: bytes) -> bytes:
    """
    Same formula as openpilot ``eps-update.py`` / Honda Z-block SA records.

    ``const_bytes``: 6-byte big-endian record (three uint16: k0, k1, k2).
  ``seed_bytes``: 2-byte seed (last two bytes of REQUEST_SEED response).
    """
    if len(const_bytes) != 6:
        raise ValueError(f"const_bytes must be 6 bytes, got {len(const_bytes)}")
    if len(seed_bytes) != 2:
        raise ValueError(f"seed_bytes must be 2 bytes, got {len(seed_bytes)}")
    k0, k1, k2 = struct.unpack("!HHH", const_bytes)
    seed = struct.unpack("!H", seed_bytes)[0]
    if k2 == 0:
        k2 = 0x10000
    key = ((seed + k0) ^ (seed * k1) % k2) & 0xFFFF
    return struct.pack("!H", key)


# 39990-TJB-A030 stock RWD / bin_to_rwd.py default
TJB_A030_SA_CONST = hex_to_sa_const("0x011101121120")
