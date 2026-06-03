from __future__ import annotations

import base64
import uuid


def bytes_to_guid_le(raw: bytes) -> str:
    """Decode AD schemaIDGUID/objectType bytes into canonical GUID string.

    AD stores GUIDs in little-endian byte order for the first three fields.
    Python's uuid.UUID(bytes_le=...) handles this correctly.
    """
    if len(raw) != 16:
        raise ValueError(f"GUID must be 16 bytes, got {len(raw)}")
    return str(uuid.UUID(bytes_le=raw))


def guid_to_bytes_le(guid: str) -> bytes:
    return uuid.UUID(guid).bytes_le


def maybe_b64_to_guid_le(value: str) -> str:
    return bytes_to_guid_le(base64.b64decode(value))


def normalize_guid(value: str | bytes | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return bytes_to_guid_le(value)
    value = str(value)
    if len(value) == 36 and "-" in value:
        return str(uuid.UUID(value))
    try:
        return maybe_b64_to_guid_le(value)
    except Exception:
        return value.lower()


def parse_int_auto(value: str | int) -> int:
    if isinstance(value, int):
        return value
    return int(value, 0)
