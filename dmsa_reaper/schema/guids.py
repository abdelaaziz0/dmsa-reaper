from __future__ import annotations

from dmsa_reaper.utils import normalize_guid

def decode_schema_guid(value) -> str | None:
    return normalize_guid(value)
