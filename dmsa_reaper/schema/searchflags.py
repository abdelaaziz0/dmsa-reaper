from __future__ import annotations

from dmsa_reaper.constants import FCONFIDENTIAL


def is_confidential(search_flags: int | str | None) -> bool:
    if search_flags is None:
        return False
    return bool(int(search_flags) & FCONFIDENTIAL)
