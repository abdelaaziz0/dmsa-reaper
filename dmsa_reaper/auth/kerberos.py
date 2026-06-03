from __future__ import annotations

from pathlib import Path


def has_ccache(path: str | None = None) -> bool:
    if path:
        return Path(path).exists()
    return False
