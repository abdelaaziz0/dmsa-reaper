from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel


def write_model(path: str | Path, model: BaseModel) -> None:
    Path(path).write_text(model.model_dump_json(indent=2), encoding="utf-8")
