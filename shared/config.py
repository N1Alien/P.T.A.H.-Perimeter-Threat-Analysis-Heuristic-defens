"""Runtime configuration with a deliberately passive safety boundary."""
from __future__ import annotations

import os


SUPPORTED_MODE = "observe"


def get_mode() -> str:
    mode = os.environ.get("PTAH_MODE", SUPPORTED_MODE).strip().lower()
    if mode != SUPPORTED_MODE:
        raise ValueError(
            f"Unsupported PTAH_MODE={mode!r}; only 'observe' is currently available."
        )
    return mode


def get_positive_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer; got {raw!r}.") from exc
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}; got {value}.")
    return value
