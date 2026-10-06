"""Small Redis-backed health records used by the standalone status command."""
from __future__ import annotations

import time


async def publish_status(client, component: str, **fields) -> None:
    payload = {key: str(value) for key, value in fields.items() if value is not None}
    payload["updated_at"] = f"{time.time():.3f}"
    await client.hset(f"ptah:status:{component}", mapping=payload)
