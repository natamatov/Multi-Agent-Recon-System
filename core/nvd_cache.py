"""
Файловый кэш ответов NVD (TTL 24 часа).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

CACHE_DIR = Path("logs/cache/nvd")
TTL_SECONDS = 86400


def _cache_path(cve_id: str) -> Path:
    return CACHE_DIR / f"{cve_id.upper()}.json"


def get_cached(cve_id: str) -> dict[str, Any] | None:
    path = _cache_path(cve_id)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if time.time() - data.get("_cached_at", 0) > TTL_SECONDS:
            path.unlink(missing_ok=True)
            return None
        return data.get("record")
    except (json.JSONDecodeError, OSError):
        return None


def set_cached(cve_id: str, record: dict[str, Any] | None) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    payload = {"_cached_at": time.time(), "record": record}
    _cache_path(cve_id).write_text(
        json.dumps(payload, ensure_ascii=False),
        encoding="utf-8",
    )
