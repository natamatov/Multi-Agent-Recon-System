"""Healthcheck для Docker и мониторинга."""

from __future__ import annotations

import os
from typing import Any

from core.dependency_manager import check_tools


def run_healthcheck() -> dict[str, Any]:
    tools = check_tools()
    return {
        "status": "ok" if tools.get("nmap") and tools.get("whatweb") else "degraded",
        "tools": tools,
        "claude_key_set": bool(os.getenv("CLAUDE_API_KEY")),
        "shodan_key_set": bool(os.getenv("SHODAN_API_KEY")),
        "nvd_key_set": bool(os.getenv("NVD_API_KEY")),
    }
