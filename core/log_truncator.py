"""
Усечение сырых логов перед отправкой в Claude/CrewAI (экономия токенов).
"""

from __future__ import annotations

import re

DEFAULT_MAX_CHARS = 48_000
NMPORT_OPEN_RE = re.compile(
    r"^(\d+)/tcp\s+open\s+(\S+)\s*(.*)$",
    re.MULTILINE,
)


def truncate_for_ai(text: str, max_chars: int = DEFAULT_MAX_CHARS) -> str:
    """
    Сохраняет начало и конец; для nmap извлекает открытые порты в summary-блок.
    """
    if len(text) <= max_chars:
        return text

    nmap_summary = _extract_nmap_summary(text)
    head = max_chars // 2
    tail = max_chars // 4
    truncated = (
        text[:head]
        + f"\n\n... [УСЕЧЕНО {len(text) - head - tail} символов] ...\n\n"
        + text[-tail:]
    )
    if nmap_summary:
        truncated = f"=== NMAP SUMMARY (auto) ===\n{nmap_summary}\n\n" + truncated
    return truncated[: max_chars + 2000]


def _extract_nmap_summary(text: str) -> str:
    lines: list[str] = []
    for match in NMPORT_OPEN_RE.finditer(text):
        port, svc, rest = match.groups()
        ver = rest.strip() or "?"
        lines.append(f"  {port}/tcp  {svc}  {ver}")
    if not lines:
        return ""
    return "OPEN PORTS:\n" + "\n".join(lines[:40])
