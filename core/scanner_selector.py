"""
Умный выбор сканеров по результатам nmap / whatweb.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000}
WORDPRESS_MARKERS = ("wordpress", "wp-content", "wp-includes")


@dataclass
class ScannerPlan:
    """Какие сканеры запускать на фазе 2."""

    always: list[str] = field(default_factory=lambda: ["nmap", "whatweb", "subfinder"])
    web: list[str] = field(default_factory=list)
    reasons: dict[str, str] = field(default_factory=dict)

    def all_tools(self) -> list[str]:
        return self.always + self.web


def analyze_scan_context(nmap_stdout: str, whatweb_stdout: str) -> dict[str, bool]:
    """Определяет контекст цели из логов."""
    open_ports: set[int] = set()
    for match in re.finditer(r"(\d+)/tcp\s+open", nmap_stdout or ""):
        try:
            open_ports.add(int(match.group(1)))
        except ValueError:
            pass

    combined = ((nmap_stdout or "") + (whatweb_stdout or "")).lower()
    has_web = bool(open_ports & WEB_PORTS) or "http" in combined or "https" in combined
    is_wordpress = any(m in combined for m in WORDPRESS_MARKERS)

    return {
        "has_web": has_web,
        "is_wordpress": is_wordpress,
        "open_ports": open_ports,
    }


def build_scanner_plan(nmap_stdout: str, whatweb_stdout: str) -> ScannerPlan:
    """
    Фаза 1: nmap, whatweb, subfinder.
    Фаза 2 (web): nuclei, nikto, ffuf, dirb; + wpscan если WordPress.
    """
    ctx = analyze_scan_context(nmap_stdout, whatweb_stdout)
    plan = ScannerPlan(
        always=["nmap", "whatweb", "subfinder"],
        reasons={
            "nmap": "базовый",
            "whatweb": "базовый",
            "subfinder": "пассивный OSINT",
        },
    )

    if not ctx["has_web"]:
        plan.reasons["_skip_web"] = (
            f"Веб-сканеры пропущены: нет открытых web-портов {sorted(ctx['open_ports'])[:8]}"
        )
        return plan

    plan.web = ["nuclei", "nikto", "ffuf", "dirb", "xsstrike"]
    for t in plan.web:
        plan.reasons[t] = "обнаружен веб-сервис"

    if ctx["is_wordpress"]:
        plan.web.append("wpscan")
        plan.reasons["wpscan"] = "обнаружен WordPress"

    return plan
