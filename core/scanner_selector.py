"""
Умный выбор сканеров v2 — адаптивная стратегия по результатам nmap/whatweb.

Принцип: запускаем только то что имеет смысл для данной цели.
- Нет веб-сервиса → пропускаем все веб-сканеры
- HTTPS → добавляем testssl
- WordPress → добавляем wpscan
- Веб-приложение с формами → добавляем sqlmap, dalfox, arjun
- GitHub URL → добавляем trufflehog
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field

WEB_PORTS        = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 4443, 9443}
WORDPRESS_MARKERS = ("wordpress", "wp-content", "wp-includes", "wp-login")
HTTPS_MARKERS     = ("https", ":443", ":8443", "ssl", "tls")
FORMS_MARKERS     = ("form", "login", "search", "query", "q=", "id=", "user", "password", "signup")
GITHUB_MARKERS    = ("github.com", "gitlab.com", "bitbucket.org")
API_MARKERS       = ("api", "graphql", "rest", "swagger", "openapi", "json", "v1", "v2")


@dataclass
class ScannerPlan:
    """Какие сканеры запускать — с объяснением причин."""

    always: list[str] = field(default_factory=lambda: ["nmap", "whatweb", "subfinder"])
    web:    list[str] = field(default_factory=list)
    reasons: dict[str, str] = field(default_factory=dict)

    def all_tools(self) -> list[str]:
        return self.always + self.web


def _available(tool: str) -> bool:
    """True если инструмент установлен в системе."""
    return shutil.which(tool) is not None


def analyze_scan_context(nmap_stdout: str, whatweb_stdout: str) -> dict:
    """Извлекает контекст цели из результатов фазы 1."""
    nmap    = nmap_stdout    or ""
    whatweb = whatweb_stdout or ""
    combined = (nmap + whatweb).lower()

    # Открытые порты
    open_ports: set[int] = set()
    for m in re.finditer(r"(\d+)/tcp\s+open", nmap):
        try:
            open_ports.add(int(m.group(1)))
        except ValueError:
            pass

    # Базовые флаги
    has_web      = bool(open_ports & WEB_PORTS) or "http" in combined
    has_https    = any(m in combined for m in HTTPS_MARKERS)
    is_wordpress = any(m in combined for m in WORDPRESS_MARKERS)
    has_forms    = any(m in combined for m in FORMS_MARKERS)
    is_github    = any(m in combined for m in GITHUB_MARKERS)
    is_api       = any(m in combined for m in API_MARKERS)

    # Определяем тип приложения
    app_type = "generic"
    if is_wordpress:
        app_type = "wordpress"
    elif is_api:
        app_type = "api"
    elif has_forms:
        app_type = "webapp"

    return {
        "has_web":      has_web,
        "has_https":    has_https,
        "is_wordpress": is_wordpress,
        "has_forms":    has_forms,
        "is_github":    is_github,
        "is_api":       is_api,
        "app_type":     app_type,
        "open_ports":   open_ports,
    }


def build_scanner_plan(nmap_stdout: str, whatweb_stdout: str) -> ScannerPlan:
    """
    Строит план сканирования на основе анализа контекста.

    Логика:
    1. Всегда: nmap/rustscan, whatweb, subfinder, theHarvester, gau
    2. Веб-цели: nuclei, nikto, testssl (https), dalfox, feroxbuster/ffuf
    3. Приложения с формами: sqlmap, arjun
    4. WordPress: wpscan
    5. Git-репозитории: trufflehog
    """
    ctx  = analyze_scan_context(nmap_stdout, whatweb_stdout)
    plan = ScannerPlan(reasons={})

    # ── Базовые сканеры (фаза 1) ──────────────────────────────────────────────
    if _available("rustscan"):
        plan.always = ["rustscan", "whatweb", "subfinder"]
        plan.reasons["rustscan"] = "заменяет nmap на discovery-фазе (×100 быстрее)"
    else:
        plan.always = ["nmap", "whatweb", "subfinder"]
        plan.reasons["nmap"] = "базовый порт-скан"

    plan.reasons["whatweb"]   = "fingerprint веб-стека"
    plan.reasons["subfinder"] = "пассивный поиск субдоменов"

    # Всегда добавляем разведчиков если доступны
    if _available("theHarvester"):
        plan.always.append("theHarvester")
        plan.reasons["theHarvester"] = "OSINT: email, субдомены, сотрудники"
    if _available("gau"):
        plan.always.append("gau")
        plan.reasons["gau"] = "архивные URL из Wayback Machine / CommonCrawl"

    # ── Нет веба — возвращаем базовый план ───────────────────────────────────
    if not ctx["has_web"]:
        plan.reasons["_skip_web"] = (
            f"Веб-сканеры пропущены: нет открытых web-портов "
            f"{sorted(ctx['open_ports'])[:8]}"
        )
        return plan

    # ── Веб-сканеры (всегда для веб-цели) ────────────────────────────────────
    plan.web = ["nuclei", "nikto"]
    plan.reasons["nuclei"] = "шаблонное сканирование CVE"
    plan.reasons["nikto"]  = "опасные файлы и мисконфиги веб-сервера"

    # TLS/SSL — только для HTTPS
    if ctx["has_https"] and _available("testssl"):
        plan.web.append("testssl")
        plan.reasons["testssl"] = "TLS/SSL аудит (Heartbleed, BEAST, слабые шифры)"

    # XSS сканер — предпочитаем dalfox
    if _available("dalfox"):
        plan.web.append("dalfox")
        plan.reasons["dalfox"] = "XSS (DOM+Reflected+Stored), активно поддерживается"
    elif _available("xsstrike"):
        plan.web.append("xsstrike")
        plan.reasons["xsstrike"] = "XSS поиск"

    # Dir brute — предпочитаем feroxbuster
    if _available("feroxbuster"):
        plan.web.append("feroxbuster")
        plan.reasons["feroxbuster"] = "рекурсивный dir-brute (быстрее dirb)"
    elif _available("ffuf"):
        plan.web.append("ffuf")
        plan.reasons["ffuf"] = "быстрый dir-fuzzing"
    else:
        plan.web.append("dirb")
        plan.reasons["dirb"] = "брутфорс директорий"

    # ── Приложения с формами / параметрами ───────────────────────────────────
    if ctx["has_forms"] or ctx["app_type"] in ("webapp", "wordpress"):
        if _available("sqlmap"):
            plan.web.append("sqlmap")
            plan.reasons["sqlmap"] = "SQL-инъекции (forms обнаружены)"
        if _available("arjun"):
            plan.web.append("arjun")
            plan.reasons["arjun"] = "скрытые HTTP-параметры"

    # ── WordPress ─────────────────────────────────────────────────────────────
    if ctx["is_wordpress"]:
        plan.web.append("wpscan")
        plan.reasons["wpscan"] = "WordPress: плагины, темы, пользователи"

    # ── Git / GitHub ──────────────────────────────────────────────────────────
    if ctx["is_github"] and _available("trufflehog"):
        plan.web.append("trufflehog")
        plan.reasons["trufflehog"] = "утёкшие секреты в репозитории"

    return plan
