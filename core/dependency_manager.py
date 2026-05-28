"""
Управление системными зависимостями M.A.R.S. v2.
Проверяет наличие всех CLI-инструментов пайплайна.
"""

from __future__ import annotations

import shutil
from typing import Iterable

# ── Ядро (обязательные) ───────────────────────────────────────────────────────
CORE_TOOLS: tuple[str, ...] = (
    "nmap",
    "whatweb",
    "nuclei",
    "wkhtmltopdf",
)

# ── Расширенные (желательные, но не обязательные) ─────────────────────────────
EXTENDED_TOOLS: tuple[str, ...] = (
    # Быстрый порт-скан
    "rustscan",
    "naabu",
    # Веб-сканирование
    "nikto",
    "ffuf",
    "feroxbuster",
    "dirb",
    "wpscan",
    # Уязвимости
    "sqlmap",
    "testssl",
    "dalfox",
    "xsstrike",
    # Разведка
    "subfinder",
    "theHarvester",
    "httpx",
    "gau",
    # v3: Расширенная разведка
    "amass",
    "dnsrecon",
    # Секреты
    "trufflehog",
    # Параметры
    "arjun",
    # v3: API / SAST
    "kr",
    "semgrep",
    "cewl",
    # v3: Брутфорс (Red Team)
    "hydra",
    # Эксплойты
    "searchsploit",
)

# Все для отображения в UI
DEFAULT_REQUIRED_TOOLS: tuple[str, ...] = CORE_TOOLS + EXTENDED_TOOLS + (
    "pompem",
    "webcheck",
)

# apt-пакеты для каждого инструмента
_APT_PACKAGES: dict[str, str] = {
    # Core
    "nmap":          "nmap",
    "whatweb":       "whatweb",
    "nuclei":        "nuclei",
    "wkhtmltopdf":   "wkhtmltopdf",
    # Port scan
    "rustscan":      "rustscan",
    "naabu":         "naabu",
    # Web
    "nikto":         "nikto",
    "ffuf":          "ffuf",
    "feroxbuster":   "feroxbuster",
    "dirb":          "dirb",
    "wpscan":        "wpscan",
    # Vulnerabilities
    "sqlmap":        "sqlmap",
    "testssl":       "testssl.sh",
    "dalfox":        "dalfox",
    "xsstrike":      "xsstrike",
    # Recon
    "subfinder":     "subfinder",
    "theHarvester":  "theharvester",
    "httpx":         "httpx",
    "gau":           "gau",
    # v3: Extended recon
    "amass":         "amass",
    "dnsrecon":      "dnsrecon",
    # Secrets
    "trufflehog":    "trufflehog",
    # Params
    "arjun":         "python3-arjun",
    # v3: API / SAST / wordlist
    "kr":            "go install github.com/assetnote/kiterunner/cmd/kr@latest",
    "semgrep":       "pip install semgrep",
    "cewl":          "cewl",
    # v3: Bruteforce (Red Team)
    "hydra":         "hydra",
    # Exploits
    "searchsploit":  "exploitdb",
    # Built-in
    "pompem":        "Встроено (M.A.R.S. Exploit Client)",
    "webcheck":      "Встроено (M.A.R.S. WAF Detector)",
}

# Категории для красивого отображения в UI
TOOL_CATEGORIES: dict[str, list[str]] = {
    "🔴 Ядро (обязательные)": list(CORE_TOOLS),
    "⚡ Порт-скан":           ["rustscan", "naabu"],
    "🔬 Веб-сканирование":    ["nikto", "ffuf", "feroxbuster", "dirb", "wpscan"],
    "🐛 Уязвимости":          ["sqlmap", "testssl", "dalfox", "xsstrike"],
    "🌐 Разведка":            ["subfinder", "theHarvester", "httpx", "gau", "amass", "dnsrecon"],
    "🔑 Секреты":             ["trufflehog"],
    "🔍 Параметры":           ["arjun"],
    "🔌 API / SAST":          ["kr", "semgrep", "cewl"],
    "🔨 Брутфорс (RedTeam)":  ["hydra"],
    "💣 Эксплойты":           ["searchsploit"],
    "⚙️  Встроенные":         ["pompem", "webcheck"],
}


def is_tool_available(tool_name: str) -> bool:
    """True если инструмент установлен или является встроенным модулем."""
    if tool_name in ("pompem", "webcheck"):
        return True  # встроены в ядро M.A.R.S.
    return shutil.which(tool_name) is not None


def check_tools(tools: tuple[str, ...] | None = None) -> dict[str, bool]:
    """Проверяет доступность инструментов. Используется в Streamlit UI."""
    names = tools if tools is not None else DEFAULT_REQUIRED_TOOLS
    return {name: is_tool_available(name) for name in names}


def check_core_tools() -> dict[str, bool]:
    """Проверяет только обязательные инструменты ядра."""
    return {name: is_tool_available(name) for name in CORE_TOOLS}


def all_tools_ready(status: dict[str, bool]) -> bool:
    return all(status.values())


def missing_tools(status: dict[str, bool]) -> list[str]:
    return [name for name, ok in status.items() if not ok]


def core_tools_ready() -> bool:
    """True если все обязательные инструменты присутствуют."""
    return all(is_tool_available(t) for t in CORE_TOOLS)


def _wait_for_tool_install(tool_name: str) -> None:
    package = _APT_PACKAGES.get(tool_name, tool_name)
    while True:
        print(
            f"\nУтилита [{tool_name}] не найдена. "
            f"Установите: sudo apt install {package}"
        )
        input("Нажмите Enter после установки...")
        if is_tool_available(tool_name):
            print(f"[OK] {tool_name} обнаружен.\n")
            return


def ensure_tools_available(tools: Iterable[str] | None = None) -> list[str]:
    """Гарантирует наличие инструментов, ожидает установки при отсутствии."""
    required  = list(tools) if tools is not None else list(CORE_TOOLS)
    available: list[str] = []
    for tool in required:
        if is_tool_available(tool):
            available.append(tool)
        else:
            _wait_for_tool_install(tool)
            available.append(tool)
    return available
