"""
Управление системными зависимостями (утилиты Kali Linux).
Проверка через utils.is_tool_available с интерактивной паузой.
"""

from __future__ import annotations

import shutil
from typing import Iterable

# Утилиты пайплайна (включая nuclei, searchsploit, wkhtmltopdf)
DEFAULT_REQUIRED_TOOLS: tuple[str, ...] = ("nmap", "whatweb", "dirb", "nuclei", "searchsploit", "wkhtmltopdf")

# Подсказки для apt в Kali/Debian
_APT_PACKAGES: dict[str, str] = {
    "nmap": "nmap",
    "whatweb": "whatweb",
    "dirb": "dirb",
    "nuclei": "nuclei",
    "searchsploit": "exploitdb",
    "wkhtmltopdf": "wkhtmltopdf",
}

def is_tool_available(tool_name: str) -> bool:
    """Проверяет доступность утилит через shutil.which."""
    return shutil.which(tool_name) is not None

def check_tools(tools: tuple[str, ...] | None = None) -> dict[str, bool]:
    """
    Проверяет доступность утилит. Используется в Streamlit.
    """
    names = tools if tools is not None else DEFAULT_REQUIRED_TOOLS
    return {name: is_tool_available(name) for name in names}

def all_tools_ready(status: dict[str, bool]) -> bool:
    """True, если все утилиты из статуса доступны."""
    return all(status.values())

def missing_tools(status: dict[str, bool]) -> list[str]:
    """Список отсутствующих утилит."""
    return [name for name, ok in status.items() if not ok]

def _wait_for_tool_install(tool_name: str) -> None:
    """
    Блокирует выполнение, пока пользователь не установит утилиту
    и не подтвердит это нажатием Enter.
    """
    package = _APT_PACKAGES.get(tool_name, tool_name)
    while True:
        print(
            f"\nУтилита [{tool_name}] не найдена. "
            f"Пожалуйста, установите ее вручную "
            f"(например: sudo apt install {package})"
        )
        input("Нажмите Enter после установки...")
        if is_tool_available(tool_name):
            print(f"[OK] Утилита [{tool_name}] обнаружена.\n")
            return

def ensure_tools_available(
    tools: Iterable[str] | None = None,
) -> list[str]:
    """
    Гарантирует наличие всех перечисленных утилит.
    При отсутствии — пауза и повторная проверка (без падения скрипта).

    :param tools: список имён.
    :return: список утилит, успешно найденных в PATH.
    """
    required = list(tools) if tools is not None else list(DEFAULT_REQUIRED_TOOLS)
    available: list[str] = []

    for tool in required:
        if is_tool_available(tool):
            available.append(tool)
        else:
            _wait_for_tool_install(tool)
            available.append(tool)

    return available
