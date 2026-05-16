"""
Проверка наличия системных утилит сканирования в PATH (Kali Linux).
"""

from __future__ import annotations

import shutil
from typing import Final


# Утилиты, необходимые для легального пассивного/полуактивного VA
REQUIRED_TOOLS: Final[tuple[str, ...]] = ("nmap", "whatweb")

# Подсказки по установке в Debian/Kali
INSTALL_HINTS: Final[dict[str, str]] = {
    "nmap": "sudo apt install nmap",
    "whatweb": "sudo apt install whatweb",
}


def check_tools(tools: tuple[str, ...] | None = None) -> dict[str, bool]:
    """
    Проверяет доступность утилит через shutil.which.

    :param tools: список имён бинарников; по умолчанию nmap и whatweb.
    :return: словарь {имя_утилиты: True/False}.
    """
    names = tools if tools is not None else REQUIRED_TOOLS
    return {name: shutil.which(name) is not None for name in names}


def all_tools_ready(status: dict[str, bool]) -> bool:
    """True, если все утилиты из статуса доступны."""
    return all(status.values())


def missing_tools(status: dict[str, bool]) -> list[str]:
    """Список отсутствующих утилит."""
    return [name for name, ok in status.items() if not ok]
