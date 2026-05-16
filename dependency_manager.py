"""
Управление системными зависимостями (утилиты Kali Linux).
Проверка через utils.is_tool_available с интерактивной паузой.
"""

from __future__ import annotations

from typing import Iterable

from utils import SCANNER_TOOLS, check_nuclei_available, is_tool_available


# Утилиты пайплайна (включая nuclei и searchsploit)
DEFAULT_REQUIRED_TOOLS: tuple[str, ...] = SCANNER_TOOLS

# Подсказки для apt в Kali/Debian
_APT_PACKAGES: dict[str, str] = {
    "nmap": "nmap",
    "whatweb": "whatweb",
    "dirb": "dirb",
    "nuclei": "nuclei",
    "searchsploit": "exploitdb",
}


def ensure_nuclei_available() -> bool:
    """
    Проверяет Nuclei; при отсутствии — интерактивная установка.
    Используется из utils/dependency_manager перед запуском воркера.
    """
    if check_nuclei_available():
        return True
    _wait_for_tool_install("nuclei")
    return True


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

    :param tools: список имён; по умолчанию nmap, whatweb, dirb, nuclei, searchsploit.
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
