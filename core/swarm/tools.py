"""
Инструменты CrewAI для PoC/эксплойтов.
Запуск и установка заблокированы, если ALLOW_EXPLOIT_EXECUTION != true.
"""

from __future__ import annotations

import os
import subprocess

from crewai_tools import tool

from core.security_mode import parse_bool_env
from ..pompem_client import PompemClient

_BLOCKED_MSG = (
    "ЗАБЛОКИРОВАНО: активная эксплуатация отключена. "
    "Режим по умолчанию — Security Assessment (VA). "
    "Для запуска PoC задайте ALLOW_EXPLOIT_EXECUTION=true в .env "
    "и выберите режим «Exploit Verification» в UI."
)


def _execution_allowed() -> bool:
    return parse_bool_env("ALLOW_EXPLOIT_EXECUTION", default=False)


@tool
def pompem_exploit_search(query: str) -> str:
    """
    Поиск эксплойтов и PoC в онлайн-базах (PacketStorm, CXSecurity) по названию технологии и версии.
    Возвращает список заголовков и ссылок на эксплойты.
    """
    client = PompemClient()
    results = client.search_all(query)

    if not results:
        return f"Эксплойтов для '{query}' не найдено в базах Pompem."

    output = [f"Результаты поиска Pompem для '{query}':"]
    for i, res in enumerate(results, 1):
        output.append(f"{i}. {res['title']} ({res['source']}) - {res['url']}")

    return "\n".join(output)


@tool
def pompem_exploit_download(url: str) -> str:
    """
    Загружает код эксплойта по прямой ссылке из PacketStorm или CXSecurity.
    Возвращает путь к сохраненному файлу или сообщение об ошибке.
    """
    client = PompemClient()
    path = client.download_exploit(url)

    if path:
        return f"Эксплойт успешно загружен: {path}"
    return f"Не удалось загрузить эксплойт по ссылке: {url}"


@tool
def install_exploit_dependencies(command: str) -> str:
    """
    Устанавливает зависимости для эксплойта. Доступно только в режиме Exploit Verification.
    """
    if not _execution_allowed():
        return _BLOCKED_MSG

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
        return f"Результат установки:\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}"
    except Exception as exc:
        return f"Ошибка при установке зависимостей: {exc}"


@tool
def execute_exploit_payload(command: str) -> str:
    """
    Запуск эксплойта. Доступно только при ALLOW_EXPLOIT_EXECUTION=true.
    """
    if not _execution_allowed():
        return _BLOCKED_MSG

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        return (
            f"Результат выполнения эксплойта:\nSTDOUT:\n{result.stdout}\n\n"
            f"STDERR:\n{result.stderr}"
        )
    except subprocess.TimeoutExpired:
        return "Ошибка: превышено время ожидания (60 сек)."
    except Exception as exc:
        return f"Критическая ошибка при запуске: {exc}"


# Инструменты, доступные только в режиме pentest_exploit (не регистрируются у агентов в VA)
EXPLOIT_EXECUTION_TOOLS = [install_exploit_dependencies, execute_exploit_payload]
