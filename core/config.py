"""
Загрузка конфигурации из .env (CLAUDE_API_KEY).
TARGET передаётся через веб-интерфейс Streamlit.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    """Проверенные настройки приложения."""

    claude_api_key: str


def load_settings(env_path: str | None = None) -> Settings:
    """
    Загружает переменные окружения и возвращает Settings.

    :param env_path: путь к .env; по умолчанию — файл в корне проекта.
    :raises SystemExit: если CLAUDE_API_KEY отсутствует или недействителен.
    """
    load_dotenv(dotenv_path=env_path)

    raw_key = os.getenv("CLAUDE_API_KEY")
    if not raw_key or not raw_key.strip():
        print(
            "[ОШИБКА] CLAUDE_API_KEY не задан. "
            "Скопируйте .env.example в .env и укажите ключ Anthropic.",
            file=sys.stderr,
        )
        sys.exit(1)

    key = raw_key.strip()
    placeholders = {"", "your_anthropic_api_key_here", "sk-..."}
    if key.lower() in placeholders or len(key) < 20:
        print(
            "[ОШИБКА] CLAUDE_API_KEY выглядит шаблонным или слишком коротким.",
            file=sys.stderr,
        )
        sys.exit(1)

    return Settings(claude_api_key=key)


def try_load_settings(env_path: str | None = None) -> Settings | None:
    """
    Загружает настройки без завершения процесса (для Streamlit UI).

    :return: Settings или None, если ключ не задан / невалиден.
    """
    load_dotenv(dotenv_path=env_path)
    raw_key = os.getenv("CLAUDE_API_KEY")
    if not raw_key or not raw_key.strip():
        return None
    key = raw_key.strip()
    placeholders = {"", "your_anthropic_api_key_here", "sk-..."}
    if key.lower() in placeholders or len(key) < 20:
        return None
    return Settings(claude_api_key=key)
