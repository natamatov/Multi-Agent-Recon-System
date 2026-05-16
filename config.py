"""
Модуль конфигурации: загрузка переменных окружения и строгая валидация.
Предназначен для запуска в Kali Linux с файлом .env в корне проекта.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from urllib.parse import urlparse

from dotenv import load_dotenv
import os


# IPv4 (упрощённая проверка) и hostname/URL
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


@dataclass(frozen=True)
class Settings:
    """Неизменяемый контейнер проверенных настроек приложения."""

    claude_api_key: str
    target: str


def _fail(message: str) -> None:
    """Выводит понятное сообщение об ошибке и завершает программу."""
    print(f"[ОШИБКА КОНФИГУРАЦИИ] {message}", file=sys.stderr)
    sys.exit(1)


def _validate_api_key(key: str | None) -> str:
    """
    Проверяет наличие и минимальную длину API-ключа Claude.
    Пустые и placeholder-значения отклоняются.
    """
    if not key or not key.strip():
        _fail(
            "Переменная CLAUDE_API_KEY не задана.\n"
            "Скопируйте .env.example в .env и укажите действующий ключ Anthropic."
        )

    cleaned = key.strip()
    placeholders = {
        "",
        "your_anthropic_api_key_here",
        "sk-...",
    }
    if cleaned.lower() in placeholders or len(cleaned) < 20:
        _fail(
            "CLAUDE_API_KEY выглядит недействительным (слишком короткий или шаблонный).\n"
            "Укажите реальный ключ в файле .env."
        )
    return cleaned


def _validate_target(raw: str | None) -> str:
    """
    Проверяет TARGET: допускаются IPv4, hostname и URL (http/https).
    Возвращает нормализованную строку цели.
    """
    if not raw or not raw.strip():
        _fail(
            "Переменная TARGET не задана.\n"
            "Укажите IP-адрес или URL цели в файле .env (см. .env.example)."
        )

    target = raw.strip()

    # URL с протоколом
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        if not parsed.netloc:
            _fail(f"Некорректный URL цели: {target}")
        return target.rstrip("/")

    # Чистый IPv4
    if _IPV4_RE.match(target):
        return target

    # hostname или host:port
    host_part = target.split(":")[0]
    if _HOSTNAME_RE.match(host_part) or host_part == "localhost":
        return target

    _fail(
        f"TARGET '{target}' не распознан как IP, hostname или URL.\n"
        "Примеры: 10.0.0.5, scanme.nmap.org, https://example.com"
    )
    raise AssertionError("unreachable")


def load_settings(env_path: str | None = None) -> Settings:
    """
    Загружает .env и возвращает объект Settings после валидации.
    При любой ошибке конфигурации завершает процесс с кодом 1.

    :param env_path: необязательный путь к .env; по умолчанию — .env в CWD.
    """
    load_dotenv(dotenv_path=env_path)

    api_key = _validate_api_key(os.getenv("CLAUDE_API_KEY"))
    target = _validate_target(os.getenv("TARGET"))

    return Settings(claude_api_key=api_key, target=target)
