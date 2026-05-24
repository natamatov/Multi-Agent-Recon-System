"""
Модуль конфигурации: загрузка переменных окружения и строгая валидация.
Предназначен для запуска в Kali Linux с файлом .env в корне проекта.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from urllib.parse import urlparse

from dotenv import load_dotenv

from .security_mode import parse_bool_env

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
    llm_provider: str
    llm_model: str
    llm_api_key: str | None
    llm_api_base: str | None
    claude_api_key: str | None
    target: str | None
    shodan_api_key: str | None = None
    wpscan_api_key: str | None = None
    virustotal_api_key: str | None = None
    network_interface: str | None = None
    source_ip: str | None = None
    http_proxy: str | None = None
    xsstrike_path: str = "xsstrike"
    enable_red_team: bool = False
    allow_exploit_execution: bool = False


def _fail(message: str) -> None:
    """Выводит понятное сообщение об ошибке и завершает программу."""
    print(f"[ОШИБКА КОНФИГУРАЦИИ] {message}", file=sys.stderr)
    sys.exit(1)


def _get_llm_settings() -> tuple[str, str, str | None, str | None, str | None]:
    """Извлекает настройки LLM из окружения."""
    provider = os.getenv("LLM_PROVIDER", "anthropic").strip().lower()
    model = os.getenv("LLM_MODEL", "claude-3-5-sonnet-20241022").strip()
    api_key = os.getenv("LLM_API_KEY")
    api_base = os.getenv("LLM_API_BASE")
    claude_key = os.getenv("CLAUDE_API_KEY")

    # Очистка ключей от плейсхолдеров
    if api_key and (api_key.strip() == "" or "your_" in api_key):
        api_key = None
    if claude_key and (claude_key.strip() == "" or "your_" in claude_key):
        claude_key = None

    return provider, model, api_key, api_base, claude_key


def validate_target_string(raw: str) -> str:
    """
    Проверяет TARGET: допускаются IPv4, hostname и URL (http/https).
    Возвращает нормализованную строку цели.
    Выбрасывает ValueError при ошибке.
    """
    target = raw.strip()

    # URL с протоколом
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        if not parsed.netloc:
            raise ValueError(f"Некорректный URL цели: {target}")
        return target.rstrip("/")

    # Чистый IPv4
    if _IPV4_RE.match(target):
        return target

    # hostname или host:port
    host_part = target.split(":")[0]
    if _HOSTNAME_RE.match(host_part) or host_part == "localhost":
        return target

    raise ValueError(
        f"TARGET '{target}' не распознан как IP, hostname или URL.\n"
        "Примеры: 10.0.0.5, scanme.nmap.org, https://example.com"
    )

def _validate_target(raw: str | None) -> str | None:
    """
    Валидирует TARGET, если он задан. Если нет - возвращает None.
    """
    if not raw or not raw.strip():
        return None
    try:
        return validate_target_string(raw)
    except ValueError as e:
        _fail(str(e))
        raise AssertionError("unreachable")


def load_settings(env_path: str | None = None) -> Settings:
    """
    Загружает .env и возвращает объект Settings после валидации.
    При любой ошибке конфигурации завершает процесс с кодом 1.
    """
    load_dotenv(dotenv_path=env_path, override=True)

    provider, model, api_key, api_base, claude_key = _get_llm_settings()

    if provider != "ollama" and not api_key and not claude_key:
        _fail("API ключ для LLM не задан. Укажите LLM_API_KEY или CLAUDE_API_KEY в .env")

    target = _validate_target(os.getenv("TARGET"))

    return Settings(
        llm_provider=provider,
        llm_model=model,
        llm_api_key=api_key,
        llm_api_base=api_base,
        claude_api_key=claude_key,
        target=target,
        shodan_api_key=os.getenv("SHODAN_API_KEY"),
        wpscan_api_key=os.getenv("WPSCAN_API_KEY"),
        virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY"),
        network_interface=os.getenv("NETWORK_INTERFACE") or None,
        source_ip=os.getenv("SOURCE_IP") or None,
        http_proxy=os.getenv("HTTP_PROXY") or None,
        xsstrike_path=os.getenv("XSSTRIKE_PATH", "xsstrike"),
        enable_red_team=parse_bool_env("ENABLE_RED_TEAM", default=False),
        allow_exploit_execution=parse_bool_env("ALLOW_EXPLOIT_EXECUTION", default=False),
    )


def try_load_settings(env_path: str | None = None) -> Settings:
    """
    Загружает настройки без завершения процесса (для Streamlit UI).
    Всегда возвращает Settings, чтобы UI мог загрузиться.
    """
    load_dotenv(dotenv_path=env_path, override=True)

    provider, model, api_key, api_base, claude_key = _get_llm_settings()

    target = None
    raw_target = os.getenv("TARGET")
    if raw_target and raw_target.strip():
        try:
            target = validate_target_string(raw_target)
        except ValueError:
            target = None

    return Settings(
        llm_provider=provider,
        llm_model=model,
        llm_api_key=api_key,
        llm_api_base=api_base,
        claude_api_key=claude_key,
        target=target,
        shodan_api_key=os.getenv("SHODAN_API_KEY"),
        wpscan_api_key=os.getenv("WPSCAN_API_KEY"),
        virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY"),
        network_interface=os.getenv("NETWORK_INTERFACE") or None,
        source_ip=os.getenv("SOURCE_IP") or None,
        http_proxy=os.getenv("HTTP_PROXY") or None,
        xsstrike_path=os.getenv("XSSTRIKE_PATH", "xsstrike"),
        enable_red_team=parse_bool_env("ENABLE_RED_TEAM", default=False),
        allow_exploit_execution=parse_bool_env("ALLOW_EXPLOIT_EXECUTION", default=False),
    )
