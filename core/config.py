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
    claude_api_key: str
    target: str | None
    shodan_api_key: str | None = None
    wpscan_api_key: str | None = None
    virustotal_api_key: str | None = None
    network_interface: str | None = None
    source_ip: str | None = None
    http_proxy: str | None = None
    enable_red_team: bool = False
    allow_exploit_execution: bool = False


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

    :param env_path: необязательный путь к .env; по умолчанию — .env в CWD.
    """
    load_dotenv(dotenv_path=env_path)

    api_key = _validate_api_key(os.getenv("CLAUDE_API_KEY"))
    target = _validate_target(os.getenv("TARGET"))
    shodan_key = os.getenv("SHODAN_API_KEY")
    wpscan_key = os.getenv("WPSCAN_API_KEY")
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    net_iface = os.getenv("NETWORK_INTERFACE") or None
    source_ip = os.getenv("SOURCE_IP") or None
    http_proxy = os.getenv("HTTP_PROXY") or None

    return Settings(
        claude_api_key=api_key,
        target=target,
        shodan_api_key=shodan_key,
        wpscan_api_key=wpscan_key,
        virustotal_api_key=vt_key,
        network_interface=net_iface,
        source_ip=source_ip,
        http_proxy=http_proxy,
        enable_red_team=parse_bool_env("ENABLE_RED_TEAM", default=False),
        allow_exploit_execution=parse_bool_env("ALLOW_EXPLOIT_EXECUTION", default=False),
    )

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
        
    target = None
    raw_target = os.getenv("TARGET")
    if raw_target and raw_target.strip():
        try:
            target = validate_target_string(raw_target)
        except ValueError:
            target = None # Ignore invalid target in UI, user will type it
            
    shodan_key = os.getenv("SHODAN_API_KEY")
    wpscan_key = os.getenv("WPSCAN_API_KEY")
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    net_iface = os.getenv("NETWORK_INTERFACE") or None
    source_ip = os.getenv("SOURCE_IP") or None
    http_proxy = os.getenv("HTTP_PROXY") or None

    return Settings(
        claude_api_key=key,
        target=target,
        shodan_api_key=shodan_key,
        wpscan_api_key=wpscan_key,
        virustotal_api_key=vt_key,
        network_interface=net_iface,
        source_ip=source_ip,
        http_proxy=http_proxy,
        enable_red_team=parse_bool_env("ENABLE_RED_TEAM", default=False),
        allow_exploit_execution=parse_bool_env("ALLOW_EXPLOIT_EXECUTION", default=False),
    )
