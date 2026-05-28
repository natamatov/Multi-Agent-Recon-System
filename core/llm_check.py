"""
Быстрая проверка доступности LLM API перед запуском аудита.
Позволяет показать пользователю понятную ошибку ещё до начала сканирования.
"""

from __future__ import annotations

import os
import socket
from typing import NamedTuple
from urllib.parse import urlparse

from core.logger import get_logger

log = get_logger("mars.llm_check")

_PROVIDER_ENDPOINTS: dict[str, str] = {
    "anthropic": "api.anthropic.com",
    "openai":    "api.openai.com",
    "ollama":    "localhost",
}
_PROVIDER_PORTS: dict[str, int] = {
    "anthropic": 443,
    "openai":    443,
    "ollama":    11434,
}


class LLMCheckResult(NamedTuple):
    ok: bool
    message: str
    hint: str = ""


def check_llm_connectivity(
    provider: str,
    model: str,
    api_key: str | None,
    api_base: str | None,
    timeout: float = 5.0,
) -> LLMCheckResult:
    """
    Проверяет доступность LLM перед аудитом.

    Не делает реальный API-вызов — только TCP-проверку endpoint'а.
    Возвращает LLMCheckResult(ok, message, hint).
    """
    provider = provider.lower()

    # ── 1. Проверка наличия API ключа ─────────────────────────────────────────
    if provider != "ollama" and not api_key:
        return LLMCheckResult(
            ok=False,
            message="API ключ не задан",
            hint=(
                "Укажите LLM_API_KEY в файле .env.\n"
                "Для Anthropic: sk-ant-api03-...\n"
                "Для OpenAI: sk-...\n"
                "Для локальных моделей без ключа: LLM_PROVIDER=ollama"
            ),
        )

    # ── 2. Определяем endpoint ────────────────────────────────────────────────
    if api_base:
        parsed = urlparse(api_base if "://" in api_base else f"https://{api_base}")
        host = parsed.hostname or "localhost"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    else:
        host = _PROVIDER_ENDPOINTS.get(provider, "api.openai.com")
        port = _PROVIDER_PORTS.get(provider, 443)

    # ── 3. TCP-проверка ────────────────────────────────────────────────────────
    if host == "localhost" or host == "127.0.0.1":
        # Ollama или локальный сервер
        try:
            with socket.create_connection((host, port), timeout=timeout):
                pass
            return LLMCheckResult(
                ok=True,
                message=f"✅ {provider.capitalize()} доступен ({host}:{port})",
            )
        except OSError:
            return LLMCheckResult(
                ok=False,
                message=f"Локальный сервер {host}:{port} недоступен",
                hint=(
                    f"Запустите Ollama: `ollama serve`\n"
                    f"Проверьте что модель загружена: `ollama pull {model}`"
                ),
            )
    else:
        # Внешний API
        try:
            with socket.create_connection((host, port), timeout=timeout):
                pass
            return LLMCheckResult(
                ok=True,
                message=f"✅ {provider.capitalize()} API доступен",
            )
        except socket.timeout:
            return LLMCheckResult(
                ok=False,
                message=f"Таймаут подключения к {host}:{port}",
                hint=(
                    "Проверьте интернет-соединение и firewall.\n"
                    "Если сеть ограничена — используйте Ollama: `LLM_PROVIDER=ollama`"
                ),
            )
        except socket.gaierror:
            return LLMCheckResult(
                ok=False,
                message=f"DNS не разрешает {host}",
                hint=(
                    "Нет интернета или DNS недоступен.\n"
                    "Для оффлайн-работы: LLM_PROVIDER=ollama + `ollama serve`"
                ),
            )
        except OSError as exc:
            return LLMCheckResult(
                ok=False,
                message=f"Нет соединения с {host}:{port} ({exc})",
                hint=(
                    "Проверьте интернет. Для локальной работы: "
                    "LLM_PROVIDER=ollama, LLM_MODEL=llama3"
                ),
            )


def check_from_settings(settings: object, timeout: float = 5.0) -> LLMCheckResult:
    """Удобная обёртка — принимает объект Settings."""
    provider = getattr(settings, "llm_provider", "anthropic")
    model    = getattr(settings, "llm_model",    "claude-3-5-sonnet-20241022")
    api_key  = getattr(settings, "llm_api_key",  None) or getattr(settings, "claude_api_key", None)
    api_base = getattr(settings, "llm_api_base", None)
    return check_llm_connectivity(provider, model, api_key, api_base, timeout=timeout)


def check_from_env(timeout: float = 5.0) -> LLMCheckResult:
    """Читает провайдер из окружения напрямую."""
    provider = os.getenv("LLM_PROVIDER", "anthropic")
    model    = os.getenv("LLM_MODEL", "claude-3-5-sonnet-20241022")
    api_key  = os.getenv("LLM_API_KEY") or os.getenv("CLAUDE_API_KEY")
    api_base = os.getenv("LLM_API_BASE")
    return check_llm_connectivity(provider, model, api_key, api_base, timeout=timeout)
