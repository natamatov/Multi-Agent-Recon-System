"""
Лёгкий AI-анализ: один вызов LLM без CrewAI.
"""

from __future__ import annotations

import json
import re
from typing import Any

from litellm import completion

from core.logger import get_logger

log = get_logger("mars.llm")

SYSTEM_PROMPT = (
    "Ты — старший инженер-аналитик по безопасности. "
    "Изучи логи nmap и whatweb. Определи версии ПО. "
    "Сопоставь с известными CVE. "
    "Отвечай СТРОГО валидным JSON: "
    '{"technologies": ["Apache 2.4"], '
    '"cves": [{"id": "CVE-XXXX", "severity": "High", '
    '"description": "...", "remediation": "..."}], '
    '"summary": "..."}'
)


class LightAnalyzer:
    """Один запрос к LLM API через LiteLLM."""

    def __init__(self, model: str, api_key: str | None = None, api_base: str | None = None) -> None:
        self.model = model
        self.api_key = api_key
        self.api_base = api_base

    def analyze(self, nmap_log: str, whatweb_log: str) -> dict[str, Any]:
        user_content = (
            "Верни ТОЛЬКО JSON.\n\n=== NMAP ===\n"
            f"{nmap_log}\n\n=== WHATWEB ===\n{whatweb_log}"
        )

        kwargs: dict[str, str] = {}
        if self.api_key:
            kwargs["api_key"] = self.api_key
        if self.api_base:
            kwargs["api_base"] = self.api_base

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content}
        ]

        try:
            response = completion(
                model=self.model,
                messages=messages,
                **kwargs
            )
            raw = response.choices[0].message.content
            return self._parse_json(raw or "", self.model)
        except Exception as exc:
            hint = _diagnose_llm_error(exc, self.model, self.api_key, self.api_base)
            log.error("LLM недоступен: %s | %s", exc, hint)
            return _ai_unavailable_result(str(exc), hint, self.model)

    @staticmethod
    def _parse_json(raw: str, model_name: str) -> dict[str, Any]:
        cleaned = raw.strip()
        fence = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned)
        if fence:
            cleaned = fence.group(1).strip()

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            data = {"summary": "Ошибка парсинга JSON от LLM.", "technologies": [], "cves": []}

        return {
            "success": True,
            "technologies": data.get("technologies", []),
            "cves": data.get("cves", []),
            "summary": data.get("summary", ""),
            "parsed_data": json.dumps(data.get("technologies", []), ensure_ascii=False),
            "cve_data": json.dumps(data.get("cves", []), ensure_ascii=False, indent=2),
            "exploit_data": "_Red Team отключён (лёгкий режим)._",
            "sigma_playbook": "",
            "osint_dorking": "",
            "audit_mode": "assessment",
            "audit_mode_label": f"Light VA ({model_name})",
            "red_team_enabled": False,
            "exploit_execution_enabled": False,
            "final_summary": data.get("summary", ""),
            "ai_engine": "light_litellm",
        }


# ─── Вспомогательные функции диагностики ──────────────────────────────────────

def _diagnose_llm_error(
    exc: Exception,
    model: str,
    api_key: str | None,
    api_base: str | None,
) -> str:
    """
    Анализирует исключение LiteLLM и возвращает конкретную подсказку.
    """
    msg = str(exc).lower()

    # Нет интернета / endpoint недоступен
    if "connection error" in msg or "connection refused" in msg or "connect call failed" in msg:
        endpoint = api_base or _default_endpoint(model)
        return (
            f"❌ Нет соединения с API ({endpoint}). "
            "Проверьте: интернет, firewall, VPN. "
            "Для локальных моделей — Ollama должен быть запущен: `ollama serve`"
        )

    # Неверный API ключ
    if "authentication" in msg or "api key" in msg or "unauthorized" in msg or "401" in msg:
        return (
            "❌ Неверный API ключ. "
            "Проверьте LLM_API_KEY в файле .env. "
            "Для Anthropic ключ начинается с `sk-ant-`, для OpenAI — `sk-`"
        )

    # Rate limit
    if "rate limit" in msg or "429" in msg or "quota" in msg:
        return (
            "⚠️ Rate limit или превышена квота API. "
            "Подождите несколько минут или проверьте баланс аккаунта."
        )

    # Неверная модель
    if "model" in msg and ("not found" in msg or "invalid" in msg or "does not exist" in msg):
        return (
            f"❌ Модель '{model}' не найдена. "
            "Проверьте LLM_MODEL в .env. "
            "Примеры: claude-3-5-sonnet-20241022, gpt-4o, llama3"
        )

    # Timeout
    if "timeout" in msg or "timed out" in msg:
        return (
            "⚠️ Таймаут подключения к LLM API. "
            "Проверьте соединение или используйте Ollama для локального запуска."
        )

    # Нет ключа
    if not api_key and "ollama" not in model.lower():
        return (
            "❌ API ключ не задан (LLM_API_KEY пустой в .env). "
            "Укажите ключ или переключитесь на Ollama (LLM_PROVIDER=ollama)."
        )

    return f"Проверьте настройки LLM в .env (провайдер: {model.split('/')[0]})"


def _default_endpoint(model: str) -> str:
    """Возвращает URL endpoint по умолчанию для модели."""
    m = model.lower()
    if "anthropic" in m:
        return "https://api.anthropic.com"
    if "ollama" in m:
        return "http://localhost:11434"
    return "https://api.openai.com"


def _ai_unavailable_result(error: str, hint: str, model: str) -> dict[str, Any]:
    """
    Возвращает частичный результат когда LLM недоступен.
    Аудит продолжается — сканеры уже отработали, данные сохраняются.
    """
    summary = (
        f"⚠️ **AI анализ недоступен** — результаты сканирования сохранены.\n\n"
        f"**Причина:** {hint}\n\n"
        "**Что сделать:**\n"
        "1. Проверьте файл `.env` → ключи LLM_API_KEY и LLM_PROVIDER\n"
        "2. Для оффлайн-работы: установите Ollama (`ollama serve`) и укажите "
        "`LLM_PROVIDER=ollama`, `LLM_MODEL=llama3`\n"
        "3. Данные nmap/nuclei/NVD/OSINT сохранены в отчёте — CVE можно изучить вручную."
    )
    return {
        "success": False,
        "error": error,
        "technologies": [],
        "cves": [],
        "summary": summary,
        "parsed_data": "",
        "cve_data": "",
        "exploit_data": "",
        "sigma_playbook": "",
        "osint_dorking": "",
        "audit_mode": "assessment",
        "audit_mode_label": f"AI недоступен ({model})",
        "red_team_enabled": False,
        "exploit_execution_enabled": False,
        "final_summary": summary,
        "ai_engine": "unavailable",
    }
