"""
AI-анализ логов сканирования через Anthropic Claude (только маппинг CVE).
"""

from __future__ import annotations

import json
import re
from typing import Any

from anthropic import Anthropic


MODEL_ID = "claude-3-5-sonnet-20240620"

SYSTEM_PROMPT = (
    "Ты — старший инженер-аналитик по безопасности. "
    "Изучи логи сканирования. Определи версии ПО. "
    "Сопоставь их с известными CVE (публичная база, без эксплуатации). "
    "Отвечай СТРОГО в формате валидного JSON: "
    '{"technologies": ["Apache 2.4", ...], '
    '"cves": [{"id": "CVE-XXXX-XXXX", "severity": "High", '
    '"description": "...", "remediation": "..."}], '
    '"summary": "..."}'
)


class ClaudeAnalyzer:
    """
    Отправляет логи Nmap и WhatWeb в Claude и возвращает структурированный JSON.
    """

    def __init__(self, api_key: str) -> None:
        self._client = Anthropic(api_key=api_key)

    def analyze(self, nmap_log: str, whatweb_log: str) -> dict[str, Any]:
        """
        Анализирует логи и возвращает dict с ключами technologies, cves, summary.

        :param nmap_log: stdout nmap.
        :param whatweb_log: stdout whatweb.
        :raises RuntimeError: при ошибке API или невалидном JSON.
        """
        user_content = (
            "Проанализируй логи ниже. Верни ТОЛЬКО JSON без markdown.\n\n"
            "=== NMAP ===\n"
            f"{nmap_log}\n\n"
            "=== WHATWEB ===\n"
            f"{whatweb_log}"
        )

        try:
            response = self._client.messages.create(
                model=MODEL_ID,
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_content}],
            )
        except Exception as exc:
            raise RuntimeError(f"Ошибка Claude API: {exc}") from exc

        raw = self._extract_text(response)
        return self._parse_json(raw)

    @staticmethod
    def _extract_text(response: Any) -> str:
        parts: list[str] = []
        for block in response.content:
            if getattr(block, "type", None) == "text":
                parts.append(block.text)
        if not parts:
            raise RuntimeError("Пустой ответ от Claude")
        return "\n".join(parts)

    @staticmethod
    def _parse_json(raw: str) -> dict[str, Any]:
        cleaned = raw.strip()
        fence = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned)
        if fence:
            cleaned = fence.group(1).strip()

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Невалидный JSON от Claude: {exc}") from exc

        if not isinstance(data, dict):
            raise RuntimeError("Ожидался JSON-объект")

        technologies = data.get("technologies", [])
        cves = data.get("cves", [])
        if not isinstance(technologies, list) or not isinstance(cves, list):
            raise RuntimeError("technologies и cves должны быть массивами")

        return {
            "technologies": technologies,
            "cves": cves,
            "summary": data.get("summary", ""),
        }
