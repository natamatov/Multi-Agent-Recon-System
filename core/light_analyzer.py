"""
Лёгкий AI-анализ: один вызов LLM без CrewAI.
"""

from __future__ import annotations

import json
import re
from typing import Any

from litellm import completion

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

        kwargs = {}
        if self.api_key:
            kwargs["api_key"] = self.api_key
        if self.api_base:
            kwargs["api_base"] = self.api_base

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content}
        ]

        response = completion(
            model=self.model,
            messages=messages,
            **kwargs
        )
        raw = response.choices[0].message.content
        return self._parse_json(raw or "", self.model)

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
