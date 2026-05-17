"""
Лёгкий AI-анализ: один вызов Claude без CrewAI.
"""

from __future__ import annotations

import json
import re
from typing import Any

from anthropic import Anthropic

from core.llm_config import ANTHROPIC_MODEL

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


class LightClaudeAnalyzer:
    """Один запрос к Anthropic API."""

    def __init__(self, api_key: str) -> None:
        self._client = Anthropic(api_key=api_key)

    def analyze(self, nmap_log: str, whatweb_log: str) -> dict[str, Any]:
        user_content = (
            "Верни ТОЛЬКО JSON.\n\n=== NMAP ===\n"
            f"{nmap_log}\n\n=== WHATWEB ===\n{whatweb_log}"
        )
        response = self._client.messages.create(
            model=ANTHROPIC_MODEL,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_content}],
        )
        raw = "".join(
            b.text for b in response.content if getattr(b, "type", None) == "text"
        )
        return self._parse_json(raw)

    @staticmethod
    def _parse_json(raw: str) -> dict[str, Any]:
        cleaned = raw.strip()
        fence = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned)
        if fence:
            cleaned = fence.group(1).strip()
        data = json.loads(cleaned)
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
            "audit_mode_label": "Light VA (single Claude)",
            "red_team_enabled": False,
            "exploit_execution_enabled": False,
            "final_summary": data.get("summary", ""),
            "ai_engine": "light_claude",
        }
