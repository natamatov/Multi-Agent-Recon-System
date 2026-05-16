"""
Аналитика через Anthropic Claude: Nmap, WhatWeb, Nuclei + NVD/SearchSploit контекст.
"""

from __future__ import annotations

import json
import re
from typing import Any

from anthropic import Anthropic


MODEL_ID = "claude-3-5-sonnet-20240620"

SYSTEM_PROMPT = (
    "Ты — эксперт по кибербезопасности уровня enterprise. "
    "Тебе переданы агрегированные данные от Nmap, WhatWeb, Nuclei, "
    "а также результаты верификации CVE через NVD и поиска Exploit-DB (SearchSploit). "
    "Твои задачи:\n"
    "1. Построить карту технологий и сервисов хоста (имя, версия, доказательство).\n"
    "2. Сопоставить сырые находки Nuclei (misconfig, CVE-теги) с общей картой CVE хоста — "
    "укажи, какие Nuclei-баги подтверждают или дополняют CVE из Nmap/WhatWeb/NVD.\n"
    "3. Объединить CVE из всех источников; для каждого указать severity, CVSS (если есть), "
    "компонент, nvd_verified (true/false), связь с Nuclei (nuclei_confirmed).\n"
    "4. Сформировать developer_instructions — пошаговые действия для разработчиков "
    "(патчи, конфиги, заголовки, отключение сервисов).\n"
    "Верни ТОЛЬКО валидный JSON без markdown."
)


class SecurityAuditAnalyzer:
    """
    Анализирует агрегированные данные сканирования и обогащения CVE.
    """

    def __init__(self, api_key: str) -> None:
        self._client = Anthropic(api_key=api_key)

    def analyze(self, aggregated: dict[str, Any]) -> dict[str, Any]:
        """
        Отправляет структурированные данные в Claude.

        :param aggregated: dict от ScanBundle.to_aggregated_dict() + nvd + searchsploit.
        """
        payload_json = json.dumps(aggregated, ensure_ascii=False, indent=2)
        user_prompt = (
            "Проанализируй агрегированные данные аудита. "
            "Особое внимание: сопоставь findings Nuclei с CVE-картой хоста.\n\n"
            "Верни JSON строго такой структуры:\n"
            "{\n"
            '  "technologies": [\n'
            '    {"name": "...", "version": "...", "evidence": "..."}\n'
            "  ],\n"
            '  "cves": [\n'
            '    {\n'
            '      "id": "CVE-....",\n'
            '      "severity": "critical|high|medium|low",\n'
            '      "cvss_score": 9.8,\n'
            '      "description": "...",\n'
            '      "affected_component": "...",\n'
            '      "nvd_verified": true,\n'
            '      "nuclei_confirmed": true,\n'
            '      "nuclei_template": "..."\n'
            "    }\n"
            "  ],\n"
            '  "nuclei_correlations": [\n'
            '    {"finding": "...", "related_cves": ["CVE-..."], "notes": "..."}\n'
            "  ],\n"
            '  "developer_instructions": [\n'
            '    {"title": "...", "action": "...", "priority": "critical|high|medium"}\n'
            "  ],\n"
            '  "summary": "краткий executive summary"\n'
            "}\n\n"
            "=== АГРЕГИРОВАННЫЕ ДАННЫЕ ===\n"
            f"{payload_json}"
        )

        try:
            response = self._client.messages.create(
                model=MODEL_ID,
                max_tokens=8192,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
            )
        except Exception as exc:
            raise RuntimeError(f"Ошибка вызова Claude API: {exc}") from exc

        raw_text = self._extract_text(response)
        return self._parse_json_response(raw_text)

    @staticmethod
    def _extract_text(response: Any) -> str:
        parts: list[str] = []
        for block in response.content:
            if getattr(block, "type", None) == "text":
                parts.append(block.text)
        if not parts:
            raise RuntimeError("Claude вернул пустой ответ")
        return "\n".join(parts)

    @staticmethod
    def _parse_json_response(raw: str) -> dict[str, Any]:
        cleaned = raw.strip()
        fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned)
        if fence_match:
            cleaned = fence_match.group(1).strip()

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"Claude вернул невалидный JSON: {exc}\nФрагмент: {cleaned[:500]}"
            ) from exc

        if not isinstance(data, dict):
            raise RuntimeError("Ожидался JSON-объект верхнего уровня")

        technologies = data.get("technologies", [])
        cves = data.get("cves", [])

        if not isinstance(technologies, list) or not isinstance(cves, list):
            raise RuntimeError("Поля technologies и cves должны быть массивами")

        return {
            "technologies": technologies,
            "cves": cves,
            "nuclei_correlations": data.get("nuclei_correlations", []),
            "developer_instructions": data.get("developer_instructions", []),
            "summary": data.get("summary", ""),
            "metadata": {
                "model": MODEL_ID,
                "analyzer": "SecurityAuditAnalyzer",
            },
        }


def save_report(report: dict[str, Any], path: str = "audit_report.json") -> None:
    """Сохраняет финальный JSON-отчёт."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    print(f"[OK] JSON-отчёт: {path}")
