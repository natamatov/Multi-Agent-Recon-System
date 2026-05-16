"""
Интеграция с SearchSploit (Exploit-DB): поиск PoC по обнаруженным технологиям.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SearchsploitMatch:
    """Одна запись из JSON-вывода searchsploit."""

    title: str
    edb_id: str
    path: str
    exploit_type: str = ""


@dataclass
class SearchsploitResult:
    """Результат поиска по одному ключевому слову."""

    query: str
    matches: list[SearchsploitMatch] = field(default_factory=list)
    success: bool = True
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "success": self.success,
            "error": self.error_message,
            "matches": [
                {
                    "title": m.title,
                    "edb_id": m.edb_id,
                    "path": m.path,
                    "type": m.exploit_type,
                }
                for m in self.matches
            ],
        }


def run_searchsploit(query: str, timeout: int = 60) -> SearchsploitResult:
    """
    Выполняет `searchsploit --json <query>` и парсит результат.

    :param query: строка поиска (продукт + версия).
    :param timeout: таймаут subprocess в секундах.
    """
    command = ["searchsploit", "--json", query]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return SearchsploitResult(
            query=query,
            success=False,
            error_message="searchsploit не найден в PATH",
        )
    except subprocess.TimeoutExpired:
        return SearchsploitResult(
            query=query,
            success=False,
            error_message=f"Таймаут ({timeout} с)",
        )
    except OSError as exc:
        return SearchsploitResult(
            query=query,
            success=False,
            error_message=str(exc),
        )

    if completed.returncode not in (0, 1):
        # код 1 — «ничего не найдено» у searchsploit
        return SearchsploitResult(
            query=query,
            success=False,
            error_message=completed.stderr.strip() or f"exit {completed.returncode}",
        )

    raw = completed.stdout.strip()
    if not raw:
        return SearchsploitResult(query=query, matches=[])

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return SearchsploitResult(
            query=query,
            success=False,
            error_message="Невалидный JSON от searchsploit",
        )

    matches: list[SearchsploitMatch] = []
    results = data.get("RESULTS_EXPLOIT", [])
    if isinstance(results, list):
        for item in results[:10]:
            matches.append(
                SearchsploitMatch(
                    title=item.get("Title", ""),
                    edb_id=str(item.get("EDB-ID", "")),
                    path=item.get("Path", ""),
                    exploit_type=item.get("Type", ""),
                )
            )

    return SearchsploitResult(query=query, matches=matches)


def lookup_technologies(
    technologies: list[dict[str, Any]],
    *,
    max_queries: int = 5,
) -> list[dict[str, Any]]:
    """
    Для каждой технологии (name + version) выполняет searchsploit.

    :param technologies: список dict с ключами name, version.
    :param max_queries: ограничение числа запросов за прогон.
    """
    results: list[dict[str, Any]] = []
    for tech in technologies[:max_queries]:
        name = str(tech.get("name", "")).strip()
        version = str(tech.get("version", "")).strip()
        if not name:
            continue
        query = f"{name} {version}".strip()
        result = run_searchsploit(query)
        results.append(result.to_dict())
    return results
