"""
Воркер Nuclei: автоматическое сканирование с выводом -jsonl.
Шаблоны: теги cve, misconfig; severity critical, high, medium.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any

from .utils import build_url, extract_cve_ids


@dataclass
class NucleiFinding:
    """Нормализованная находка из одной строки JSONL Nuclei."""

    template_id: str
    name: str
    severity: str
    host: str
    matched_at: str
    description: str = ""
    cve_ids: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "template_id": self.template_id,
            "name": self.name,
            "severity": self.severity,
            "host": self.host,
            "matched_at": self.matched_at,
            "description": self.description,
            "cve_ids": self.cve_ids,
            "tags": self.tags,
        }


@dataclass
class NucleiScanResult:
    """Итог сканирования Nuclei."""

    target: str
    command: list[str]
    findings: list[NucleiFinding] = field(default_factory=list)
    stdout_raw: str = ""
    stderr: str = ""
    success: bool = True
    error_message: str | None = None

    def to_log_text(self) -> str:
        """Текстовое представление для AI-анализатора."""
        lines = [
            "=== NUCLEI SCAN ===",
            f"Команда: {' '.join(self.command)}",
            f"Находок: {len(self.findings)}",
            f"Успех: {self.success}",
        ]
        if self.error_message:
            lines.append(f"Ошибка: {self.error_message}")
        for finding in self.findings:
            lines.append(
                f"[{finding.severity.upper()}] {finding.name} @ {finding.matched_at}"
            )
            if finding.cve_ids:
                lines.append(f"  CVE: {', '.join(finding.cve_ids)}")
            if finding.description:
                lines.append(f"  Описание: {finding.description[:300]}")
        if not self.findings and self.stdout_raw.strip():
            lines.append(f"Сырой вывод:\n{self.stdout_raw[:2000]}")
        return "\n".join(lines)

    def all_cve_ids(self) -> list[str]:
        """Все CVE из находок Nuclei."""
        ids: set[str] = set()
        for f in self.findings:
            ids.update(f.cve_ids)
        ids.update(extract_cve_ids(self.stdout_raw))
        return sorted(ids)


def _parse_jsonl_line(line: str) -> NucleiFinding | None:
    """Парсит одну строку JSONL в NucleiFinding."""
    line = line.strip()
    if not line:
        return None
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None

    info = data.get("info", {})
    tags_raw = info.get("tags", [])
    if isinstance(tags_raw, str):
        tags = [t.strip() for t in tags_raw.split(",")]
    else:
        tags = list(tags_raw) if tags_raw else []

    classification = info.get("classification", {}) or {}
    cve_ids: list[str] = []
    cve_id = classification.get("cve-id")
    if cve_id:
        if isinstance(cve_id, list):
            cve_ids = [str(c).upper() for c in cve_id]
        else:
            cve_ids = [str(cve_id).upper()]

    text_blob = json.dumps(data)
    cve_ids = sorted(set(cve_ids) | set(extract_cve_ids(text_blob)))

    return NucleiFinding(
        template_id=data.get("template-id", data.get("templateID", "")),
        name=info.get("name", data.get("matcher-name", "unknown")),
        severity=(info.get("severity") or "unknown").lower(),
        host=data.get("host", ""),
        matched_at=data.get("matched-at", data.get("matched", "")),
        description=info.get("description", ""),
        cve_ids=cve_ids,
        tags=tags,
        raw=data,
    )


def _build_nuclei_command(target: str) -> list[str]:
    """Формирует argv для Nuclei: JSONL, теги cve/misconfig, severity."""
    url = build_url(target)
    return [
        "nuclei",
        "-u", url,
        "-jsonl",
        "-tags", "cve,misconfig",
        "-severity", "critical,high,medium",
        "-silent",
    ]


def run_nuclei_scan(target: str, timeout: int = 900) -> NucleiScanResult:
    """
    Синхронный запуск Nuclei (для тестов и fallback).
    """
    return asyncio.run(run_nuclei_scan_async(target, timeout=timeout))


async def run_nuclei_scan_async(
    target: str,
    timeout: int = 900,
) -> NucleiScanResult:
    """
    Асинхронный запуск Nuclei через asyncio.create_subprocess_exec.

    :param target: IP, hostname или URL из config.TARGET.
    :param timeout: максимальное время сканирования в секундах.
    """
    command = _build_nuclei_command(target)
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        return NucleiScanResult(
            target=target,
            command=command,
            success=False,
            error_message=f"Превышен таймаут Nuclei ({timeout} с)",
        )
    except FileNotFoundError:
        return NucleiScanResult(
            target=target,
            command=command,
            success=False,
            error_message="nuclei не найден в PATH",
        )
    except OSError as exc:
        return NucleiScanResult(
            target=target,
            command=command,
            success=False,
            error_message=str(exc),
        )

    stdout = stdout_bytes.decode("utf-8", errors="replace")
    stderr = stderr_bytes.decode("utf-8", errors="replace")

    findings: list[NucleiFinding] = []
    for line in stdout.splitlines():
        parsed = _parse_jsonl_line(line)
        if parsed:
            findings.append(parsed)

    success = process.returncode == 0 or bool(findings)
    error_msg: str | None = None
    if process.returncode != 0 and not findings:
        error_msg = f"Код возврата: {process.returncode}"

    return NucleiScanResult(
        target=target,
        command=command,
        findings=findings,
        stdout_raw=stdout,
        stderr=stderr,
        success=success,
        error_message=error_msg,
    )
