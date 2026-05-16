"""
Модуль сбора данных: безопасный запуск утилит сканирования.
Параллельный запуск nmap, whatweb и nuclei через asyncio.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Sequence

from .nuclei_worker import NucleiScanResult, run_nuclei_scan_async
from .utils import build_url, extract_host


@dataclass
class ScanResult:
    """Результат одного сканирования: имя утилиты, команда, вывод или ошибка."""

    tool: str
    command: list[str]
    stdout: str = ""
    stderr: str = ""
    success: bool = True
    error_message: str | None = None


@dataclass
class ScanBundle:
    """Агрегированные результаты сканеров для AI и отчётов."""

    target: str
    results: list[ScanResult] = field(default_factory=list)
    nuclei: NucleiScanResult | None = None

    def to_log_text(self) -> str:
        """Сериализует результаты в единый текстовый лог."""
        sections: list[str] = [f"=== ЦЕЛЬ АУДИТА: {self.target} ===\n"]
        for item in self.results:
            sections.append(f"--- {item.tool.upper()} ---")
            sections.append(f"Команда: {' '.join(item.command)}")
            sections.append(f"Успех: {item.success}")
            if item.error_message:
                sections.append(f"Ошибка: {item.error_message}")
            if item.stderr.strip():
                sections.append(f"STDERR:\n{item.stderr.strip()}")
            sections.append(f"STDOUT:\n{item.stdout.strip() or '(пусто)'}")
            sections.append("")
        if self.nuclei:
            sections.append(self.nuclei.to_log_text())
        return "\n".join(sections)

    def to_aggregated_dict(self) -> dict[str, Any]:
        """
        Структурированные данные для Claude, NVD и HTML-отчёта.
        """
        scanners = {
            r.tool: {
                "success": r.success,
                "stdout": r.stdout,
                "stderr": r.stderr,
                "error": r.error_message,
                "command": r.command,
            }
            for r in self.results
        }
        nuclei_block: dict[str, Any] = {}
        if self.nuclei:
            nuclei_block = {
                "success": self.nuclei.success,
                "findings": [f.to_dict() for f in self.nuclei.findings],
                "cve_ids": self.nuclei.all_cve_ids(),
                "raw_log": self.nuclei.to_log_text(),
            }
        return {
            "target": self.target,
            "scanners": scanners,
            "nuclei": nuclei_block,
            "combined_logs": self.to_log_text(),
        }


async def _run_command_async(
    tool: str,
    command: Sequence[str],
    timeout: int = 600,
) -> ScanResult:
    """
    Асинхронный запуск внешней утилиты (без shell=True).
    """
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
        return ScanResult(
            tool=tool,
            command=list(command),
            success=False,
            error_message=f"Превышен таймаут ({timeout} с)",
        )
    except FileNotFoundError:
        return ScanResult(
            tool=tool,
            command=list(command),
            success=False,
            error_message=f"Утилита {tool} не найдена в PATH",
        )
    except OSError as exc:
        return ScanResult(
            tool=tool,
            command=list(command),
            success=False,
            error_message=f"Ошибка ОС: {exc}",
        )

    stdout = stdout_bytes.decode("utf-8", errors="replace")
    stderr = stderr_bytes.decode("utf-8", errors="replace")
    success = process.returncode == 0
    error_msg: str | None = None
    if not success:
        error_msg = f"Код возврата: {process.returncode}"

    combined = (stdout + stderr).lower()
    unreachable_markers = (
        "failed to resolve",
        "no route to host",
        "connection refused",
        "could not resolve",
        "0 hosts up",
        "unable to connect",
    )
    if any(marker in combined for marker in unreachable_markers):
        success = False
        error_msg = (error_msg or "") + " | Возможно, хост недоступен"

    return ScanResult(
        tool=tool,
        command=list(command),
        stdout=stdout,
        stderr=stderr,
        success=success,
        error_message=error_msg.strip() if error_msg else None,
    )


async def run_nmap_async(target: str, timeout: int = 600) -> ScanResult:
    """Nmap -sV: порты и версии сервисов."""
    host = extract_host(target)
    command = ["nmap", "-sV", "-T4", "--open", "-oN", "-", host]
    return await _run_command_async("nmap", command, timeout=timeout)


async def run_whatweb_async(target: str, timeout: int = 300) -> ScanResult:
    """WhatWeb: fingerprint веб-стека."""
    url = build_url(target)
    command = ["whatweb", "-a", "3", url]
    return await _run_command_async("whatweb", command, timeout=timeout)


async def run_dirb_async(target: str, timeout: int = 900) -> ScanResult:
    """Dirb: перебор директорий (после параллельной фазы)."""
    url = build_url(target)
    wordlist = "/usr/share/dirb/wordlists/common.txt"
    command = ["dirb", url, wordlist, "-S", "-r"]
    return await _run_command_async("dirb", command, timeout=timeout)

async def run_subfinder_async(target: str, timeout: int = 300) -> ScanResult:
    """Subfinder: пассивный поиск поддоменов."""
    host = extract_host(target)
    command = ["subfinder", "-d", host, "-silent"]
    return await _run_command_async("subfinder", command, timeout=timeout)


async def run_parallel_scans(target: str) -> ScanBundle:
    """
    Параллельно запускает nmap, whatweb и nuclei через asyncio.gather.
    Dirb выполняется последовательно после (длительный перебор).
    """
    bundle = ScanBundle(target=target)

    nmap_result, whatweb_result, nuclei_result, subfinder_result = await asyncio.gather(
        run_nmap_async(target),
        run_whatweb_async(target),
        run_nuclei_scan_async(target),
        run_subfinder_async(target),
    )

    bundle.results.extend([nmap_result, whatweb_result, subfinder_result])
    bundle.nuclei = nuclei_result

    print("[*] Dirb (последовательно)...")
    dirb_result = await run_dirb_async(target)
    bundle.results.append(dirb_result)

    return bundle
