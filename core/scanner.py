"""
Модуль сбора данных: безопасный запуск утилит сканирования.
Параллельный запуск nmap, whatweb и nuclei через asyncio.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Sequence

from core.audit_state import update_progress
from core.cancel_registry import AuditCancellation, AuditCancelledError, is_audit_cancelled

from .nuclei_worker import NucleiScanResult, run_nuclei_scan_async
from .utils import build_url, extract_host
from .waf_detector import run_waf_check


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
    waf: dict[str, Any] | None = None
    scanner_plan: dict[str, Any] | None = None

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
        if self.waf and self.waf.get("detected"):
            sections.append("--- WAF / CDN DETECTION ---")
            sections.append(f"Обнаружено: {', '.join(self.waf.get('providers', []))}")
            sections.append("Рекомендации по обходу:")
            for hint in self.waf.get("hints", []):
                sections.append(f" - {hint}")
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
            "waf": self.waf,
            "combined_logs": self.to_log_text(),
        }


async def _run_command_async(
    tool: str,
    command: Sequence[str],
    timeout: int = 600,
) -> ScanResult:
    """
    Асинхронный запуск внешней утилиты (без shell=True).
    Регистрирует PID для отмены через AuditCancellation.
    """
    if is_audit_cancelled():
        return ScanResult(
            tool=tool,
            command=list(command),
            success=False,
            error_message="Аудит отменён",
        )

    cancel = AuditCancellation.get()
    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        if process.pid:
            cancel.register_pid(process.pid)
            update_progress(
                f"Сканер {tool} (pid {process.pid})",
                cancel.snapshot_pids(),
            )

        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout,
        )
    except AuditCancelledError:
        if process and process.returncode is None:
            process.kill()
        return ScanResult(
            tool=tool,
            command=list(command),
            success=False,
            error_message="Аудит отменён",
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


async def run_nmap_async(
    target: str,
    timeout: int = 600,
    interface: str | None = None,
    source_ip: str | None = None,
) -> ScanResult:
    """Nmap -sV: порты и версии сервисов."""
    host = extract_host(target)
    command = ["nmap", "-sV", "-T4", "--open", "-oN", "-", host]
    if interface:
        command.extend(["-e", interface])
    if source_ip:
        command.extend(["-S", source_ip])
    return await _run_command_async("nmap", command, timeout=timeout)


async def run_whatweb_async(
    target: str,
    timeout: int = 300,
    proxy: str | None = None,
) -> ScanResult:
    """WhatWeb: fingerprint веб-стека."""
    url = build_url(target)
    command = ["whatweb", "-a", "3", url]
    if proxy:
        command.extend(["--proxy", proxy])
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

async def run_wpscan_async(target: str, api_key: str | None = None, timeout: int = 600) -> ScanResult:
    """WPScan: сканирование WordPress. Завершится быстро, если это не WP."""
    url = build_url(target)
    command = ["wpscan", "--url", url, "-e", "vp,vt,u", "--batch"]
    if api_key:
        command.extend(["--api-token", api_key])
    return await _run_command_async("wpscan", command, timeout=timeout)


async def run_nikto_async(target: str, timeout: int = 600) -> ScanResult:
    """Nikto: активное сканирование веб-сервера (устаревшее ПО, опасные файлы, настройки)."""
    url = build_url(target)
    command = ["nikto", "-h", url, "-nointeractive", "-Format", "txt"]
    return await _run_command_async("nikto", command, timeout=timeout)


async def run_ffuf_async(target: str, timeout: int = 300) -> ScanResult:
    """ffuf: быстрый fuzzing директорий и файлов (альтернатива dirb)."""
    url = build_url(target)
    wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
    # fallback на dirb wordlist если seclists не установлены
    import os
    if not os.path.exists(wordlist):
        wordlist = "/usr/share/dirb/wordlists/common.txt"
    command = ["ffuf", "-u", f"{url}/FUZZ", "-w", wordlist, "-mc", "200,301,302,403", "-t", "50", "-s"]
    return await _run_command_async("ffuf", command, timeout=timeout)


async def run_xsstrike_async(target: str, timeout: int = 600, xsstrike_path: str = "xsstrike") -> ScanResult:
    """XSStrike: расширенный поиск XSS."""
    url = build_url(target)
    if xsstrike_path.endswith(".py"):
        command = ["python3", xsstrike_path, "-u", url, "--crawl"]
    else:
        command = [xsstrike_path, "-u", url, "--crawl"]
    return await _run_command_async("xsstrike", command, timeout=timeout)


async def run_light_scans(
    target: str,
    *,
    network_interface: str | None = None,
    source_ip: str | None = None,
    http_proxy: str | None = None,
) -> ScanBundle:
    """Лёгкий профиль: только nmap и whatweb параллельно."""
    bundle = ScanBundle(target=target)
    nmap_r, whatweb_r = await asyncio.gather(
        run_nmap_async(target, interface=network_interface, source_ip=source_ip),
        run_whatweb_async(target, proxy=http_proxy),
    )
    bundle.results.extend([nmap_r, whatweb_r])
    return bundle


async def run_smart_scans(
    target: str,
    wpscan_api_key: str | None = None,
    network_interface: str | None = None,
    source_ip: str | None = None,
    http_proxy: str | None = None,
    xsstrike_path: str = "xsstrike",
) -> ScanBundle:
    """
    Умный режим: фаза 1 nmap+whatweb+subfinder, затем веб-сканеры по контексту.
    """
    from core.scanner_selector import build_scanner_plan

    bundle = ScanBundle(target=target)

    nmap_r, whatweb_r, subfinder_r = await asyncio.gather(
        run_nmap_async(target, interface=network_interface, source_ip=source_ip),
        run_whatweb_async(target, proxy=http_proxy),
        run_subfinder_async(target),
    )
    bundle.results.extend([nmap_r, whatweb_r, subfinder_r])

    plan = build_scanner_plan(nmap_r.stdout, whatweb_r.stdout)
    bundle.scanner_plan = {
        "tools": plan.all_tools(),
        "web": plan.web,
        "reasons": plan.reasons,
    }

    if not plan.web:
        url = build_url(target)
        bundle.waf = run_waf_check(url)
        return bundle

    tasks: list[Any] = []
    tool_names: list[str] = []
    if "nuclei" in plan.web:
        tasks.append(run_nuclei_scan_async(target))
        tool_names.append("nuclei")
    if "wpscan" in plan.web:
        tasks.append(run_wpscan_async(target, api_key=wpscan_api_key))
        tool_names.append("wpscan")
    if "nikto" in plan.web:
        tasks.append(run_nikto_async(target))
        tool_names.append("nikto")
    if "xsstrike" in plan.web:
        tasks.append(run_xsstrike_async(target, xsstrike_path=xsstrike_path))
        tool_names.append("xsstrike")

    results = await asyncio.gather(*tasks) if tasks else []

    idx = 0
    for name in tool_names:
        if name == "nuclei":
            bundle.nuclei = results[idx]
            idx += 1
        else:
            bundle.results.append(results[idx])
            idx += 1

    if "ffuf" in plan.web or "dirb" in plan.web:
        phase2 = []
        if "ffuf" in plan.web:
            phase2.append(run_ffuf_async(target))
        if "dirb" in plan.web:
            phase2.append(run_dirb_async(target))
        extra = await asyncio.gather(*phase2)
        bundle.results.extend(extra)

    url = build_url(target)
    bundle.waf = run_waf_check(url)
    return bundle


async def run_parallel_scans(
    target: str,
    wpscan_api_key: str | None = None,
    network_interface: str | None = None,
    source_ip: str | None = None,
    http_proxy: str | None = None,
    xsstrike_path: str = "xsstrike",
) -> ScanBundle:
    """
    Параллельно запускает все сканеры.
    """
    bundle = ScanBundle(target=target)

    nmap_r, whatweb_r, nuclei_r, subfinder_r, wpscan_r, nikto_r, xsstrike_r = await asyncio.gather(
        run_nmap_async(target, interface=network_interface, source_ip=source_ip),
        run_whatweb_async(target, proxy=http_proxy),
        run_nuclei_scan_async(target),
        run_subfinder_async(target),
        run_wpscan_async(target, api_key=wpscan_api_key),
        run_nikto_async(target),
        run_xsstrike_async(target, xsstrike_path=xsstrike_path),
    )

    bundle.results.extend([nmap_r, whatweb_r, subfinder_r, wpscan_r, nikto_r, xsstrike_r])
    bundle.nuclei = nuclei_r

    print("[*] WAF detection (WebCheck logic)...")
    url = build_url(target)
    bundle.waf = run_waf_check(url)

    print("[*] ffuf (быстрый fuzzing, параллельно с dirb)...")
    ffuf_result, dirb_result = await asyncio.gather(
        run_ffuf_async(target),
        run_dirb_async(target),
    )
    bundle.results.extend([ffuf_result, dirb_result])

    return bundle
