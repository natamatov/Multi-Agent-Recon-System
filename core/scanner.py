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


# ─── NEW TOOLS v2 ─────────────────────────────────────────────────────────────

async def run_rustscan_async(
    target: str,
    timeout: int = 120,
) -> ScanResult:
    """
    RustScan: обнаружение открытых портов за секунды, затем передача в nmap -sV.
    В 100× быстрее чистого nmap на discovery-фазе.
    """
    host = extract_host(target)
    command = [
        "rustscan",
        "-a", host,
        "--ulimit", "5000",
        "-b", "2500",
        "--timeout", "3000",
        "--",          # всё что дальше — передаётся в nmap
        "-sV",
        "--script", "default,vuln",
    ]
    return await _run_command_async("rustscan", command, timeout=timeout)


async def run_naabu_async(
    target: str,
    timeout: int = 120,
) -> ScanResult:
    """naabu (ProjectDiscovery): быстрый порт-скан, хорошо работает в связке с httpx."""
    host = extract_host(target)
    command = [
        "naabu",
        "-host", host,
        "-silent",
        "-json",
        "-top-ports", "1000",
    ]
    return await _run_command_async("naabu", command, timeout=timeout)


async def run_httpx_async(
    targets: list[str] | str,
    timeout: int = 120,
) -> ScanResult:
    """
    httpx (ProjectDiscovery): быстрая проверка HTTP-сервисов.
    Принимает список субдоменов/хостов — возвращает живые с заголовками.
    """
    import os as _os
    import tempfile

    if isinstance(targets, str):
        targets = [targets]

    # Записываем список в tmp файл
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8"
    )
    tmp.write("\n".join(targets))
    tmp.close()

    command = [
        "httpx",
        "-l", tmp.name,
        "-title",
        "-status-code",
        "-tech-detect",
        "-content-length",
        "-follow-redirects",
        "-silent",
        "-json",
    ]
    result = await _run_command_async("httpx", command, timeout=timeout)
    try:
        _os.unlink(tmp.name)
    except OSError:
        pass
    return result


async def run_gau_async(target: str, timeout: int = 120) -> ScanResult:
    """
    gau (GetAllUrls): URL из Wayback Machine, CommonCrawl, OTX, URLscan.
    Находит старые API эндпоинты, backup файлы, забытые пути.
    """
    host = extract_host(target)
    command = [
        "gau",
        "--threads", "5",
        "--subs",           # включать субдомены
        "--blacklist", "png,jpg,gif,svg,woff,woff2,ttf,ico,css",
        host,
    ]
    return await _run_command_async("gau", command, timeout=timeout)


async def run_sqlmap_async(
    target: str,
    timeout: int = 600,
    forms: bool = True,
) -> ScanResult:
    """
    sqlmap: автоматическое обнаружение и анализ SQL-инъекций.
    Режим: только обнаружение (--technique=B,E,U,S,T), без извлечения данных.
    """
    url = build_url(target)
    command = [
        "sqlmap",
        "-u", url,
        "--batch",              # без интерактива
        "--level=2",            # глубина проверок (1-5)
        "--risk=1",             # безопасность (1-3, 1=безопасный)
        "--technique=BEUST",    # Boolean, Error, Union, Stacked, Time-based
        "--random-agent",
        "--output-dir=/tmp/sqlmap_mars",
        "--answers=quit=N,crack=N",  # не пытаться взламывать хеши
    ]
    if forms:
        command.extend(["--forms", "--crawl=2"])
    return await _run_command_async("sqlmap", command, timeout=timeout)


async def run_testssl_async(target: str, timeout: int = 300) -> ScanResult:
    """
    testssl.sh: полный TLS/SSL аудит.
    Проверяет: протоколы, шифры, Heartbleed, POODLE, BEAST, CRIME, HSTS, cert expiry.
    """
    host = extract_host(target)
    # Определяем порт
    port = "443"
    if ":443" in target or target.startswith("https://"):
        port = "443"
    elif ":8443" in target:
        port = "8443"

    command = [
        "testssl",
        "--severity",  "MEDIUM",
        "--quiet",
        "--warnings",  "off",
        "--color",     "0",
        "--jsonfile",  "/tmp/testssl_mars.json",
        f"{host}:{port}",
    ]
    return await _run_command_async("testssl", command, timeout=timeout)


async def run_dalfox_async(target: str, timeout: int = 300) -> ScanResult:
    """
    dalfox: современный XSS-сканер с DOM XSS поддержкой.
    Лучше xsstrike: активно поддерживается, pipeline mode, BXSS.
    """
    url = build_url(target)
    command = [
        "dalfox",
        "url", url,
        "--silence",
        "--no-color",
        "--format", "json",
        "--deep-domxss",
        "--follow-redirects",
        "--timeout", "10",
    ]
    return await _run_command_async("dalfox", command, timeout=timeout)


async def run_feroxbuster_async(target: str, timeout: int = 600) -> ScanResult:
    """
    feroxbuster: рекурсивный брутфорс директорий.
    Быстрее dirb, поддерживает рекурсию, умную фильтрацию.
    """
    url = build_url(target)

    import os as _os
    # Предпочтительный wordlist — SecLists, fallback на dirb
    wordlists = [
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/dirb/wordlists/common.txt",
    ]
    wordlist = next((w for w in wordlists if _os.path.exists(w)), wordlists[-1])

    command = [
        "feroxbuster",
        "--url", url,
        "--depth", "3",
        "--wordlist", wordlist,
        "--filter-status", "404",
        "--silent",
        "--json",
        "--output", "/tmp/ferox_mars.json",
        "--threads", "50",
    ]
    return await _run_command_async("feroxbuster", command, timeout=timeout)


async def run_theharvester_async(target: str, timeout: int = 180) -> ScanResult:
    """
    theHarvester: OSINT — email-адреса, субдомены, сотрудники через Google/Bing/LinkedIn.
    """
    host = extract_host(target)
    command = [
        "theHarvester",
        "-d", host,
        "-b", "google,bing,yahoo,duckduckgo,sublist3r,anubis",
        "-l", "200",          # лимит результатов
        "-f", "/tmp/harvester_mars",
    ]
    return await _run_command_async("theHarvester", command, timeout=timeout)


async def run_trufflehog_async(target: str, timeout: int = 300) -> ScanResult:
    """
    trufflehog: поиск утёкших секретов (API ключи, пароли, токены) в git-репозиториях.
    Особенно полезно если цель имеет публичный GitHub.
    """
    host = extract_host(target)
    # Если это github.com URL — сканируем как git
    if "github.com" in host:
        scan_url = build_url(target)
        command = ["trufflehog", "git", scan_url, "--only-verified", "--json"]
    else:
        # Попытка найти репо по организации
        command = [
            "trufflehog", "github",
            "--org", host.split(".")[0],
            "--only-verified",
            "--json",
        ]
    return await _run_command_async("trufflehog", command, timeout=timeout)


async def run_arjun_async(target: str, timeout: int = 300) -> ScanResult:
    """
    arjun: обнаружение скрытых HTTP-параметров.
    Находит GET/POST параметры, которые не видны в коде, но обрабатываются сервером.
    """
    url = build_url(target)
    command = [
        "arjun",
        "-u", url,
        "--stable",
        "-oJ", "/tmp/arjun_mars.json",
        "-q",
    ]
    return await _run_command_async("arjun", command, timeout=timeout)


async def run_xsstrike_async(target: str, timeout: int = 600, xsstrike_path: str = "xsstrike") -> ScanResult:
    """XSStrike: расширенный поиск XSS."""
    url = build_url(target)
    if xsstrike_path.endswith(".py"):
        command = ["python3", xsstrike_path, "-u", url, "--crawl"]
    else:
        command = [xsstrike_path, "-u", url, "--crawl"]
    return await _run_command_async("xsstrike", command, timeout=timeout)


# ─── NEW TOOLS v3 ─────────────────────────────────────────────────────────────

async def run_amass_async(target: str, timeout: int = 300) -> ScanResult:
    """
    amass: комплексное сопоставление поверхности атаки.
    Субдомены, ASN-блоки, связанные IP через 20+ пассивных источников.
    Лучше subfinder для корпоративных сетей.
    """
    host = extract_host(target)
    command = [
        "amass", "enum",
        "-passive",          # пассивный режим — не касаемся цели напрямую
        "-d", host,
        "-timeout", "5",     # максимум 5 минут
        "-silent",
    ]
    return await _run_command_async("amass", command, timeout=timeout)


async def run_dnsrecon_async(target: str, timeout: int = 120) -> ScanResult:
    """
    dnsrecon: DNS zone transfer, cache snooping, brute-force субдоменов.
    Особенно эффективен при неправильно настроенном DNS (zone transfer открыт).
    """
    host = extract_host(target)
    command = [
        "dnsrecon",
        "-d", host,
        "-t", "std,axfr,bing",   # стандарт + попытка zone transfer + Bing enum
        "--json", "/tmp/dnsrecon_mars.json",
    ]
    return await _run_command_async("dnsrecon", command, timeout=timeout)


async def run_cewl_async(target: str, timeout: int = 180) -> ScanResult:
    """
    CeWL: генерирует кастомный wordlist из содержимого сайта.
    Слова из контента → используются для password spraying, dir brute.
    """
    url = build_url(target)
    command = [
        "cewl",
        url,
        "-d", "2",                       # глубина обхода
        "-m", "5",                       # минимальная длина слова
        "-w", "/tmp/cewl_mars_wordlist.txt",
        "--lowercase",
    ]
    return await _run_command_async("cewl", command, timeout=timeout)


async def run_kiterunner_async(target: str, timeout: int = 300) -> ScanResult:
    """
    kiterunner (kr): бруте API эндпоинтов из openapi/swagger словарей.
    Идеален для REST API целей — находит скрытые /api/v1/..., /graphql, /swagger.
    """
    import os as _os
    url = build_url(target)
    # Словарь: предпочитаем routes-large от Assetnote
    wordlists = [
        "/usr/share/kiterunner/routes-large.kite",
        "/opt/kiterunner/routes-large.kite",
        "routes-large.kite",
    ]
    wordlist = next((w for w in wordlists if _os.path.exists(w)), wordlists[0])
    command = [
        "kr", "scan",
        url,
        "-w", wordlist,
        "--max-connection-per-host", "5",
        "--delay", "100ms",
        "--fail-status-codes", "400,401,403,404,429,500,501,502,503",
        "--output", "text",
    ]
    return await _run_command_async("kiterunner", command, timeout=timeout)


async def run_semgrep_async(target: str, timeout: int = 300) -> ScanResult:
    """
    semgrep: SAST — статический анализ исходного кода на паттерны уязвимостей.
    Используется если цель — git-репозиторий или локальный путь к коду.
    """
    import os as _os

    # Определяем путь: локальная директория или URL репо
    if _os.path.isdir(target):
        scan_path = target
    elif _os.path.isdir("/tmp/semgrep_repo"):
        scan_path = "/tmp/semgrep_repo"
    else:
        return ScanResult(
            tool="semgrep",
            command=[],
            success=False,
            error_message="semgrep: цель не является локальной директорией",
        )

    command = [
        "semgrep",
        "--config=auto",           # автоматически подбирает правила по языку
        "--json",
        "--output=/tmp/semgrep_mars.json",
        "--quiet",
        "--metrics=off",
        scan_path,
    ]
    return await _run_command_async("semgrep", command, timeout=timeout)


async def run_hydra_async(
    target: str,
    service: str = "ssh",
    timeout: int = 300,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
) -> ScanResult:
    """
    Hydra: брутфорс логинов сервисов (SSH, FTP, HTTP-Form, SMB и др.).
    Только для авторизованного тестирования! Требует ENABLE_RED_TEAM=true.
    service: ssh, ftp, smb, rdp, http-form-post
    """
    import os as _os
    if _os.getenv("ENABLE_RED_TEAM", "").lower() not in ("1", "true", "yes"):
        return ScanResult(
            tool="hydra",
            command=[],
            success=False,
            error_message="hydra отключён: требует ENABLE_RED_TEAM=true",
        )

    host = extract_host(target)
    # Стандартный список пользователей для тестирования
    user_list = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
    if not _os.path.exists(user_list):
        user_list = "admin"   # базовый фолбэк

    command = [
        "hydra",
        "-L", user_list,
        "-P", wordlist,
        "-t", "4",           # 4 потока (бережно)
        "-f",                # останавливаться на первом успехе
        "-w", "10",          # таймаут ожидания ответа (10 сек)
        host,
        service,
    ]
    return await _run_command_async("hydra", command, timeout=timeout)


async def run_light_scans(
    target: str,
    *,
    network_interface: str | None = None,
    source_ip: str | None = None,
    http_proxy: str | None = None,
) -> ScanBundle:
    """
    Лёгкий профиль: nmap/rustscan + whatweb параллельно.
    Если rustscan доступен — использует его вместо nmap (быстрее).
    """
    import shutil as _shutil
    bundle = ScanBundle(target=target)

    if _shutil.which("rustscan"):
        port_scan = run_rustscan_async(target)
    else:
        port_scan = run_nmap_async(target, interface=network_interface, source_ip=source_ip)

    port_r, whatweb_r = await asyncio.gather(port_scan, run_whatweb_async(target, proxy=http_proxy))
    bundle.results.extend([port_r, whatweb_r])
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
    Умный режим v2: адаптивный выбор инструментов по контексту цели.

    Фаза 1 (параллельно): порт-скан + whatweb + subfinder + theHarvester + gau
    Фаза 2 (по контексту): web-сканеры выбираются по результатам фазы 1
    """
    import shutil as _shutil

    from core.scanner_selector import build_scanner_plan

    bundle = ScanBundle(target=target)

    # ── Фаза 1: разведка ──────────────────────────────────────────────────────
    port_scan_coro = (
        run_rustscan_async(target)
        if _shutil.which("rustscan")
        else run_nmap_async(target, interface=network_interface, source_ip=source_ip)
    )

    recon_coros: list[Any] = [
        port_scan_coro,
        run_whatweb_async(target, proxy=http_proxy),
        run_subfinder_async(target),
    ]
    if _shutil.which("theHarvester"):
        recon_coros.append(run_theharvester_async(target))
    if _shutil.which("gau"):
        recon_coros.append(run_gau_async(target))
    if _shutil.which("dnsrecon"):
        recon_coros.append(run_dnsrecon_async(target))

    recon_results = await asyncio.gather(*recon_coros)
    port_r, whatweb_r, subfinder_r = recon_results[0], recon_results[1], recon_results[2]
    bundle.results.extend([port_r, whatweb_r, subfinder_r])
    for extra_r in recon_results[3:]:
        bundle.results.append(extra_r)

    # ── Строим план фазы 2 ────────────────────────────────────────────────────
    plan = build_scanner_plan(port_r.stdout, whatweb_r.stdout)
    bundle.scanner_plan = {
        "tools":   plan.all_tools(),
        "web":     plan.web,
        "reasons": plan.reasons,
    }

    if not plan.web:
        bundle.waf = run_waf_check(build_url(target))
        return bundle

    # ── Фаза 2A: параллельные веб-сканеры ─────────────────────────────────────
    phase2a_tasks: list[Any] = []
    phase2a_names: list[str] = []

    def _add(name: str, coro: Any) -> None:
        phase2a_tasks.append(coro)
        phase2a_names.append(name)

    if "nuclei"     in plan.web:
        _add("nuclei",      run_nuclei_scan_async(target))
    if "nikto"      in plan.web:
        _add("nikto",       run_nikto_async(target))
    if "testssl"    in plan.web:
        _add("testssl",     run_testssl_async(target))
    if "dalfox"     in plan.web:
        _add("dalfox",      run_dalfox_async(target))
    if "sqlmap"     in plan.web:
        _add("sqlmap",      run_sqlmap_async(target))
    if "arjun"      in plan.web:
        _add("arjun",       run_arjun_async(target))
    if "wpscan"     in plan.web:
        _add("wpscan",      run_wpscan_async(target, api_key=wpscan_api_key))
    if "xsstrike"   in plan.web:
        _add("xsstrike",    run_xsstrike_async(target, xsstrike_path=xsstrike_path))
    if "trufflehog" in plan.web:
        _add("trufflehog",  run_trufflehog_async(target))
    if "semgrep"    in plan.web:
        _add("semgrep",     run_semgrep_async(target))
    if "kiterunner" in plan.web:
        _add("kiterunner",  run_kiterunner_async(target))
    if "cewl"       in plan.web:
        _add("cewl",        run_cewl_async(target))

    phase2a_results = await asyncio.gather(*phase2a_tasks) if phase2a_tasks else []
    for name, res in zip(phase2a_names, phase2a_results):
        if name == "nuclei":
            bundle.nuclei = res
        else:
            bundle.results.append(res)

    # ── Фаза 2B: dir brute (медленнее, запускаем последними) ─────────────────
    phase2b: list[Any] = []
    if "feroxbuster" in plan.web and _shutil.which("feroxbuster"):
        phase2b.append(run_feroxbuster_async(target))
    elif "ffuf" in plan.web:
        phase2b.append(run_ffuf_async(target))
    if "dirb" in plan.web and not phase2b:
        phase2b.append(run_dirb_async(target))

    # httpx для субдоменов из subfinder
    if subfinder_r.success and subfinder_r.stdout.strip() and _shutil.which("httpx"):
        subdomains = [s.strip() for s in subfinder_r.stdout.splitlines() if s.strip()]
        if subdomains:
            phase2b.append(run_httpx_async(subdomains[:50]))  # лимит 50

    # amass — дополнительная субдомен-разведка (запускаем в фазе 2 из-за времени)
    if _shutil.which("amass"):
        phase2b.append(run_amass_async(target))

    if phase2b:
        extra = await asyncio.gather(*phase2b)
        bundle.results.extend(extra)

    bundle.waf = run_waf_check(build_url(target))
    return bundle


async def _skip_scan(tool: str) -> ScanResult:
    """Placeholder для инструментов не установленных в системе."""
    return ScanResult(tool=tool, command=[], success=False, error_message="not installed")


async def run_parallel_scans(
    target: str,
    wpscan_api_key: str | None = None,
    network_interface: str | None = None,
    source_ip: str | None = None,
    http_proxy: str | None = None,
    xsstrike_path: str = "xsstrike",
) -> ScanBundle:
    """
    Полный параллельный запуск ВСЕХ сканеров (USE_SMART_SCANNERS=false).
    Использует rustscan вместо nmap если доступен.
    """
    import shutil as _shutil
    bundle = ScanBundle(target=target)

    port_scan = (
        run_rustscan_async(target)
        if _shutil.which("rustscan")
        else run_nmap_async(target, interface=network_interface, source_ip=source_ip)
    )

    # Запускаем всё параллельно — кроме dir-brute (тяжёлые, во второй волне)
    wave1 = await asyncio.gather(
        port_scan,
        run_whatweb_async(target, proxy=http_proxy),
        run_nuclei_scan_async(target),
        run_subfinder_async(target),
        run_wpscan_async(target, api_key=wpscan_api_key),
        run_nikto_async(target),
        run_testssl_async(target),
        run_dalfox_async(target),
        run_sqlmap_async(target),
        run_gau_async(target),
        run_theharvester_async(target) if _shutil.which("theHarvester") else _skip_scan("theHarvester"),
        run_trufflehog_async(target)   if _shutil.which("trufflehog")   else _skip_scan("trufflehog"),
        run_arjun_async(target)        if _shutil.which("arjun")        else _skip_scan("arjun"),
    )

    port_r, whatweb_r, nuclei_r, subfinder_r, wpscan_r, nikto_r, testssl_r, \
        dalfox_r, sqlmap_r, gau_r, *optional_r = wave1

    bundle.nuclei = nuclei_r  # type: ignore
    for r in [port_r, whatweb_r, subfinder_r, wpscan_r, nikto_r,
              testssl_r, dalfox_r, sqlmap_r, gau_r]:
        if isinstance(r, ScanResult):
            bundle.results.append(r)
    for r in optional_r:
        # _skip_scan stubs have command=[] — skip tools that were not installed
        if isinstance(r, ScanResult) and r.command:
            bundle.results.append(r)

    bundle.waf = run_waf_check(build_url(target))

    # Вторая волна: dir brute + httpx для субдоменов
    wave2_coros: list[Any] = []
    if _shutil.which("feroxbuster"):
        wave2_coros.append(run_feroxbuster_async(target))
    else:
        wave2_coros.extend([run_ffuf_async(target), run_dirb_async(target)])

    if subfinder_r.success and subfinder_r.stdout.strip() and _shutil.which("httpx"):
        subs = [s.strip() for s in subfinder_r.stdout.splitlines() if s.strip()][:50]
        if subs:
            wave2_coros.append(run_httpx_async(subs))

    if wave2_coros:
        wave2 = await asyncio.gather(*wave2_coros)
        for r in wave2:
            if isinstance(r, ScanResult):
                bundle.results.append(r)

    return bundle
