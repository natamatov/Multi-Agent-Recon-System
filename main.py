#!/usr/bin/env python3
"""
Оркестратор enterprise-аудита: параллельные сканеры, NVD, SearchSploit, Swarm AI (CrewAI), HTML/PDF.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.config import load_settings, validate_target_string
from core.dependency_manager import ensure_tools_available
from core.nvd_client import enrich_cves_from_text
from core.reporter import save_html_report, save_pdf_report
from core.scanner import ScanBundle, run_parallel_scans
from core.searchsploit_client import lookup_technologies
from core.shodan_client import run_shodan_recon
from core.utils import merge_unique_cves
from core.swarm.orchestrator import MARSSwarmManager

REPORT_JSON = "audit_report.json"
REPORT_HTML = "audit_report.html"
REPORT_PDF = "audit_report.pdf"

def build_final_report(
    target: str,
    bundle: ScanBundle,
    swarm_results: dict[str, Any],
    *,
    nvd_records: list[dict[str, Any]],
    searchsploit_results: list[dict[str, Any]],
) -> dict[str, Any]:
    """Собирает итоговый JSON для JSON/HTML отчётов."""
    nuclei_findings: list[dict[str, Any]] = []
    if bundle.nuclei:
        nuclei_findings = [f.to_dict() for f in bundle.nuclei.findings]

    scan_summary: dict[str, Any] = {
        r.tool: {"success": r.success, "error": r.error_message}
        for r in bundle.results
    }
    if bundle.nuclei:
        scan_summary["nuclei"] = {
            "success": bundle.nuclei.success,
            "findings_count": len(bundle.nuclei.findings),
            "error": bundle.nuclei.error_message,
        }

    return {
        "audit": {
            "target": target,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "platform": "Kali Linux / PentestPlatform Enterprise",
        },
        "scan_summary": scan_summary,
        "nuclei_findings": nuclei_findings,
        "nvd_enrichment": nvd_records,
        "searchsploit": searchsploit_results,
        "raw_scan_logs": bundle.to_log_text(),
        "ai_summary": swarm_results.get("final_summary", ""),
        "parsed_data": swarm_results.get("parsed_data", ""),
        "cve_data": swarm_results.get("cve_data", ""),
        "sigma_playbook": swarm_results.get("sigma_playbook", ""),
        "osint_dorking": swarm_results.get("osint_dorking", ""),
        "success": swarm_results.get("success", False),
        "error": swarm_results.get("error", "")
    }


async def _run_audit_async(target: str) -> dict[str, Any]:
    """Асинхронная фаза сканирования и обогащения."""
    print("[*] Параллельный запуск: nmap, whatweb, nuclei, subfinder, wpscan...")
    curr_settings = load_settings()
    bundle = await run_parallel_scans(target, wpscan_api_key=curr_settings.wpscan_api_key)

    for result in bundle.results:
        status = "OK" if result.success else "WARN"
        print(f"    [{status}] {result.tool}")
    if bundle.nuclei:
        status = "OK" if bundle.nuclei.success else "WARN"
        print(
            f"    [{status}] nuclei "
            f"({len(bundle.nuclei.findings)} находок)"
        )

    # NVD: извлечение CVE из всех логов
    logs = bundle.to_log_text()
    print("[*] Верификация CVE через NVD API...")
    nvd_key = os.getenv("NVD_API_KEY")
    nvd_records = enrich_cves_from_text(logs, api_key=nvd_key)
    print(f"    [+] NVD: обработано {len(nvd_records)} CVE")

    # Предварительный список технологий из логов для searchsploit (до AI)
    pre_tech = []
    if bundle.nuclei:
        for finding in bundle.nuclei.findings:
            pre_tech.append({"name": finding.name, "version": ""})

    print("[*] Поиск Exploit-DB (searchsploit)...")
    searchsploit_results = lookup_technologies(pre_tech) if pre_tech else []
    if not searchsploit_results:
        searchsploit_results = lookup_technologies(
            [{"name": target, "version": ""}],
            max_queries=1,
        )
    print(f"    [+] SearchSploit: {len(searchsploit_results)} запросов")

    print("[*] Пассивный OSINT (Shodan)...")
    # Достаем ключ из загруженных настроек
    from core.config import load_settings
    curr_settings = load_settings()
    shodan_res = run_shodan_recon(target, api_key=curr_settings.shodan_api_key)
    if shodan_res.get("success"):
        print(f"    [+] Shodan: найдено {len(shodan_res.get('open_ports', []))} портов")
    else:
        print(f"    [-] Shodan: {shodan_res.get('error')}")

    osint_data = f"SHODAN: {json.dumps(shodan_res, ensure_ascii=False)}\n\n"
    # Добавим поддомены из Subfinder к osint_data
    subfinder_res = next((r for r in bundle.results if r.tool == "subfinder"), None)
    if subfinder_res and subfinder_res.success:
        osint_data += f"SUBFINDER:\n{subfinder_res.stdout}\n"

    print("[*] Запуск AI Swarm (CrewAI)...")
    def step_callback(step):
        print("  [AI Agent]: Выполняется шаг анализа...")
        
    manager = MARSSwarmManager(step_callback=step_callback)
    swarm_results = manager.run_analysis(logs, osint_data=osint_data)
    
    if swarm_results.get("success"):
        print("[+] Swarm анализ успешно завершён.")
    else:
        print(f"[-] Ошибка Swarm: {swarm_results.get('error')}")

    return build_final_report(
        target,
        bundle,
        swarm_results,
        nvd_records=nvd_records,
        searchsploit_results=searchsploit_results,
    )


def main() -> None:
    """Точка входа."""
    print("=" * 60)
    print("  PentestPlatform — Enterprise Security Audit (Swarm Edition)")
    print("=" * 60)

    settings = load_settings()
    target = settings.target
    if not target:
        raw_target = input("Введите TARGET (IP, домен или URL): ").strip()
        try:
            target = validate_target_string(raw_target)
        except ValueError as e:
            print(f"[ОШИБКА] {e}")
            sys.exit(1)
            
    print(f"[+] Цель: {target}")

    print("[*] Проверка утилит (nmap, whatweb, dirb, nuclei, searchsploit, wkhtmltopdf)...")
    tools = ensure_tools_available()
    print(f"[+] Доступны: {', '.join(tools)}")

    try:
        final_report = asyncio.run(_run_audit_async(target))
    except RuntimeError as exc:
        print(f"[ОШИБКА] {exc}", file=sys.stderr)
        sys.exit(1)

    base = Path(__file__).resolve().parent
    
    # Save JSON
    json_path = base / REPORT_JSON
    json_path.write_text(json.dumps(final_report, ensure_ascii=False, indent=2), encoding="utf-8")
    
    # Save HTML
    save_html_report(final_report, str(base / REPORT_HTML))
    
    # Save PDF
    save_pdf_report(final_report, str(base / REPORT_PDF))

    print("\n[+] Аудит завершён.")
    print("=" * 60)
    if final_report.get("success"):
        print(final_report.get("ai_summary", "")[:500] + "...")


if __name__ == "__main__":
    main()
