#!/usr/bin/env python3
"""
Оркестратор enterprise-аудита: параллельные сканеры, NVD, SearchSploit, Claude, HTML.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ai_analyzer import SecurityAuditAnalyzer, save_report
from config import Settings, load_settings
from dependency_manager import ensure_tools_available
from nvd_client import enrich_cves_from_text
from reporter import save_html_report
from scanner import ScanBundle, run_parallel_scans
from searchsploit_client import lookup_technologies
from utils import merge_unique_cves


REPORT_JSON = "audit_report.json"
REPORT_HTML = "audit_report.html"


def _merge_nvd_into_cves(
    ai_cves: list[dict[str, Any]],
    nvd_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Объединяет CVE от Claude с верифицированными данными NVD (CVSS, описание).
    """
    nvd_map = {r["id"].upper(): r for r in nvd_records if r.get("id")}
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()

    for cve in ai_cves:
        cid = str(cve.get("id", "")).upper()
        if not cid:
            continue
        seen.add(cid)
        row = dict(cve)
        if cid in nvd_map:
            nvd = nvd_map[cid]
            row["nvd_verified"] = nvd.get("verified", False)
            row["cvss_score"] = row.get("cvss_score") or nvd.get("cvss_score")
            row["severity"] = row.get("severity") or nvd.get("severity")
            if not row.get("description"):
                row["description"] = nvd.get("description", "")
        merged.append(row)

    for cid, nvd in nvd_map.items():
        if cid not in seen:
            merged.append({
                "id": cid,
                "severity": nvd.get("severity", "unknown"),
                "cvss_score": nvd.get("cvss_score"),
                "description": nvd.get("description", ""),
                "affected_component": "",
                "nvd_verified": nvd.get("verified", False),
                "source": "NVD-only",
            })

    return merged


def build_final_report(
    settings: Settings,
    bundle: ScanBundle,
    analysis: dict[str, Any],
    *,
    nvd_records: list[dict[str, Any]],
    searchsploit_results: list[dict[str, Any]],
) -> dict[str, Any]:
    """Собирает итоговый JSON для JSON/HTML отчётов."""
    nuclei_findings: list[dict[str, Any]] = []
    if bundle.nuclei:
        nuclei_findings = [f.to_dict() for f in bundle.nuclei.findings]

    cves = _merge_nvd_into_cves(analysis.get("cves", []), nvd_records)

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
            "target": settings.target,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "platform": "Kali Linux / PentestPlatform Enterprise",
        },
        "scan_summary": scan_summary,
        "technologies": analysis.get("technologies", []),
        "cves": cves,
        "nuclei_findings": nuclei_findings,
        "nuclei_correlations": analysis.get("nuclei_correlations", []),
        "developer_instructions": analysis.get("developer_instructions", []),
        "ai_summary": analysis.get("summary", ""),
        "nvd_enrichment": nvd_records,
        "searchsploit": searchsploit_results,
        "raw_scan_logs": bundle.to_log_text(),
        "metadata": analysis.get("metadata", {}),
    }


async def _run_audit_async(settings: Settings) -> dict[str, Any]:
    """Асинхронная фаза сканирования и обогащения."""
    print("[*] Параллельный запуск: nmap, whatweb, nuclei...")
    bundle = await run_parallel_scans(settings.target)

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
            [{"name": settings.target, "version": ""}],
            max_queries=1,
        )
    print(f"    [+] SearchSploit: {len(searchsploit_results)} запросов")

    aggregated = bundle.to_aggregated_dict()
    aggregated["nvd_enrichment"] = nvd_records
    aggregated["searchsploit"] = searchsploit_results
    aggregated["cve_inventory"] = merge_unique_cves(
        [r["id"] for r in nvd_records if r.get("id")],
        bundle.nuclei.all_cve_ids() if bundle.nuclei else [],
    )

    print("[*] AI-анализ (Claude)...")
    analyzer = SecurityAuditAnalyzer(api_key=settings.claude_api_key)
    analysis = analyzer.analyze(aggregated)

    # SearchSploit по технологиям от Claude
    print("[*] SearchSploit по технологиям от AI...")
    ai_searchsploit = lookup_technologies(analysis.get("technologies", []))
    searchsploit_results.extend(ai_searchsploit)

    return build_final_report(
        settings,
        bundle,
        analysis,
        nvd_records=nvd_records,
        searchsploit_results=searchsploit_results,
    )


def main() -> None:
    """Точка входа."""
    print("=" * 60)
    print("  PentestPlatform — Enterprise Security Audit")
    print("=" * 60)

    settings = load_settings()
    print(f"[+] Цель: {settings.target}")

    print("[*] Проверка утилит (nmap, whatweb, dirb, nuclei, searchsploit)...")
    tools = ensure_tools_available()
    print(f"[+] Доступны: {', '.join(tools)}")

    try:
        final_report = asyncio.run(_run_audit_async(settings))
    except RuntimeError as exc:
        print(f"[ОШИБКА] {exc}", file=sys.stderr)
        sys.exit(1)

    base = Path(__file__).resolve().parent
    save_report(final_report, str(base / REPORT_JSON))
    save_html_report(final_report, str(base / REPORT_HTML))

    tech_count = len(final_report.get("technologies", []))
    cve_count = len(final_report.get("cves", []))
    print(f"[+] Технологий: {tech_count} | CVE: {cve_count}")
    print(json.dumps(
        {
            "summary": final_report.get("ai_summary", "")[:200],
            "cves_sample": final_report.get("cves", [])[:2],
        },
        ensure_ascii=False,
        indent=2,
    ))


if __name__ == "__main__":
    main()
