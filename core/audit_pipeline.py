"""
Единый пайплайн аудита для CLI и Streamlit.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from core.audit_profile import AuditProfile, profile_label
from core.audit_state import (
    mark_cancelled,
    mark_completed,
    mark_error,
    mark_running,
    update_progress,
)
from core.cancel_registry import (
    AuditCancelledError,
    AuditCancellation,
    ensure_not_cancelled,
    is_audit_cancelled,
)
from core.config import Settings
from core.light_analyzer import LightClaudeAnalyzer
from core.logger import get_logger
from core.nvd_client import enrich_cves_from_text
from core.rate_limiter import NVD_LIMITER, SHODAN_LIMITER, VT_LIMITER
from core.scanner import ScanBundle, run_light_scans, run_parallel_scans
from core.searchsploit_client import lookup_technologies
from core.security_mode import AuditMode, exploit_execution_enabled, mode_from_env, mode_label
from core.shodan_client import run_shodan_recon
from core.virustotal_client import run_virustotal_recon
from core.swarm.orchestrator import MARSSwarmManager

log = get_logger("mars.pipeline")

ProgressCallback = Callable[[str], None]


def _default_progress(msg: str) -> None:
    update_progress(msg)


def build_final_report(
    target: str,
    bundle: ScanBundle,
    ai_results: dict[str, Any],
    *,
    profile: AuditProfile,
    nvd_records: list[dict[str, Any]],
    searchsploit_results: list[dict[str, Any]],
    shodan_res: dict[str, Any] | None = None,
    vt_res: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Итоговый JSON-отчёт."""
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
            "platform": "M.A.R.S. / Kali Linux",
            "profile": profile.value,
            "profile_label": profile_label(profile),
        },
        "scan_summary": scan_summary,
        "nuclei_findings": nuclei_findings,
        "nvd_enrichment": nvd_records,
        "searchsploit": searchsploit_results,
        "shodan": shodan_res or {},
        "virustotal": vt_res or {},
        "waf": bundle.waf,
        "raw_scan_logs": bundle.to_log_text(),
        "ai_summary": ai_results.get("final_summary", ai_results.get("summary", "")),
        "parsed_data": ai_results.get("parsed_data", ""),
        "cve_data": ai_results.get("cve_data", ""),
        "exploit_data": ai_results.get("exploit_data", ""),
        "sigma_playbook": ai_results.get("sigma_playbook", ""),
        "osint_dorking": ai_results.get("osint_dorking", ""),
        "technologies": ai_results.get("technologies", []),
        "cves": ai_results.get("cves", []),
        "audit_mode": ai_results.get("audit_mode", ""),
        "audit_mode_label": ai_results.get("audit_mode_label", ""),
        "red_team_enabled": ai_results.get("red_team_enabled", False),
        "exploit_execution_enabled": ai_results.get("exploit_execution_enabled", False),
        "ai_engine": ai_results.get("ai_engine", "crewai_swarm"),
        "success": ai_results.get("success", False),
        "error": ai_results.get("error"),
    }


def _run_nvd(logs: str, api_key: str | None, on_progress: ProgressCallback) -> list[dict[str, Any]]:
    on_progress("NVD: верификация CVE (очередь rate-limit)...")
    ensure_not_cancelled()

    def _do() -> list[dict[str, Any]]:
        return enrich_cves_from_text(logs, api_key=api_key)

    return NVD_LIMITER.call(_do, is_cancelled=is_audit_cancelled)


def _run_searchsploit(
    bundle: ScanBundle,
    target: str,
    on_progress: ProgressCallback,
) -> list[dict[str, Any]]:
    on_progress("SearchSploit: поиск PoC в Exploit-DB...")
    ensure_not_cancelled()
    pre_tech: list[dict[str, str]] = []
    if bundle.nuclei:
        for finding in bundle.nuclei.findings:
            pre_tech.append({"name": finding.name, "version": ""})
    if pre_tech:
        return lookup_technologies(pre_tech)
    return lookup_technologies([{"name": target, "version": ""}], max_queries=1)


def _run_osint(
    target: str,
    settings: Settings,
    on_progress: ProgressCallback,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    on_progress("OSINT: Shodan (очередь)...")
    ensure_not_cancelled()

    def shodan_call() -> dict[str, Any]:
        return run_shodan_recon(target, api_key=settings.shodan_api_key)

    shodan_res = SHODAN_LIMITER.call(shodan_call, is_cancelled=is_audit_cancelled)

    on_progress("OSINT: VirusTotal (очередь)...")
    ensure_not_cancelled()

    def vt_call() -> dict[str, Any]:
        return run_virustotal_recon(target, api_key=settings.virustotal_api_key)

    vt_res = VT_LIMITER.call(vt_call, is_cancelled=is_audit_cancelled)

    osint_data = f"SHODAN: {json.dumps(shodan_res, ensure_ascii=False)}\n\n"
    osint_data += f"VIRUSTOTAL: {json.dumps(vt_res, ensure_ascii=False)}\n\n"
    return shodan_res, vt_res, osint_data


def _run_ai_light(
    bundle: ScanBundle,
    settings: Settings,
    on_progress: ProgressCallback,
) -> dict[str, Any]:
    on_progress("AI: один вызов Claude (лёгкий режим)...")
    ensure_not_cancelled()
    nmap_log = next((r.stdout for r in bundle.results if r.tool == "nmap"), "")
    whatweb_log = next((r.stdout for r in bundle.results if r.tool == "whatweb"), "")
    analyzer = LightClaudeAnalyzer(api_key=settings.claude_api_key)
    return analyzer.analyze(nmap_log, whatweb_log)


def _run_ai_swarm(
    logs: str,
    osint_data: str,
    mode: AuditMode,
    on_progress: ProgressCallback,
    step_callback: Callable[..., None] | None = None,
) -> dict[str, Any]:
    on_progress(f"AI Swarm (CrewAI): {mode_label(mode)}...")
    ensure_not_cancelled()
    if exploit_execution_enabled(mode):
        os.environ["ALLOW_EXPLOIT_EXECUTION"] = "true"
    else:
        os.environ["ALLOW_EXPLOIT_EXECUTION"] = "false"
    manager = MARSSwarmManager(step_callback=step_callback, mode=mode)
    return manager.run_analysis(logs, osint_data=osint_data)


async def run_audit_async(
    target: str,
    settings: Settings,
    *,
    profile: AuditProfile = AuditProfile.FULL,
    audit_mode: AuditMode | None = None,
    on_progress: ProgressCallback | None = None,
    step_callback: Callable[..., None] | None = None,
) -> dict[str, Any]:
    """
    Полный цикл аудита. Бросает AuditCancelledError при отмене.
    """
    progress = on_progress or _default_progress
    cancel = AuditCancellation.get()
    cancel.reset()
    mark_running(target, profile.value, "Инициализация")

    mode = audit_mode or mode_from_env()
    nvd_key = os.getenv("NVD_API_KEY")

    try:
        progress("Проверка отмены / подготовка...")
        ensure_not_cancelled()

        if profile == AuditProfile.LIGHT:
            progress("Сканирование: nmap + whatweb...")
            bundle = await run_light_scans(
                target,
                network_interface=settings.network_interface,
                source_ip=settings.source_ip,
                http_proxy=settings.http_proxy,
            )
        else:
            progress("Сканирование: параллельный запуск всех сканеров...")
            bundle = await run_parallel_scans(
                target,
                wpscan_api_key=settings.wpscan_api_key,
                network_interface=settings.network_interface,
                source_ip=settings.source_ip,
                http_proxy=settings.http_proxy,
            )

        update_progress("Сканирование завершено", cancel.snapshot_pids())
        logs = bundle.to_log_text()
        ensure_not_cancelled()

        nvd_records = _run_nvd(logs, nvd_key, progress)
        searchsploit_results = _run_searchsploit(bundle, target, progress)

        shodan_res: dict[str, Any] = {}
        vt_res: dict[str, Any] = {}
        osint_data = ""

        if profile == AuditProfile.FULL:
            shodan_res, vt_res, osint_data = _run_osint(target, settings, progress)
            subfinder_res = next((r for r in bundle.results if r.tool == "subfinder"), None)
            if subfinder_res and subfinder_res.success:
                osint_data += f"SUBFINDER:\n{subfinder_res.stdout}\n"
            if bundle.waf:
                osint_data += f"WAF:\n{json.dumps(bundle.waf, ensure_ascii=False)}\n"

        ensure_not_cancelled()

        if profile == AuditProfile.LIGHT:
            ai_results = _run_ai_light(bundle, settings, progress)
        else:
            ai_results = _run_ai_swarm(logs, osint_data, mode, progress, step_callback)

        report = build_final_report(
            target,
            bundle,
            ai_results,
            profile=profile,
            nvd_records=nvd_records,
            searchsploit_results=searchsploit_results,
            shodan_res=shodan_res,
            vt_res=vt_res,
        )
        mark_completed("Аудит завершён", report_ready=True)
        log.info("Аудит завершён: target=%s profile=%s", target, profile.value)
        return report

    except AuditCancelledError as exc:
        mark_cancelled(str(exc))
        log.warning("Аудит отменён: %s", exc)
        raise
    except Exception as exc:
        mark_error(str(exc))
        log.exception("Ошибка аудита")
        raise


def save_reports(report: dict[str, Any], base_dir: Path | None = None) -> dict[str, str]:
    """Сохраняет JSON, HTML, PDF в каталог проекта."""
    from core.reporter import save_html_report, save_pdf_report

    base = base_dir or Path(__file__).resolve().parent.parent
    paths: dict[str, str] = {}

    json_path = base / "audit_report.json"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    paths["json"] = str(json_path)

    html_path = base / "audit_report.html"
    save_html_report(report, str(html_path))
    paths["html"] = str(html_path)

    pdf_path = base / "audit_report.pdf"
    save_pdf_report(report, str(pdf_path))
    paths["pdf"] = str(pdf_path)

    return paths
