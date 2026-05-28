"""
Единый пайплайн аудита для CLI и Streamlit.
"""

from __future__ import annotations

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
    AuditCancellation,
    AuditCancelledError,
    ensure_not_cancelled,
    is_audit_cancelled,
)
from core.config import Settings
from core.epss_client import enrich_findings_with_epss, get_epss_scores, prioritize_findings
from core.greynoise_client import interpret_greynoise, run_greynoise_recon
from core.integrations.notify import notify_audit_completed
from core.light_analyzer import LightAnalyzer, _ai_unavailable_result, _diagnose_llm_error
from core.log_truncator import truncate_for_ai
from core.logger import get_logger
from core.mitre_mapper import (
    attack_summary_markdown,
    build_attack_summary,
    enrich_findings_with_attack,
)
from core.nvd_client import enrich_cves_from_text
from core.rate_limiter import NVD_LIMITER, SHODAN_LIMITER, VT_LIMITER
from core.report_store import (
    REPORTS_DIR,
    archive_report,
    diff_cve_reports,
    enrich_report_with_unified_findings,
    find_previous_report,
)
from core.scanner import ScanBundle, run_light_scans, run_parallel_scans, run_smart_scans
from core.searchsploit_client import lookup_technologies
from core.security_mode import AuditMode, exploit_execution_enabled, mode_from_env, mode_label
from core.shodan_client import run_shodan_recon
from core.virustotal_client import run_virustotal_recon

log = get_logger("mars.pipeline")

ProgressCallback = Callable[[str], None]
USE_SMART_SCANNERS = os.getenv("USE_SMART_SCANNERS", "true").lower() in ("1", "true", "yes")


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
    cve_diff: dict[str, Any] | None = None,
    greynoise_res: dict[str, Any] | None = None,
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
    if bundle.scanner_plan:
        scan_summary["_scanner_plan"] = bundle.scanner_plan

    report: dict[str, Any] = {
        "audit": {
            "target": target,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "platform": "M.A.R.S. / Kali Linux",
            "profile": profile.value,
            "profile_label": profile_label(profile),
            "smart_scanners": USE_SMART_SCANNERS,
        },
        "scan_summary": scan_summary,
        "nuclei_findings": nuclei_findings,
        "nvd_enrichment": nvd_records,
        "searchsploit": searchsploit_results,
        "shodan":     shodan_res    or {},
        "virustotal": vt_res        or {},
        "greynoise":  greynoise_res or {},
        "waf":        bundle.waf,
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
        "cve_diff": cve_diff,
    }
    return enrich_report_with_unified_findings(report)


def _run_nvd(logs: str, api_key: str | None, on_progress: ProgressCallback) -> list[dict[str, Any]]:
    on_progress("NVD: верификация CVE (кэш + rate-limit)...")
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
    shodan_res: dict[str, Any] = {"success": False, "error": "ключ не задан"}
    vt_res: dict[str, Any] = {"success": False, "error": "ключ не задан"}
    osint_data = ""

    if settings.shodan_api_key:
        on_progress("OSINT: Shodan (очередь)...")
        ensure_not_cancelled()

        def shodan_call() -> dict[str, Any]:
            return run_shodan_recon(target, api_key=settings.shodan_api_key)

        shodan_res = SHODAN_LIMITER.call(shodan_call, is_cancelled=is_audit_cancelled)
    else:
        on_progress("OSINT: Shodan пропущен (нет SHODAN_API_KEY)")

    if settings.virustotal_api_key:
        on_progress("OSINT: VirusTotal (очередь)...")
        ensure_not_cancelled()

        def vt_call() -> dict[str, Any]:
            return run_virustotal_recon(target, api_key=settings.virustotal_api_key)

        vt_res = VT_LIMITER.call(vt_call, is_cancelled=is_audit_cancelled)
    else:
        on_progress("OSINT: VirusTotal пропущен (нет VIRUSTOTAL_API_KEY)")

    osint_data = f"SHODAN: {json.dumps(shodan_res, ensure_ascii=False)}\n\n"
    osint_data += f"VIRUSTOTAL: {json.dumps(vt_res, ensure_ascii=False)}\n\n"
    return shodan_res, vt_res, osint_data


def _run_ai_light(
    bundle: ScanBundle,
    settings: Settings,
    on_progress: ProgressCallback,
) -> dict[str, Any]:
    on_progress("AI: один вызов LLM (лёгкий режим)...")
    ensure_not_cancelled()
    nmap_log = next((r.stdout for r in bundle.results if r.tool == "nmap"), "")
    whatweb_log = next((r.stdout for r in bundle.results if r.tool == "whatweb"), "")

    provider = getattr(settings, "llm_provider", "anthropic").lower()
    model = getattr(settings, "llm_model", "claude-3-5-sonnet-20241022")
    api_key = getattr(settings, "llm_api_key", None)
    if not api_key:
        api_key = getattr(settings, "claude_api_key", None)
    api_base = getattr(settings, "llm_api_base", None)

    model_str = f"{provider}/{model}"

    # LightAnalyzer уже ловит ошибки внутри и возвращает частичный результат
    analyzer = LightAnalyzer(model=model_str, api_key=api_key, api_base=api_base)
    return analyzer.analyze(nmap_log, whatweb_log)


def _run_ai_swarm(
    logs: str,
    osint_data: str,
    mode: AuditMode,
    settings: Settings,
    on_progress: ProgressCallback,
    step_callback: Callable[..., None] | None = None,
) -> dict[str, Any]:
    on_progress(f"AI Swarm (CrewAI): {mode_label(mode)}...")
    ensure_not_cancelled()
    truncated = truncate_for_ai(logs)
    if exploit_execution_enabled(mode):
        os.environ["ALLOW_EXPLOIT_EXECUTION"] = "true"
    else:
        os.environ["ALLOW_EXPLOIT_EXECUTION"] = "false"
    try:
        from core.swarm.orchestrator import MARSSwarmManager
        manager = MARSSwarmManager(step_callback=step_callback, mode=mode)
        return manager.run_analysis(truncated, osint_data=osint_data)
    except Exception as exc:
        provider = getattr(settings, "llm_provider", "anthropic").lower()
        model_str = f"{provider}/{getattr(settings, 'llm_model', 'claude-3-5-sonnet-20241022')}"
        api_key = getattr(settings, "llm_api_key", None) or getattr(settings, "claude_api_key", None)
        hint = _diagnose_llm_error(exc, model_str, api_key, getattr(settings, "llm_api_base", None))
        log.error("AI Swarm недоступен: %s | %s", exc, hint)
        return _ai_unavailable_result(str(exc), hint, model_str)


async def run_audit_async(
    target: str,
    settings: Settings,
    *,
    profile: AuditProfile = AuditProfile.FULL,
    audit_mode: AuditMode | None = None,
    on_progress: ProgressCallback | None = None,
    step_callback: Callable[..., None] | None = None,
) -> dict[str, Any]:
    """Полный цикл аудита. Бросает AuditCancelledError при отмене."""
    progress = on_progress or _default_progress
    cancel = AuditCancellation.get()
    cancel.reset()
    mark_running(target, profile.value, "Инициализация")

    mode = audit_mode or mode_from_env()
    nvd_key = os.getenv("NVD_API_KEY")

    try:
        progress("Подготовка...")
        ensure_not_cancelled()

        # ── Pre-flight LLM check (предупреждение, не блокирует сканирование) ───
        try:
            from core.llm_check import check_from_settings as _llm_chk
            _chk = _llm_chk(settings, timeout=3.0)
            if _chk.ok:
                log.info("LLM pre-flight: %s", _chk.message)
            else:
                log.warning("LLM pre-flight: %s | %s", _chk.message, _chk.hint)
                progress(
                    f"⚠️ LLM недоступен: {_chk.message} — "
                    "сканирование продолжается, AI-анализ деградирует gracefully"
                )
        except Exception as _e:
            log.debug("LLM pre-flight пропущен: %s", _e)

        if profile == AuditProfile.LIGHT:
            progress("Сканирование: nmap + whatweb...")
            bundle = await run_light_scans(
                target,
                network_interface=settings.network_interface,
                source_ip=settings.source_ip,
                http_proxy=settings.http_proxy,
            )
        elif USE_SMART_SCANNERS:
            progress("Сканирование: умный выбор сканеров...")
            bundle = await run_smart_scans(
                target,
                wpscan_api_key=settings.wpscan_api_key,
                network_interface=settings.network_interface,
                source_ip=settings.source_ip,
                http_proxy=settings.http_proxy,
                xsstrike_path=settings.xsstrike_path,
            )
            if bundle.scanner_plan:
                progress(f"План: {', '.join(bundle.scanner_plan.get('web', []) or ['только база'])}")
        else:
            progress("Сканирование: полный параллельный набор...")
            bundle = await run_parallel_scans(
                target,
                wpscan_api_key=settings.wpscan_api_key,
                network_interface=settings.network_interface,
                source_ip=settings.source_ip,
                http_proxy=settings.http_proxy,
                xsstrike_path=settings.xsstrike_path,
            )

        update_progress("Сканирование завершено", cancel.snapshot_pids())
        logs = bundle.to_log_text()
        ensure_not_cancelled()

        nvd_records = _run_nvd(logs, nvd_key, progress)
        searchsploit_results = _run_searchsploit(bundle, target, progress)

        shodan_res:     dict[str, Any] = {}
        vt_res:         dict[str, Any] = {}
        greynoise_res:  dict[str, Any] = {}
        osint_data = ""

        if profile == AuditProfile.FULL:
            shodan_res, vt_res, osint_data = _run_osint(target, settings, progress)

            # ── GreyNoise ──────────────────────────────────────────────────
            if settings.greynoise_api_key:
                progress("OSINT: GreyNoise IP classification...")
                ensure_not_cancelled()
                try:
                    greynoise_res = await run_greynoise_recon(target, settings.greynoise_api_key)
                    osint_data += (
                        f"GREYNOISE:\n"
                        f"{interpret_greynoise(greynoise_res)}\n"
                        f"{json.dumps(greynoise_res, ensure_ascii=False)}\n\n"
                    )
                except Exception as exc:
                    log.warning("GreyNoise ошибка: %s", exc)
            else:
                progress("OSINT: GreyNoise пропущен (нет GREYNOISE_API_KEY)")

            # Дополнительные данные из новых сканеров
            for tool_name in ("subfinder", "gau", "theHarvester", "httpx"):
                tool_res = next((r for r in bundle.results if r.tool == tool_name), None)
                if tool_res and tool_res.success and tool_res.stdout.strip():
                    osint_data += f"{tool_name.upper()}:\n{tool_res.stdout[:3000]}\n\n"
            if bundle.waf:
                osint_data += f"WAF:\n{json.dumps(bundle.waf, ensure_ascii=False)}\n"

        ensure_not_cancelled()

        if profile == AuditProfile.LIGHT:
            ai_results = _run_ai_light(bundle, settings, progress)
        else:
            ai_results = _run_ai_swarm(logs, osint_data, mode, settings, progress, step_callback)

        # ── EPSS scoring ───────────────────────────────────────────────────────
        progress("EPSS: приоритизация CVE по вероятности эксплуатации...")
        ensure_not_cancelled()
        all_cve_ids = list({
            r.get("id", "")
            for r in nvd_records
            if str(r.get("id", "")).startswith("CVE-")
        })
        epss_scores: dict[str, Any] = {}
        if all_cve_ids:
            try:
                epss_scores = await get_epss_scores(all_cve_ids)
                log.info("EPSS: получено %d scores для %d CVE", len(epss_scores), len(all_cve_ids))
            except Exception as exc:
                log.warning("EPSS ошибка: %s", exc)

        prev = find_previous_report(target)
        cve_diff = None
        if prev:
            progress("Сравнение с предыдущим аудитом...")
            draft = build_final_report(
                target, bundle, ai_results,
                profile=profile,
                nvd_records=nvd_records,
                searchsploit_results=searchsploit_results,
                shodan_res=shodan_res,
                vt_res=vt_res,
                greynoise_res=greynoise_res,
            )
            cve_diff = diff_cve_reports(prev, draft)

        report = build_final_report(
            target, bundle, ai_results,
            profile=profile,
            nvd_records=nvd_records,
            searchsploit_results=searchsploit_results,
            shodan_res=shodan_res,
            vt_res=vt_res,
            cve_diff=cve_diff,
            greynoise_res=greynoise_res,
        )

        # ── Обогащаем unified_findings данными EPSS ────────────────────────────
        if epss_scores and report.get("unified_findings"):
            report["unified_findings"] = enrich_findings_with_epss(
                report["unified_findings"], epss_scores
            )
            report["unified_findings"] = prioritize_findings(report["unified_findings"])
            log.info("EPSS: %d findings приоритизировано", len(report["unified_findings"]))
        report["epss_scores"] = epss_scores

        # ── MITRE ATT&CK mapping ───────────────────────────────────────────────
        if report.get("unified_findings"):
            progress("MITRE ATT&CK: сопоставление техник...")
            report["unified_findings"] = enrich_findings_with_attack(report["unified_findings"])
            attack_summary = build_attack_summary(report["unified_findings"])
            report["attack_summary"]          = attack_summary
            report["attack_summary_markdown"] = attack_summary_markdown(attack_summary)
            log.info(
                "MITRE: %d техник, тактики: %s",
                attack_summary.get("total_techniques", 0),
                ", ".join(attack_summary.get("kill_chain_coverage", [])[:4]),
            )

        # ── Уведомления ────────────────────────────────────────────────────────
        notify_cfg = {
            "telegram_token":   os.getenv("TELEGRAM_BOT_TOKEN"),
            "telegram_chat_id": os.getenv("TELEGRAM_CHAT_ID"),
            "slack_webhook":    os.getenv("SLACK_WEBHOOK_URL"),
        }
        if any(notify_cfg.values()):
            progress("Отправка уведомлений...")
            try:
                await notify_audit_completed(report, **notify_cfg)
            except Exception as exc:
                log.warning("Уведомления: ошибка: %s", exc)

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
    """Сохраняет JSON, HTML, PDF и архивирует в reports/."""
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

    aid = archive_report(report, paths)
    paths["audit_id"] = aid
    paths["archive_dir"] = str(REPORTS_DIR / aid)

    return paths
