#!/usr/bin/env python3
"""
M.A.R.S. — Streamlit UI (единый пайплайн, отмена, экспорт отчётов).
"""

from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path

import streamlit as st

from core.audit_pipeline import run_audit_async, save_reports
from core.audit_profile import AuditProfile, profile_label
from core.audit_state import (
    is_still_running,
    load_state,
    mark_idle,
)
from core.cancel_registry import AuditCancellation
from core.config import try_load_settings
from core.dependency_manager import _APT_PACKAGES, check_tools, missing_tools
from core.logger import setup_logging, get_logger
from core.security_mode import (
    AuditMode,
    exploit_execution_enabled,
    mode_label,
    red_team_enabled,
    resolve_mode,
)

setup_logging()
log = get_logger("mars.ui")

REPORT_JSON = Path("audit_report.json")

st.set_page_config(
    page_title="M.A.R.S. Security Assessment Hub",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

APP_TITLE = "M.A.R.S. — Multi-Agent Recon System"


def _init_session() -> None:
    defaults = {
        "tool_status": check_tools(),
        "audit_result": None,
        "raw_logs": None,
        "ping_result": None,
        "audit_mode": AuditMode.ASSESSMENT.value,
        "audit_profile": AuditProfile.FULL.value,
        "pentest_authorized": False,
        "audit_thread": None,
        "last_report_paths": None,
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val


def _load_report_from_disk() -> dict | None:
    if REPORT_JSON.exists():
        try:
            return json.loads(REPORT_JSON.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None
    return None


def _render_running_banner() -> None:
    state = load_state()
    if not is_still_running() and state.status != "running":
        return

    st.warning(
        f"⏳ **Аудит выполняется** — цель: `{state.target}` | "
        f"{state.message or '...'}"
    )
    if state.child_pids:
        st.caption(f"Дочерние PID: {', '.join(map(str, state.child_pids))}")

    if st.button("🛑 Остановить аудит", type="primary", key="stop_audit"):
        from core.audit_state import mark_cancelled

        killed = AuditCancellation.get().request_cancel()
        mark_cancelled(f"Остановлено пользователем (PID: {len(killed)})")
        st.session_state.audit_thread = None
        st.error(f"Отмена запрошена. Завершено процессов: {len(killed)}")
        st.rerun()


def _audit_thread_target(
    target: str,
    settings,
    profile: AuditProfile,
    mode: AuditMode,
) -> None:
    """Фоновый поток: результат только в audit_report.* и audit_state.json."""
    try:
        report = asyncio.run(
            run_audit_async(
                target,
                settings,
                profile=profile,
                audit_mode=mode,
            )
        )
        paths = save_reports(report, Path.cwd())
        Path("logs/mars_report_paths.json").write_text(
            json.dumps(paths, ensure_ascii=False),
            encoding="utf-8",
        )
    except Exception:
        log.exception("Ошибка в потоке аудита")


def _start_audit_background(
    target: str,
    settings,
    profile: AuditProfile,
    mode: AuditMode,
) -> None:
    if st.session_state.audit_thread and st.session_state.audit_thread.is_alive():
        st.warning("Аудит уже выполняется.")
        return

    st.session_state.audit_result = None
    st.session_state.raw_logs = None

    thread = threading.Thread(
        target=_audit_thread_target,
        args=(target, settings, profile, mode),
        daemon=True,
        name="mars-audit",
    )
    st.session_state.audit_thread = thread
    thread.start()
    st.info("Аудит запущен в фоне. Можно обновить страницу — статус сохранится.")
    st.rerun()


def _report_to_ui(report: dict) -> None:
    st.session_state.audit_result = {
        "parsed_data": report.get("parsed_data", ""),
        "cve_data": report.get("cve_data", ""),
        "exploit_data": report.get("exploit_data", ""),
        "sigma_playbook": report.get("sigma_playbook", ""),
        "osint_dorking": report.get("osint_dorking", ""),
        "audit_mode_label": report.get("audit_mode_label", ""),
        "red_team_enabled": report.get("red_team_enabled", False),
        "exploit_execution_enabled": report.get("exploit_execution_enabled", False),
        "success": report.get("success", True),
    }
    st.session_state.raw_logs = report.get("raw_scan_logs", "")


def _sync_thread_results() -> None:
    """Подхватывает результат после обновления страницы (файлы на диске)."""
    paths_file = Path("logs/mars_report_paths.json")
    if paths_file.exists():
        try:
            st.session_state.last_report_paths = json.loads(
                paths_file.read_text(encoding="utf-8")
            )
        except json.JSONDecodeError:
            pass

    thread = st.session_state.get("audit_thread")
    if thread is not None and not thread.is_alive():
        st.session_state.audit_thread = None

    state = load_state()
    if state.status in ("completed", "error", "cancelled"):
        report = _load_report_from_disk()
        if report and not st.session_state.audit_result:
            _report_to_ui(report)


def _render_sidebar_deps() -> bool:
    st.sidebar.header("🔧 Зависимости")
    status = st.session_state.tool_status
    missing = missing_tools(status)

    if not missing:
        st.sidebar.success("✅ Все утилиты доступны")
    else:
        st.sidebar.warning("⚠️ Не хватает утилит")
        with st.sidebar.expander("Установка", expanded=True):
            for tool in missing:
                pkg = _APT_PACKAGES.get(tool, tool)
                st.code(f"sudo apt install {pkg}", language="bash")
        if st.sidebar.button("🔄 Проверить снова"):
            st.session_state.tool_status = check_tools()
            st.rerun()
        return False

    if st.sidebar.button("🔄 Обновить статус"):
        st.session_state.tool_status = check_tools()
        st.rerun()
    return True


def _render_profile_sidebar() -> AuditProfile:
    st.sidebar.divider()
    st.sidebar.subheader("📋 Профиль сканирования")
    opts = {
        AuditProfile.LIGHT.value: "⚡ Лёгкий (nmap + whatweb + Claude)",
        AuditProfile.FULL.value: "🔬 Полный (все сканеры + Swarm)",
    }
    sel = st.sidebar.radio(
        "Профиль",
        list(opts.keys()),
        format_func=lambda k: opts[k],
        index=0 if st.session_state.audit_profile == AuditProfile.LIGHT.value else 1,
    )
    st.session_state.audit_profile = sel
    return AuditProfile(sel)


def _render_audit_mode_sidebar(settings) -> AuditMode:
    st.sidebar.divider()
    st.sidebar.subheader("🎚️ Режим AI (CrewAI)")
    if st.session_state.audit_profile == AuditProfile.LIGHT.value:
        st.sidebar.info("В лёгком профиле используется один вызов Claude (без Swarm).")
        return AuditMode.ASSESSMENT

    mode_options = {
        AuditMode.ASSESSMENT.value: "🛡️ VA (Red Team выкл.)",
        AuditMode.PENTEST_POC.value: "🔬 Pentest — PoC Analysis",
        AuditMode.PENTEST_EXPLOIT.value: "⚠️ Exploit Verification",
    }
    selected = st.sidebar.radio(
        "Режим",
        list(mode_options.keys()),
        format_func=lambda k: mode_options[k],
    )
    ui_confirmed = False
    if selected == AuditMode.PENTEST_EXPLOIT.value:
        st.session_state.pentest_authorized = st.sidebar.checkbox(
            "Письменное разрешение на тестирование",
            value=st.session_state.pentest_authorized,
        )
        confirm = st.sidebar.text_input("Повторите TARGET", key="pentest_confirm")
        st.session_state.pentest_confirm_target = confirm.strip()
        ui_confirmed = st.session_state.pentest_authorized and bool(confirm.strip())
    elif selected == AuditMode.PENTEST_POC.value:
        st.session_state.pentest_authorized = st.sidebar.checkbox(
            "Авторизованный пентест",
            value=st.session_state.pentest_authorized,
        )
        ui_confirmed = st.session_state.pentest_authorized
    else:
        st.session_state.pentest_authorized = False

    mode = resolve_mode(
        selected,
        env_enable_red_team=settings.enable_red_team,
        env_allow_execution=settings.allow_exploit_execution,
        ui_confirmed_execution=ui_confirmed,
    )
    st.sidebar.caption(f"Активно: **{mode_label(mode)}**")
    return mode


def _render_export_buttons() -> None:
    st.subheader("📥 Экспорт отчётов")
    col1, col2, col3 = st.columns(3)
    paths = st.session_state.get("last_report_paths") or {}
    base = Path.cwd()

    with col1:
        jp = paths.get("json") or str(base / "audit_report.json")
        if Path(jp).exists():
            st.download_button(
                "JSON",
                Path(jp).read_bytes(),
                file_name="audit_report.json",
                use_container_width=True,
            )
    with col2:
        hp = paths.get("html") or str(base / "audit_report.html")
        if Path(hp).exists():
            st.download_button(
                "HTML",
                Path(hp).read_bytes(),
                file_name="audit_report.html",
                use_container_width=True,
            )
    with col3:
        pp = paths.get("pdf") or str(base / "audit_report.pdf")
        if Path(pp).exists():
            st.download_button(
                "PDF",
                Path(pp).read_bytes(),
                file_name="audit_report.pdf",
                use_container_width=True,
            )


def main() -> None:
    _init_session()
    _render_running_banner()
    _sync_thread_results()

    st.title(f"🛡️ {APP_TITLE}")
    st.caption("Легальный VA. Только с письменным разрешением.")

    if not _render_sidebar_deps():
        st.stop()

    settings = try_load_settings()
    if not settings:
        st.error("Задайте `CLAUDE_API_KEY` в `.env`")
        st.stop()

    profile = _render_profile_sidebar()
    audit_mode = _render_audit_mode_sidebar(settings)

    running = is_still_running() or (
        st.session_state.audit_thread is not None
        and st.session_state.audit_thread.is_alive()
    )

    st.divider()
    target = st.text_input("🎯 TARGET", placeholder="192.168.1.10 или https://example.com")

    c1, c2 = st.columns(2)
    with c1:
        start = st.button(
            "🚀 Запустить аудит",
            type="primary",
            disabled=running,
            use_container_width=True,
        )
    with c2:
        if st.button("🔄 Обновить статус", disabled=not running, use_container_width=True):
            st.rerun()

    if start:
        t = (target or "").strip()
        if not t:
            st.warning("Укажите TARGET")
        elif red_team_enabled(audit_mode) and not st.session_state.pentest_authorized:
            st.error("Подтвердите авторизацию в sidebar")
        elif audit_mode == AuditMode.PENTEST_EXPLOIT and (
            st.session_state.get("pentest_confirm_target") != t
        ):
            st.error("TARGET не совпадает с полем подтверждения")
        else:
            _start_audit_background(t, settings, profile, audit_mode)

    res = st.session_state.audit_result
    if res and st.session_state.raw_logs:
        st.divider()
        _render_export_buttons()

        tab_nvd, tab_parsed, tab_cve, tab_exp, tab_sigma, tab_osint, tab_raw = st.tabs([
            "🔐 NVD / SearchSploit",
            "📄 Данные",
            "🚨 CVE",
            "💣 PoC",
            "🛡️ Sigma",
            "🌐 OSINT",
            "📜 Логи",
        ])

        report = _load_report_from_disk() or {}

        with tab_nvd:
            st.subheader("NVD")
            st.json(report.get("nvd_enrichment", []))
            st.subheader("SearchSploit")
            st.json(report.get("searchsploit", []))

        with tab_parsed:
            st.markdown(res.get("parsed_data", "_—_"))
        with tab_cve:
            st.markdown(res.get("cve_data", "_—_"))
        with tab_exp:
            st.markdown(res.get("exploit_data", "_—_"))
        with tab_sigma:
            st.markdown(res.get("sigma_playbook", "_—_"))
        with tab_osint:
            st.json({
                "shodan": report.get("shodan", {}),
                "virustotal": report.get("virustotal", {}),
            })
            st.markdown(res.get("osint_dorking", ""))
        with tab_raw:
            st.code(st.session_state.raw_logs, language="text")


if __name__ == "__main__":
    main()
