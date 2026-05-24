#!/usr/bin/env python3
"""
M.A.R.S. — Streamlit UI: dashboard, live progress, scope, экспорт.
"""

from __future__ import annotations

import asyncio
import json
import threading
from datetime import datetime
from pathlib import Path

import dotenv
import pandas as pd
import streamlit as st

from core.audit_pipeline import run_audit_async, save_reports
from core.audit_profile import AuditProfile
from core.audit_state import is_still_running, load_state, mark_cancelled
from core.cancel_registry import AuditCancellation
from core.config import try_load_settings
from core.dependency_manager import _APT_PACKAGES, check_tools, missing_tools
from core.export_csv import findings_to_csv
from core.logger import LOG_FILE, get_logger, setup_logging
from core.report_store import list_recent_audits, load_archived_report
from core.scope_guard import validate_scope
from core.security_mode import AuditMode, red_team_enabled, resolve_mode

setup_logging()
log = get_logger("mars.ui")

REPORT_JSON = Path("audit_report.json")
APP_TITLE = "M.A.R.S. — Multi-Agent Recon System"

st.set_page_config(
    page_title="M.A.R.S. Security Assessment Hub",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def _init_session() -> None:
    defaults = {
        "tool_status": check_tools(),
        "audit_result": None,
        "raw_logs": None,
        "audit_mode": AuditMode.ASSESSMENT.value,
        "audit_profile": AuditProfile.FULL.value,
        "pentest_authorized": False,
        "audit_thread": None,
        "last_report_paths": None,
        "scope_ticket": "",
        "_dash_last_status": None,
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val


def _is_audit_running() -> bool:
    """True, если аудит в процессе (state-файл или живой поток)."""
    thread = st.session_state.get("audit_thread")
    return bool(
        is_still_running()
        or (thread is not None and thread.is_alive())
    )


def _load_report() -> dict | None:
    if REPORT_JSON.exists():
        try:
            return json.loads(REPORT_JSON.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None
    return None


@st.fragment(run_every=5)
def _live_audit_panel() -> None:
    """Авто-обновление каждые 5 с при running."""
    state = load_state()
    if not _is_audit_running():
        return

    st.warning(f"⏳ **Аудит:** `{state.target}` — {state.message or '...'}")
    if state.child_pids:
        st.caption(f"PID: {', '.join(map(str, state.child_pids))}")

    if LOG_FILE.exists():
        tail = LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()[-15:]
        with st.expander("Хвост лога (mars_audit.log)"):
            st.code("\n".join(tail), language="text")

    if st.button("🛑 Остановить", type="primary", key="stop_live"):
        killed = AuditCancellation.get().request_cancel()
        mark_cancelled(f"Остановлено (PID: {len(killed)})")
        st.session_state.audit_thread = None
        st.rerun()


@st.fragment(run_every=30)
def _dashboard_panel() -> None:
    """Авто-обновление истории каждые 30 с."""
    _sync_results()
    state = load_state()
    st.session_state.get("audit_thread")
    running = _is_audit_running()
    current = "running" if running else state.status
    prev = st.session_state.get("_dash_last_status")
    if prev == "running" and current == "completed":
        st.toast("Аудит завершён — отчёт обновлён", icon="✅")
    st.session_state._dash_last_status = current

    st.caption(f"Авто-обновление · {datetime.now().strftime('%H:%M:%S')}")
    _render_dashboard()


def _render_dashboard() -> None:
    st.subheader("📊 Dashboard")
    history = list_recent_audits(8)
    if not history:
        st.info("История пуста. Запустите первый аудит.")
        return

    cols = st.columns(4)
    total_cve = sum(h.get("cve_count", 0) for h in history)
    sum(h.get("critical_high", 0) for h in history)
    cols[0].metric("Аудитов в истории", len(history))
    cols[1].metric("CVE (последние)", history[0].get("cve_count", 0))
    cols[2].metric("Critical+High (последний)", history[0].get("critical_high", 0))
    cols[3].metric("Σ CVE", total_cve)

    df = pd.DataFrame(history)
    st.dataframe(
        df[["audit_id", "target", "timestamp_utc", "profile", "cve_count", "critical_high"]],
        width="stretch",
        hide_index=True,
    )

    aid = st.selectbox("Открыть архивный отчёт", [h["audit_id"] for h in history])
    if st.button("Загрузить выбранный"):
        archived = load_archived_report(aid)
        if archived:
            st.session_state["_view_archived"] = archived
            st.success(f"Загружен {aid}")


def _audit_thread_target(
    target: str,
    settings,
    profile: AuditProfile,
    mode: AuditMode,
) -> None:
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
        log.exception("Ошибка аудита")


def _sync_results() -> None:
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
        report = _load_report()
        if report and not st.session_state.audit_result:
            st.session_state.audit_result = report
            st.session_state.raw_logs = report.get("raw_scan_logs", "")


def _sidebar_deps() -> bool:
    st.sidebar.header("🔧 Зависимости")
    status = st.session_state.tool_status
    missing = missing_tools(status)
    if missing:
        for tool in missing:
            st.sidebar.code(f"sudo apt install {_APT_PACKAGES.get(tool, tool)}", language="bash")
        if st.sidebar.button("🔄 Проверить"):
            st.session_state.tool_status = check_tools()
            st.rerun()
        return False
    st.sidebar.success("✅ OK")
    return True


def _sidebar_llm_config(settings) -> None:
    st.sidebar.divider()
    st.sidebar.subheader("⚙️ Настройки LLM")

    provider_opts = ["anthropic", "openai", "ollama"]

    curr_provider = getattr(settings, "llm_provider", "anthropic").lower()
    if curr_provider not in provider_opts:
        curr_provider = "anthropic"

    idx = provider_opts.index(curr_provider)
    provider = st.sidebar.selectbox("Провайдер", provider_opts, index=idx)

    curr_model = getattr(settings, "llm_model", "")
    model = st.sidebar.text_input("Модель", value=curr_model, placeholder="claude-3-5-sonnet-20241022, gpt-4o, llama3")

    curr_key = settings.llm_api_key or ""
    if not curr_key and settings.claude_api_key:
        curr_key = settings.claude_api_key

    api_key = st.sidebar.text_input("API Key", value=curr_key or "", type="password", help="Необязательно для Ollama")

    curr_base = getattr(settings, "llm_api_base", "")
    api_base = st.sidebar.text_input("API Base URL", value=curr_base or "", placeholder="http://localhost:11434")

    if st.sidebar.button("💾 Сохранить настройки LLM"):
        env_path = Path(".env")
        if not env_path.exists():
            env_path.touch()

        dotenv.set_key(str(env_path), "LLM_PROVIDER", provider)
        dotenv.set_key(str(env_path), "LLM_MODEL", model)
        dotenv.set_key(str(env_path), "LLM_API_KEY", api_key)
        dotenv.set_key(str(env_path), "LLM_API_BASE", api_base)

        st.sidebar.success("Настройки сохранены!")
        st.rerun()


def main() -> None:
    _init_session()
    _live_audit_panel()
    _sync_results()

    st.title(f"🛡️ {APP_TITLE}")

    if not _sidebar_deps():
        st.stop()

    settings = try_load_settings()

    _sidebar_llm_config(settings)

    llm_ready = True
    if settings.llm_provider != "ollama" and not settings.llm_api_key and not getattr(settings, "claude_api_key", None):
        st.error("Пожалуйста, настройте LLM в боковом меню (укажите API-ключ)")
        llm_ready = False

    st.sidebar.divider()
    st.sidebar.subheader("📋 Scope")
    st.session_state.scope_ticket = st.sidebar.text_input(
        "ID заявки / договора",
        value=st.session_state.scope_ticket,
    )
    scope_ok = st.sidebar.checkbox(
        "Подтверждаю авторизацию на тестирование",
        value=st.session_state.pentest_authorized,
    )
    st.session_state.pentest_authorized = scope_ok

    profile_opts = {
        AuditProfile.LIGHT.value: "⚡ Лёгкий",
        AuditProfile.FULL.value: "🔬 Полный",
    }
    prof = st.sidebar.radio(
        "Профиль",
        list(profile_opts.keys()),
        format_func=lambda k: profile_opts[k],
    )
    profile = AuditProfile(prof)

    audit_mode = AuditMode.ASSESSMENT
    if profile == AuditProfile.FULL:
        st.sidebar.subheader("🎚️ AI режим")
        sel = st.sidebar.radio("Режим", [AuditMode.ASSESSMENT.value, AuditMode.PENTEST_POC.value])
        ui_conf = scope_ok
        if sel == AuditMode.PENTEST_POC.value:
            audit_mode = resolve_mode(
                sel,
                env_enable_red_team=settings.enable_red_team,
                ui_confirmed_execution=ui_conf,
            )
        else:
            audit_mode = AuditMode.ASSESSMENT

    running = _is_audit_running()

    tab_dash, tab_audit = st.tabs(["Dashboard", "Новый аудит"])

    with tab_dash:
        _dashboard_panel()
        archived = st.session_state.get("_view_archived")
        if archived:
            st.json(archived.get("severity_summary", {}))

    with tab_audit:
        target = st.text_input("🎯 TARGET", placeholder="https://example.com")
        c1, c2 = st.columns(2)
        with c1:
            start = st.button("🚀 Запустить", type="primary", disabled=running or not llm_ready)
        with c2:
            if st.button("🔄 Статус", disabled=not running):
                st.rerun()

        if start:
            t = (target or "").strip()
            scope = validate_scope(
                t,
                ticket_id=st.session_state.scope_ticket,
                ui_confirmed=scope_ok,
            )
            if not scope.allowed:
                st.error(scope.message)
            elif profile == AuditProfile.FULL and red_team_enabled(audit_mode) and not scope_ok:
                st.error("Подтвердите авторизацию")
            elif t:
                st.session_state.audit_result = None
                thread = threading.Thread(
                    target=_audit_thread_target,
                    args=(t, settings, profile, audit_mode),
                    daemon=True,
                )
                st.session_state.audit_thread = thread
                thread.start()
                st.rerun()
            else:
                st.warning("Укажите TARGET")

        report = st.session_state.audit_result or _load_report()
        if report:
            findings = report.get("unified_findings", [])
            st.divider()
            sev = report.get("severity_summary", {})
            if sev:
                st.bar_chart(sev)

            m1, m2, m3 = st.columns(3)
            m1.metric("CVE всего", len(findings))
            m2.metric("Critical+High", sev.get("critical", 0) + sev.get("high", 0))
            m3.metric("Профиль", report.get("audit", {}).get("profile_label", ""))

            paths = st.session_state.get("last_report_paths") or {}
            ec1, ec2, ec3, ec4 = st.columns(4)
            with ec1:
                if Path(paths.get("json", "audit_report.json")).exists():
                    st.download_button("JSON", Path(paths.get("json", REPORT_JSON)).read_bytes(), "audit.json")
            with ec2:
                hp = paths.get("html", "audit_report.html")
                if Path(hp).exists():
                    st.download_button("HTML", Path(hp).read_bytes(), "audit.html")
            with ec3:
                pp = paths.get("pdf", "audit_report.pdf")
                if Path(pp).exists():
                    st.download_button("PDF", Path(pp).read_bytes(), "audit.pdf")
            with ec4:
                st.download_button(
                    "CVE CSV",
                    findings_to_csv(findings).encode("utf-8-sig"),
                    "cve_findings.csv",
                    mime="text/csv",
                )

            diff = report.get("cve_diff")
            if diff:
                with st.expander("📈 Diff с прошлым аудитом"):
                    st.write(f"**Новые:** {len(diff.get('new', []))} | "
                             f"**Исчезли:** {len(diff.get('resolved', []))}")
                    if diff.get("new"):
                        st.dataframe(pd.DataFrame(diff["new"]), width="stretch")

            tabs = st.tabs(["CVE таблица", "NVD", "AI", "Логи"])
            with tabs[0]:
                if findings:
                    df = pd.DataFrame(findings)
                    sev_filter = st.multiselect(
                        "Severity",
                        ["critical", "high", "medium", "low", "unknown"],
                        default=["critical", "high", "medium"],
                    )
                    if sev_filter:
                        df = df[df["severity"].isin(sev_filter)]
                    st.dataframe(df, width="stretch", hide_index=True)
            with tabs[1]:
                st.json(report.get("nvd_enrichment", []))
            with tabs[2]:
                st.markdown(report.get("cve_data", ""))
            with tabs[3]:
                st.code(report.get("raw_scan_logs", ""), language="text")


if __name__ == "__main__":
    main()
