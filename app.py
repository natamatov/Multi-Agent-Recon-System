#!/usr/bin/env python3
"""
M.A.R.S. v2 — Streamlit UI.
5 вкладок: Обзор · Новый аудит · Результаты · История · Настройки
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
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

st.set_page_config(
    page_title="M.A.R.S. — Security Assessment",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─── CSS ──────────────────────────────────────────────────────────────────────
CUSTOM_CSS = """
<style>
/* ── Severity badges ── */
.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: .5px;
    text-transform: uppercase;
}
.badge-critical { background:#7f1d1d; color:#fca5a5; border:1px solid #dc2626; }
.badge-high     { background:#7c2d12; color:#fdba74; border:1px solid #ea580c; }
.badge-medium   { background:#78350f; color:#fcd34d; border:1px solid #d97706; }
.badge-low      { background:#14532d; color:#86efac; border:1px solid #16a34a; }
.badge-info     { background:#1e3a5f; color:#93c5fd; border:1px solid #2563eb; }
.badge-unknown  { background:#1f2937; color:#9ca3af; border:1px solid #4b5563; }

/* ── Status pills ── */
.pill {
    display: inline-block;
    padding: 4px 14px;
    border-radius: 20px;
    font-size: 13px;
    font-weight: 600;
}
.pill-running   { background:#78350f; color:#fcd34d; }
.pill-completed { background:#14532d; color:#86efac; }
.pill-error     { background:#7f1d1d; color:#fca5a5; }
.pill-idle      { background:#1f2937; color:#9ca3af; font-weight:400; }

/* ── Step progress ── */
.step-cell {
    text-align: center;
    padding: 6px 2px;
}
.step-icon  { font-size: 22px; line-height: 1; }
.step-label { font-size: 11px; margin-top: 3px; }
.step-done  { opacity: 1; }
.step-active{ opacity: 1; }
.step-wait  { opacity: 0.3; }

/* ── Severity metric tiles ── */
.sev-tile {
    text-align: center;
    border-radius: 8px;
    padding: 10px 4px;
    margin: 2px;
}
.sev-num   { font-size: 28px; font-weight: 700; line-height: 1; }
.sev-name  { font-size: 10px; text-transform: uppercase; letter-spacing: .5px; color: #94a3b8; margin-top: 3px; }

/* ── Elapsed timer ── */
.elapsed { font-size: 32px; font-weight: 800; color: #f59e0b; font-family: monospace; }

/* ── Log box ── */
.log-box {
    font-family: 'Courier New', monospace;
    font-size: 12px;
    background: #0f172a;
    color: #94a3b8;
    padding: 14px;
    border-radius: 6px;
    max-height: 320px;
    overflow-y: auto;
    white-space: pre-wrap;
    line-height: 1.5;
    border: 1px solid #1e293b;
}

/* ── Profile cards ── */
.profile-card {
    border-radius: 10px;
    padding: 16px;
    cursor: default;
}

/* ── History row ── */
.hist-target { font-weight: 600; font-family: monospace; }
.hist-ts     { color: #94a3b8; font-size: 12px; }
</style>
"""

# ─── Pipeline steps ───────────────────────────────────────────────────────────
# (key, label, idle_icon, keywords_in_message)
PIPELINE_STEPS = [
    ("ping",   "Доступность",  "🔍", ["ping", "icmp", "tcp", "host", "reach"]),
    ("scan",   "Сканеры",      "🔬", ["nmap", "whatweb", "nikto", "wpscan", "ffuf", "dirb", "сканер", "scanner"]),
    ("nuclei", "Nuclei",       "⚡", ["nuclei"]),
    ("nvd",    "CVE / NVD",    "📋", ["nvd", "cve", "enrich", "обогащ"]),
    ("osint",  "OSINT",        "🌐", ["shodan", "virustotal", "osint", "subfinder"]),
    ("ai",     "AI агенты",    "🤖", ["agent", "swarm", "crewai", "claude", "ai", "агент", "analysi", "анализ", "light"]),
    ("report", "Отчёт",        "📄", ["report", "отчёт", "saving", "архив", "completed", "готово", "finish"]),
]

SEV_COLORS = {
    "critical": ("#dc2626", "#7f1d1d"),
    "high":     ("#ea580c", "#7c2d12"),
    "medium":   ("#d97706", "#78350f"),
    "low":      ("#16a34a", "#14532d"),
    "info":     ("#2563eb", "#1e3a5f"),
    "unknown":  ("#6b7280", "#1f2937"),
}
SEV_EMOJI = {
    "critical": "🔴", "high": "🟠", "medium": "🟡",
    "low": "🟢", "info": "🔵", "unknown": "⚪",
}


# ─── Session state ────────────────────────────────────────────────────────────

def _init_session() -> None:
    defaults: dict = {
        "tool_status":          None,
        "audit_result":         None,
        "raw_logs":             None,
        "audit_mode":           AuditMode.ASSESSMENT.value,
        "audit_profile":        AuditProfile.FULL.value,
        "pentest_authorized":   False,
        "audit_thread":         None,
        "last_report_paths":    None,
        "scope_ticket":         "",
        "_dash_last_status":    None,
        "_history_report":      None,
        "_history_report_id":   None,
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val
    if st.session_state.tool_status is None:
        st.session_state.tool_status = check_tools()


def _is_audit_running() -> bool:
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


def _audit_thread_target(
    target: str,
    settings,
    profile: AuditProfile,
    mode: AuditMode,
) -> None:
    try:
        report = asyncio.run(
            run_audit_async(target, settings, profile=profile, audit_mode=mode)
        )
        paths = save_reports(report, Path.cwd())
        Path("logs/mars_report_paths.json").write_text(
            json.dumps(paths, ensure_ascii=False), encoding="utf-8"
        )
    except Exception:
        log.exception("Ошибка аудита")


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _detect_step(message: str) -> int:
    """Определяет текущий шаг конвейера по ключевым словам в message."""
    msg = (message or "").lower()
    for i, (_, _, _, keywords) in enumerate(PIPELINE_STEPS):
        if any(kw in msg for kw in keywords):
            return i
    return 0


def _elapsed_str(started_at: float) -> str:
    if not started_at:
        return "—"
    secs = int(time.time() - started_at)
    return f"{secs // 60:02d}:{secs % 60:02d}"


def _sev_tile_html(sev: str, count: int) -> str:
    fg, bg = SEV_COLORS.get(sev, ("#6b7280", "#1f2937"))
    return (
        f'<div class="sev-tile" style="background:{bg}22; border:1px solid {fg}44">'
        f'<div class="sev-num" style="color:{fg}">{count}</div>'
        f'<div class="sev-name">{sev}</div>'
        f'</div>'
    )


# ─── Fragments (auto-refresh) ─────────────────────────────────────────────────

@st.fragment(run_every=3)
def _progress_fragment() -> None:
    """
    Живая панель прогресса — видна поверх всех вкладок.
    Показывается только пока идёт аудит.
    """
    if not _is_audit_running():
        return

    state = load_state()
    current_step = _detect_step(state.message or "")
    elapsed = _elapsed_str(state.started_at)

    st.markdown("---")

    # ── Header row
    hc1, hc2, hc3 = st.columns([4, 1, 1])
    with hc1:
        st.markdown(f"### ⚙️ Аудит: `{state.target}`")
    with hc2:
        st.markdown(
            f'<div class="elapsed">{elapsed}</div>',
            unsafe_allow_html=True,
        )
    with hc3:
        if st.button("🛑 Остановить", type="primary", key="stop_progress"):
            killed = AuditCancellation.get().request_cancel()
            mark_cancelled(f"Остановлено пользователем ({len(killed)} процессов)")
            st.session_state.audit_thread = None
            st.rerun()

    # ── Step indicators
    step_cols = st.columns(len(PIPELINE_STEPS))
    for i, (_, label, idle_icon, _kw) in enumerate(PIPELINE_STEPS):
        with step_cols[i]:
            if i < current_step:
                icon, css = "✅", "step-done"
            elif i == current_step:
                icon, css = "⏳", "step-active"
            else:
                icon, css = idle_icon, "step-wait"
            st.markdown(
                f'<div class="step-cell {css}">'
                f'<div class="step-icon">{icon}</div>'
                f'<div class="step-label">{label}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

    # ── Current operation message
    if state.message:
        st.markdown(
            f'<div style="padding:8px 12px; background:#1e293b; border-radius:6px; '
            f'border-left:3px solid #f59e0b; margin:8px 0; font-size:14px;">'
            f'<b>▶ {state.message}</b></div>',
            unsafe_allow_html=True,
        )

    # ── Log tail
    if LOG_FILE.exists():
        tail = LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()[-20:]
        with st.expander("📋 Журнал выполнения", expanded=True):
            st.markdown(
                f'<div class="log-box">' + "\n".join(tail) + "</div>",
                unsafe_allow_html=True,
            )

    st.markdown("---")


@st.fragment(run_every=30)
def _dashboard_fragment() -> None:
    """Авто-обновление обзорного дашборда каждые 30 с."""
    _sync_results()

    state = load_state()
    running = _is_audit_running()
    current_status = "running" if running else state.status
    prev = st.session_state.get("_dash_last_status")
    if prev == "running" and current_status == "completed":
        st.toast("✅ Аудит завершён — отчёт готов!", icon="✅")
    st.session_state._dash_last_status = current_status

    _render_overview_content()


# ─── Tab: Обзор ───────────────────────────────────────────────────────────────

def _render_overview_content() -> None:
    state = load_state()
    running = _is_audit_running()

    # ── Status banner
    if running:
        pill_html = f'<span class="pill pill-running">⚙️ Идёт аудит — {state.target}</span>'
    elif state.status == "completed":
        pill_html = '<span class="pill pill-completed">✅ Последний аудит завершён</span>'
    elif state.status == "error":
        pill_html = f'<span class="pill pill-error">❌ Ошибка: {state.error or "неизвестная"}</span>'
    else:
        pill_html = '<span class="pill pill-idle">💤 Ожидание</span>'

    st.markdown(pill_html, unsafe_allow_html=True)
    st.caption(f"Обновлено: {datetime.now().strftime('%H:%M:%S')}")
    st.markdown("")

    history = list_recent_audits(8)
    if not history:
        st.info("🚀 История пуста. Перейдите на вкладку **🚀 Новый аудит** и запустите первый скан.")
        with st.container():
            st.markdown("""
            #### Быстрый старт
            1. ⚙️ **Настройки** → укажите LLM провайдер и API ключ
            2. 🚀 **Новый аудит** → введите цель (URL / IP / домен)
            3. Подтвердите авторизацию в боковом меню
            4. Нажмите **Запустить аудит**
            """)
        return

    # ── Metrics
    last = history[0]
    total_cve = sum(h.get("cve_count", 0) for h in history)
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("📁 Аудитов", len(history))
    m2.metric("🔴 Critical+High (посл.)", last.get("critical_high", 0))
    m3.metric("🐛 CVE (посл.)", last.get("cve_count", 0))
    m4.metric("Σ CVE всего", total_cve)

    st.markdown("#### Последние аудиты")
    df = pd.DataFrame(history)
    display_cols = [c for c in ["target", "timestamp_utc", "profile", "cve_count", "critical_high"] if c in df.columns]
    _col_names = {
        "target": "Цель", "timestamp_utc": "Время (UTC)",
        "profile": "Профиль", "cve_count": "CVE", "critical_high": "Critical+High",
    }
    df_display = df[display_cols].rename(columns=_col_names)
    st.dataframe(df_display, hide_index=True, use_container_width=True)


# ─── Tab: Новый аудит ─────────────────────────────────────────────────────────

def _render_audit_tab(
    settings,
    profile: AuditProfile,
    audit_mode: AuditMode,
    scope_ok: bool,
    llm_ready: bool,
) -> None:
    running = _is_audit_running()

    if running:
        st.info(
            "⚙️ **Аудит выполняется.** Прогресс отображается выше. "
            "Результаты появятся во вкладке **📊 Результаты** после завершения."
        )
        return

    # ── Target input
    st.markdown("### 🎯 Цель сканирования")
    target = st.text_input(
        "target",
        placeholder="https://example.com  ·  192.168.1.1  ·  target.internal",
        label_visibility="collapsed",
        key="target_input",
    )

    # ── Profile selector
    st.markdown("### 📋 Профиль аудита")
    pc1, pc2 = st.columns(2)
    light_sel = profile == AuditProfile.LIGHT
    full_sel  = profile == AuditProfile.FULL

    with pc1:
        border_l = "#f59e0b" if light_sel else "#334155"
        bg_l     = "#1c190f" if light_sel else "#1e293b"
        st.markdown(
            f'<div class="profile-card" style="border:2px solid {border_l}; background:{bg_l};">'
            f"<b>⚡ Лёгкий</b> &nbsp; <small style='color:#94a3b8'>~2–5 мин</small><br>"
            f"<small style='color:#94a3b8'>nmap · whatweb · 1 Claude агент<br>"
            f"Быстрая проверка без глубокого сканирования</small></div>",
            unsafe_allow_html=True,
        )

    with pc2:
        border_f = "#3b82f6" if full_sel else "#334155"
        bg_f     = "#0a0f1e" if full_sel else "#1e293b"
        st.markdown(
            f'<div class="profile-card" style="border:2px solid {border_f}; background:{bg_f};">'
            f"<b>🔬 Полный</b> &nbsp; <small style='color:#94a3b8'>~15–30 мин</small><br>"
            f"<small style='color:#94a3b8'>8+ сканеров · Nuclei · OSINT · NVD · 5 AI агентов<br>"
            f"Максимальное покрытие и глубина анализа</small></div>",
            unsafe_allow_html=True,
        )

    # ── Mode (только для FULL)
    if profile == AuditProfile.FULL:
        st.markdown("### 🎚️ Режим AI анализа")
        mc1, mc2 = st.columns(2)
        with mc1:
            st.markdown(
                "**🛡️ Assessment** — только анализ, без поиска эксплойтов  \n"
                "<small style='color:#94a3b8'>Рекомендуется по умолчанию</small>",
                unsafe_allow_html=True,
            )
        with mc2:
            st.markdown(
                "**🔎 Pentest PoC** — поиск публичных PoC и векторов атаки  \n"
                "<small style='color:#94a3b8'>Требует авторизации. Атаки не выполняются.</small>",
                unsafe_allow_html=True,
            )

    st.markdown("")

    # ── Launch button
    can_start = bool(
        target and target.strip()
        and scope_ok
        and llm_ready
        and not running
    )
    col_btn, col_hint = st.columns([2, 3])
    with col_btn:
        start = st.button(
            "🚀 Запустить аудит",
            type="primary",
            disabled=not can_start,
            use_container_width=True,
        )
    with col_hint:
        if not target or not target.strip():
            st.caption("← Введите цель")
        elif not scope_ok:
            st.caption("← Подтвердите авторизацию в боковом меню")
        elif not llm_ready:
            st.caption("← Укажите API ключ в разделе ⚙️ Настройки")
        else:
            st.caption("✅ Готово к запуску")

    # ── Launch logic
    if start:
        t = target.strip()
        scope = validate_scope(
            t,
            ticket_id=st.session_state.scope_ticket,
            ui_confirmed=scope_ok,
        )
        if not scope.allowed:
            st.error(f"🚫 {scope.message}")
        else:
            st.session_state.audit_result = None
            thread = threading.Thread(
                target=_audit_thread_target,
                args=(t, settings, profile, audit_mode),
                daemon=True,
            )
            st.session_state.audit_thread = thread
            thread.start()
            st.rerun()

    # ── Last result summary (если уже есть отчёт)
    report = st.session_state.audit_result or _load_report()
    if report and not running:
        sev = report.get("severity_summary", {})
        findings = report.get("unified_findings", [])
        st.markdown("---")
        st.success(
            f"✅ Последний аудит завершён: **{report.get('audit', {}).get('target', '—')}**  \n"
            "Полные результаты — во вкладке **📊 Результаты**"
        )
        sm1, sm2, sm3, sm4 = st.columns(4)
        sm1.metric("CVE найдено",   len(findings))
        sm2.metric("🔴 Critical",   sev.get("critical", 0))
        sm3.metric("🟠 High",       sev.get("high", 0))
        sm4.metric("🟡 Medium",     sev.get("medium", 0))


# ─── Tab: Результаты ──────────────────────────────────────────────────────────

def _render_results_tab() -> None:
    report = st.session_state.audit_result or _load_report()

    if not report:
        st.info(
            "📭 Нет данных для отображения.  \n"
            "Запустите аудит во вкладке **🚀 Новый аудит**."
        )
        return

    findings    = report.get("unified_findings", [])
    sev_summary = report.get("severity_summary", {})
    audit_info  = report.get("audit", {})
    paths       = st.session_state.get("last_report_paths") or {}

    # ── Header + download buttons
    hdr1, hdr2 = st.columns([3, 2])
    with hdr1:
        st.markdown(f"### 📊 `{audit_info.get('target', '—')}`")
        st.caption(
            f"Профиль: **{audit_info.get('profile_label', audit_info.get('profile', '—'))}**"
            f" · {audit_info.get('timestamp_utc', '')[:19]}"
        )

    with hdr2:
        st.markdown("**⬇️ Скачать отчёт**")
        dc1, dc2, dc3, dc4 = st.columns(4)
        json_p = Path(paths.get("json", "audit_report.json"))
        html_p = Path(paths.get("html", "audit_report.html"))
        pdf_p  = Path(paths.get("pdf",  "audit_report.pdf"))
        if json_p.exists():
            dc1.download_button("JSON", json_p.read_bytes(), "audit.json",
                                use_container_width=True)
        if html_p.exists():
            dc2.download_button("HTML", html_p.read_bytes(), "audit.html",
                                use_container_width=True)
        if pdf_p.exists():
            dc3.download_button("PDF", pdf_p.read_bytes(), "audit.pdf",
                                use_container_width=True)
        if findings:
            dc4.download_button(
                "CSV",
                findings_to_csv(findings).encode("utf-8-sig"),
                "findings.csv",
                mime="text/csv",
                use_container_width=True,
            )

    # ── Severity tiles
    st.markdown("")
    sev_cols = st.columns(6)
    for i, sev_key in enumerate(["critical", "high", "medium", "low", "info", "unknown"]):
        cnt = sev_summary.get(sev_key, 0)
        sev_cols[i].markdown(_sev_tile_html(sev_key, cnt), unsafe_allow_html=True)
    st.markdown("")

    # ── CVE diff
    diff = report.get("cve_diff")
    if diff and (diff.get("new") or diff.get("resolved")):
        new_n, res_n = len(diff.get("new", [])), len(diff.get("resolved", []))
        with st.expander(f"📈 Изменения с прошлого аудита — +{new_n} новых / -{res_n} закрыто"):
            dc1, dc2 = st.columns(2)
            with dc1:
                if diff.get("new"):
                    st.markdown(f"**🆕 Новые ({new_n})**")
                    for f in diff["new"][:15]:
                        st.markdown(
                            f"- `{f.get('id')}` "
                            f"{SEV_EMOJI.get(str(f.get('severity','')).lower(), '⚪')}"
                        )
            with dc2:
                if diff.get("resolved"):
                    st.markdown(f"**✅ Закрытые ({res_n})**")
                    for f in diff["resolved"][:15]:
                        st.markdown(f"- `{f.get('id')}`")

    # ── Detail tabs
    r1, r2, r3, r4 = st.tabs(["🐛 Уязвимости", "🤖 AI Анализ", "🌐 OSINT", "🔍 Логи"])

    # ── Tab: Уязвимости
    with r1:
        if not findings:
            st.success("🎉 CVE не обнаружено.")
        else:
            filt = st.multiselect(
                "Фильтр по severity",
                ["critical", "high", "medium", "low", "info", "unknown"],
                default=["critical", "high", "medium"],
                key="res_sev_filter",
            )
            shown = [f for f in findings if f.get("severity", "unknown") in filt] if filt else findings

            # Finding cards
            for f in shown[:60]:
                sev_val = str(f.get("severity", "unknown")).lower()
                emoji   = SEV_EMOJI.get(sev_val, "⚪")
                cvss    = f.get("cvss_score")
                cvss_str = f"CVSS {cvss:.1f}" if cvss else ""
                label = (
                    f"{emoji} **{f.get('id', '—')}**"
                    f"{' — ' + cvss_str if cvss_str else ''}"
                    f" · {str(f.get('affected_component', f.get('description', '')))[:70]}"
                )
                with st.expander(label):
                    fc1, fc2 = st.columns([3, 1])
                    with fc1:
                        desc = f.get("description", "—")
                        st.markdown(f"**Описание:** {desc}")
                        if f.get("remediation"):
                            st.markdown(f"**Исправление:** {f['remediation']}")
                        if f.get("affected_component"):
                            st.markdown(f"**Компонент:** `{f['affected_component']}`")
                        if f.get("evidence"):
                            st.markdown(f"**Признак:** {f['evidence']}")
                    with fc2:
                        if cvss:
                            st.metric("CVSS", f"{cvss:.1f}")
                        nvd_ok = "✅ Да" if f.get("nvd_verified") else "❌ Нет"
                        st.markdown(f"**NVD верифицировано:** {nvd_ok}")
                        sources = f.get("sources", [])
                        if sources:
                            st.markdown(f"**Источники:** {', '.join(sources)}")

            if len(shown) > 60:
                st.caption(f"Показано 60 из {len(shown)}. Для полного списка скачайте CSV.")

            # Full table
            st.markdown("---")
            with st.expander("📋 Полная таблица CVE"):
                df = pd.DataFrame(shown)
                if not df.empty:
                    table_cols = [c for c in
                        ["id", "severity", "cvss_score", "affected_component", "nvd_verified", "sources"]
                        if c in df.columns]
                    st.dataframe(df[table_cols], hide_index=True, use_container_width=True)

    # ── Tab: AI Анализ
    with r2:
        ai_text = report.get("cve_data", "") or report.get("ai_analysis", "")
        if ai_text:
            st.markdown(ai_text)
        else:
            st.info("AI анализ недоступен для этого отчёта.")

        nvd_list = report.get("nvd_enrichment", [])
        if nvd_list:
            with st.expander(f"📋 NVD сырые данные ({len(nvd_list)} записей)"):
                st.json(nvd_list[:25])

    # ── Tab: OSINT
    with r3:
        osint_keys = [k for k in report if k in
            ("shodan_data", "virustotal_data", "subfinder_data", "osint", "osint_data")]
        if osint_keys:
            for k in osint_keys:
                with st.expander(f"🌐 {k}"):
                    st.json(report[k])
        else:
            st.info(
                "OSINT данные отсутствуют.  \n"
                "Убедитесь, что настроены ключи Shodan/VirusTotal в разделе ⚙️ Настройки,  \n"
                "и что использовался **Полный** профиль."
            )

    # ── Tab: Логи
    with r4:
        raw = report.get("raw_scan_logs", "") or st.session_state.get("raw_logs", "")
        if raw:
            display = raw[-12000:] if len(raw) > 12000 else raw
            if len(raw) > 12000:
                st.caption(f"Показаны последние 12 000 символов из {len(raw):,}")
            st.code(display, language="text")
        else:
            st.info("Логи недоступны.")


# ─── Tab: История ─────────────────────────────────────────────────────────────

def _render_history_tab() -> None:
    history = list_recent_audits(30)

    if not history:
        st.info("История аудитов пуста.")
        return

    st.markdown(f"### 📁 Архив аудитов ({len(history)})")

    # ── List
    for entry in history:
        col_t, col_ts, col_cve, col_ch, col_btn = st.columns([3, 2, 1, 1, 1])
        sev_ch   = entry.get("critical_high", 0)
        has_crit = sev_ch > 0

        col_t.markdown(f"**`{entry.get('target', '—')}`**")
        col_ts.caption(str(entry.get("timestamp_utc", ""))[:19])
        col_cve.markdown(f"🐛 **{entry.get('cve_count', 0)}**")
        fg, bg = SEV_COLORS.get("critical" if has_crit else "low", ("#6b7280", "#1f2937"))
        col_ch.markdown(
            f'<span class="badge badge-{"critical" if has_crit else "low"}">{sev_ch} C/H</span>',
            unsafe_allow_html=True,
        )
        with col_btn:
            if st.button("📂 Открыть", key=f"hist_{entry['audit_id']}",
                         use_container_width=True):
                loaded = load_archived_report(entry["audit_id"])
                if loaded:
                    st.session_state["_history_report"]    = loaded
                    st.session_state["_history_report_id"] = entry["audit_id"]
                    st.rerun()
                else:
                    st.error("Не удалось загрузить отчёт")

        st.divider()

    # ── Opened report viewer
    loaded = st.session_state.get("_history_report")
    if loaded:
        aid   = st.session_state.get("_history_report_id", "архивный")
        tgt   = loaded.get("audit", {}).get("target", aid)
        finds = loaded.get("unified_findings", [])
        sev   = loaded.get("severity_summary", {})

        st.markdown("---")
        cl1, cl2 = st.columns([5, 1])
        cl1.markdown(f"### 📊 `{tgt}`")
        if cl2.button("✖ Закрыть", key="close_hist"):
            st.session_state["_history_report"]    = None
            st.session_state["_history_report_id"] = None
            st.rerun()

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("CVE",           len(finds))
        m2.metric("Critical",      sev.get("critical", 0))
        m3.metric("High",          sev.get("high", 0))
        m4.metric("Профиль",       loaded.get("audit", {}).get("profile", "—"))

        if finds:
            df = pd.DataFrame(finds)
            cols = [c for c in ["id", "severity", "cvss_score", "affected_component", "nvd_verified"] if c in df.columns]
            st.dataframe(df[cols], hide_index=True, use_container_width=True)

        archived_bytes = json.dumps(loaded, ensure_ascii=False, indent=2).encode("utf-8")
        st.download_button(
            "⬇️ Скачать отчёт (JSON)",
            archived_bytes,
            f"{aid}_report.json",
            mime="application/json",
        )


# ─── Tab: Настройки ───────────────────────────────────────────────────────────

def _render_settings_tab(settings) -> None:
    st.markdown("### ⚙️ Настройки")

    s_llm, s_osint, s_deps, s_scope = st.tabs(
        ["🤖 LLM провайдер", "🌐 OSINT ключи", "🔧 Зависимости", "📋 Scope"]
    )

    # ── LLM
    with s_llm:
        st.markdown("#### LLM провайдер и модель")
        provider_opts = ["anthropic", "openai", "ollama"]
        curr_provider = getattr(settings, "llm_provider", "anthropic").lower()
        if curr_provider not in provider_opts:
            curr_provider = "anthropic"

        pl1, pl2 = st.columns(2)
        with pl1:
            provider = st.selectbox(
                "Провайдер",
                provider_opts,
                index=provider_opts.index(curr_provider),
                help="anthropic = Claude · openai = GPT · ollama = локальные модели",
            )
        with pl2:
            model = st.text_input(
                "Модель",
                value=getattr(settings, "llm_model", ""),
                placeholder="claude-3-5-sonnet-20241022  /  gpt-4o  /  llama3",
            )

        curr_key = settings.llm_api_key or getattr(settings, "claude_api_key", "") or ""
        api_key = st.text_input(
            "API Key",
            value=curr_key,
            type="password",
            help="Для Ollama оставьте пустым",
        )
        api_base = st.text_input(
            "API Base URL (опционально)",
            value=getattr(settings, "llm_api_base", "") or "",
            placeholder="http://localhost:11434  (для Ollama)",
        )

        if st.button("💾 Сохранить настройки LLM", type="primary"):
            env_path = Path(".env")
            if not env_path.exists():
                env_path.touch()
            dotenv.set_key(str(env_path), "LLM_PROVIDER", provider)
            dotenv.set_key(str(env_path), "LLM_MODEL", model)
            dotenv.set_key(str(env_path), "LLM_API_KEY", api_key)
            dotenv.set_key(str(env_path), "LLM_API_BASE", api_base)
            st.success("✅ Сохранено. Перезапустите приложение для применения.")

    # ── OSINT keys
    with s_osint:
        st.markdown("#### API ключи для OSINT (опционально)")
        st.info("Без ключей OSINT модуль работает в ограниченном режиме.")

        ok1, ok2 = st.columns(2)
        with ok1:
            shodan_key = st.text_input(
                "Shodan",
                type="password",
                value=getattr(settings, "shodan_api_key", "") or "",
                help="shodan.io → Account → API Key",
            )
            vt_key = st.text_input(
                "VirusTotal",
                type="password",
                value=getattr(settings, "virustotal_api_key", "") or "",
                help="virustotal.com → Profile → API Key",
            )
        with ok2:
            nvd_key = st.text_input(
                "NVD (повышает rate limit)",
                type="password",
                value=getattr(settings, "nvd_api_key", "") or "",
                help="nvd.nist.gov → Request API Key",
            )
            wpscan_key = st.text_input(
                "WPScan",
                type="password",
                value=getattr(settings, "wpscan_api_key", "") or "",
                help="wpscan.com → Profile → API Token",
            )

        if st.button("💾 Сохранить OSINT ключи"):
            env_path = Path(".env")
            if not env_path.exists():
                env_path.touch()
            if shodan_key:
                dotenv.set_key(str(env_path), "SHODAN_API_KEY", shodan_key)
            if vt_key:
                dotenv.set_key(str(env_path), "VIRUSTOTAL_API_KEY", vt_key)
            if nvd_key:
                dotenv.set_key(str(env_path), "NVD_API_KEY", nvd_key)
            if wpscan_key:
                dotenv.set_key(str(env_path), "WPSCAN_API_TOKEN", wpscan_key)
            st.success("✅ Сохранено.")

    # ── Dependencies
    with s_deps:
        st.markdown("#### Статус инструментов")
        tool_status = st.session_state.tool_status or {}
        missing     = missing_tools(tool_status) if tool_status else []

        if tool_status:
            all_tools = list(tool_status.items())
            n_cols = 5
            for row_start in range(0, len(all_tools), n_cols):
                row = all_tools[row_start : row_start + n_cols]
                cols = st.columns(n_cols)
                for i, (tool_name, available) in enumerate(row):
                    icon = "✅" if available else "❌"
                    cols[i].markdown(f"{icon} `{tool_name}`")

        if missing:
            st.markdown("---")
            st.warning(f"Отсутствуют инструменты: {', '.join(missing)}")
            install_cmd = (
                "sudo apt update && sudo apt install -y "
                + " ".join(_APT_PACKAGES.get(t, t) for t in missing)
            )
            st.code(install_cmd, language="bash")

        if st.button("🔄 Перепроверить инструменты"):
            st.session_state.tool_status = check_tools()
            st.rerun()

    # ── Scope
    with s_scope:
        st.markdown("#### Настройки Scope Guard")
        st.info(
            "Scope Guard защищает от случайного сканирования неавторизованных целей.  \n"
            "Настройки задаются через переменные окружения в файле `.env`."
        )

        s2 = try_load_settings()
        rows = [
            ("SCOPE_TICKET_REQUIRED",    "Требование тикета",         getattr(s2, "scope_ticket_required",  False)),
            ("ALLOW_INTERNAL_TARGETS",   "Разрешить внутренние IP",   getattr(s2, "allow_internal_targets", False)),
            ("REQUIRE_SCOPE_CONFIRMATION","Требовать подтверждение UI",True),
        ]
        for env_var, label, val in rows:
            vc1, vc2 = st.columns([3, 1])
            vc1.markdown(f"**{label}** `{env_var}`")
            vc2.markdown("✅ вкл" if val else "❌ выкл")

        allowed = getattr(s2, "allowed_targets", "") or ""
        if allowed:
            st.markdown(f"**Разрешённые цели:** `{allowed}`")
        else:
            st.caption("ALLOWED_TARGETS не задан — разрешены все цели (кроме приватных IP при ALLOW_INTERNAL_TARGETS=false)")

        st.markdown("---")
        st.caption("Для изменения отредактируйте `.env` и перезапустите приложение.")


# ─── Sidebar ──────────────────────────────────────────────────────────────────

def _render_sidebar(settings) -> tuple[AuditProfile, AuditMode, bool, bool]:
    """
    Компактный сайдбар: статус · авторизация · профиль · режим.
    Возвращает (profile, audit_mode, scope_ok, llm_ready).
    """
    with st.sidebar:
        st.markdown("## 🛡️ M.A.R.S.")
        st.caption("Multi-Agent Recon System")
        st.divider()

        # ── Status
        state   = load_state()
        running = _is_audit_running()
        if running:
            st.markdown(
                f'<span class="pill pill-running">⚙️ Running</span>',
                unsafe_allow_html=True,
            )
            st.caption(f"`{state.target}`")
        elif state.status == "completed":
            st.markdown('<span class="pill pill-completed">✅ Done</span>', unsafe_allow_html=True)
            st.caption(f"`{state.target}`")
        elif state.status == "error":
            st.markdown('<span class="pill pill-error">❌ Error</span>', unsafe_allow_html=True)
        else:
            st.markdown('<span class="pill pill-idle">💤 Idle</span>', unsafe_allow_html=True)

        st.divider()

        # ── Авторизация (обязательно для запуска)
        st.markdown("**📋 Авторизация**")
        scope_ticket = st.text_input(
            "Тикет / договор",
            value=st.session_state.scope_ticket,
            placeholder="VULN-2024-001",
            help="ID заявки на тестирование (опционально)",
        )
        st.session_state.scope_ticket = scope_ticket

        scope_ok = st.checkbox(
            "Подтверждаю права на тестирование",
            value=st.session_state.pentest_authorized,
            help="Обязательно перед запуском",
        )
        st.session_state.pentest_authorized = scope_ok

        if not scope_ok:
            st.caption("⚠️ Поставьте галочку для разблокировки запуска")

        st.divider()

        # ── Профиль
        st.markdown("**⚡ Профиль**")
        prof = st.radio(
            "Профиль",
            [AuditProfile.LIGHT.value, AuditProfile.FULL.value],
            format_func=lambda k: (
                "⚡ Лёгкий (~5 мин)" if k == AuditProfile.LIGHT.value
                else "🔬 Полный (~20–30 мин)"
            ),
            label_visibility="collapsed",
        )
        profile = AuditProfile(prof)

        # ── Режим
        audit_mode = AuditMode.ASSESSMENT
        if profile == AuditProfile.FULL:
            st.divider()
            st.markdown("**🎚️ AI режим**")
            sel = st.radio(
                "Режим",
                [AuditMode.ASSESSMENT.value, AuditMode.PENTEST_POC.value],
                format_func=lambda v: (
                    "🛡️ Assessment" if v == AuditMode.ASSESSMENT.value
                    else "🔎 Pentest PoC"
                ),
                label_visibility="collapsed",
            )
            if sel == AuditMode.PENTEST_POC.value:
                audit_mode = resolve_mode(
                    sel,
                    env_enable_red_team=settings.enable_red_team,
                    ui_confirmed_execution=scope_ok,
                )

        st.divider()

        # ── LLM статус
        llm_ready = True
        has_key   = bool(
            settings.llm_api_key
            or getattr(settings, "claude_api_key", None)
        )
        if settings.llm_provider != "ollama" and not has_key:
            st.warning("⚠️ Нет API ключа\nОткройте ⚙️ **Настройки**")
            llm_ready = False
        else:
            prov  = getattr(settings, "llm_provider", "?")
            model = getattr(settings, "llm_model", "?")
            st.success(f"✅ **{prov}**\n`{model}`")

    return profile, audit_mode, scope_ok, llm_ready


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    _init_session()
    _sync_results()

    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

    settings = try_load_settings()
    profile, audit_mode, scope_ok, llm_ready = _render_sidebar(settings)

    # Title
    st.markdown("# 🛡️ M.A.R.S.")
    st.caption("Multi-Agent Recon System — Security Assessment Platform")

    # ── Живая панель прогресса (всегда поверх вкладок)
    _progress_fragment()

    # ── Основные вкладки
    tab_overview, tab_audit, tab_results, tab_history, tab_settings = st.tabs([
        "🏠 Обзор",
        "🚀 Новый аудит",
        "📊 Результаты",
        "📁 История",
        "⚙️ Настройки",
    ])

    with tab_overview:
        _dashboard_fragment()

    with tab_audit:
        _render_audit_tab(settings, profile, audit_mode, scope_ok, llm_ready)

    with tab_results:
        _render_results_tab()

    with tab_history:
        _render_history_tab()

    with tab_settings:
        _render_settings_tab(settings)


if __name__ == "__main__":
    main()
