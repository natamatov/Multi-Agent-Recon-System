#!/usr/bin/env python3
"""
MARS SOLUTIONS - Security Assessment Hub
Streamlit UI для легального Vulnerability Assessment (Kali Linux).
"""

from __future__ import annotations

import json
from typing import Any

import pandas as pd
import streamlit as st

from core.ai_analyzer import ClaudeAnalyzer
from core.config import try_load_settings
from core.dependency_manager import (
    INSTALL_HINTS,
    all_tools_ready,
    check_tools,
    missing_tools,
)
from core.scanner import run_all_scanners


# ——— Конфигурация страницы ———
st.set_page_config(
    page_title="MARS SOLUTIONS - Security Assessment Hub",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

APP_TITLE = "MARS SOLUTIONS - Security Assessment Hub"


def _init_session() -> None:
    """Инициализация session_state."""
    if "tool_status" not in st.session_state:
        st.session_state.tool_status = check_tools()
    if "audit_result" not in st.session_state:
        st.session_state.audit_result = None
    if "raw_logs" not in st.session_state:
        st.session_state.raw_logs = None


def _render_sidebar() -> bool:
    """
    Боковая панель: статус утилит, ошибки, кнопка перепроверки.

    :return: True если все зависимости установлены.
    """
    st.sidebar.header("Зависимости системы")
    status: dict[str, bool] = st.session_state.tool_status

    for tool, available in status.items():
        icon = "✅" if available else "❌"
        st.sidebar.write(f"{icon} **{tool}**")

    missing = missing_tools(status)
    if missing:
        for tool in missing:
            hint = INSTALL_HINTS.get(tool, f"sudo apt install {tool}")
            st.sidebar.error(
                f"Утилита `{tool}` не найдена.\n\n"
                f"Установите: `{hint}`"
            )

        if st.sidebar.button("Проверить зависимости снова", use_container_width=True):
            st.session_state.tool_status = check_tools()
            st.rerun()

        st.sidebar.warning(
            "Установите все утилиты, затем нажмите «Проверить зависимости снова»."
        )
        return False

    st.sidebar.success("Все утилиты доступны.")
    return True


def _severity_style(val: str) -> str:
    """CSS-фон для колонки severity в таблице CVE."""
    v = str(val).lower()
    if v in ("critical", "high"):
        return "background-color: #fecaca; color: #7f1d1d;"
    if v in ("medium", "moderate"):
        return "background-color: #fef08a; color: #713f12;"
    if v == "low":
        return "background-color: #bbf7d0; color: #14532d;"
    return "background-color: #e5e7eb; color: #374151;"


def _normalize_technologies(raw: list[Any]) -> list[str]:
    """Приводит technologies к списку строк для отображения."""
    result: list[str] = []
    for item in raw:
        if isinstance(item, str):
            result.append(item)
        elif isinstance(item, dict):
            name = item.get("name", "")
            version = item.get("version", "")
            label = f"{name} {version}".strip() or str(item)
            result.append(label)
        else:
            result.append(str(item))
    return result


def _cves_to_dataframe(cves: list[Any]) -> pd.DataFrame:
    """Формирует DataFrame для st.dataframe с подсветкой severity."""
    if not cves:
        return pd.DataFrame(
            columns=["id", "severity", "description", "remediation"]
        )

    rows: list[dict[str, str]] = []
    for cve in cves:
        if isinstance(cve, dict):
            rows.append({
                "id": str(cve.get("id", "N/A")),
                "severity": str(cve.get("severity", "Unknown")),
                "description": str(cve.get("description", "")),
                "remediation": str(cve.get("remediation", cve.get("fix", ""))),
            })
        else:
            rows.append({
                "id": str(cve),
                "severity": "Unknown",
                "description": "",
                "remediation": "",
            })
    return pd.DataFrame(rows)


def _render_ai_tab(analysis: dict[str, Any]) -> None:
    """Вкладка отчёта AI: технологии и таблица CVE."""
    technologies = _normalize_technologies(analysis.get("technologies", []))
    cves = analysis.get("cves", [])
    summary = analysis.get("summary", "")

    st.subheader("Резюме")
    st.info(summary or "Резюме не предоставлено.")

    st.subheader("Обнаруженные технологии")
    if technologies:
        if hasattr(st, "pills"):
            st.pills(technologies, selection_mode=None, key="tech_pills")
        else:
            st.caption(" · ".join(f"`{t}`" for t in technologies))
    else:
        st.caption("Технологии не определены.")

    st.subheader("CVE")
    df = _cves_to_dataframe(cves)
    if df.empty:
        st.caption("Уязвимости CVE не выявлены.")
    else:
        styler = df.style
        if hasattr(styler, "map"):
            styled = styler.map(_severity_style, subset=["severity"])
        else:
            styled = styler.applymap(_severity_style, subset=["severity"])
        st.dataframe(styled, use_container_width=True, hide_index=True)


def _render_raw_tab(nmap_log: str, whatweb_log: str) -> None:
    """Вкладка сырых логов сканеров."""
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("#### Nmap")
        st.code(nmap_log or "(пусто)", language="text")
    with col2:
        st.markdown("#### WhatWeb")
        st.code(whatweb_log or "(пусто)", language="text")


def _run_audit(target: str, api_key: str) -> None:
    """Выполняет сканирование и AI-анализ внутри st.status."""
    with st.status("Выполнение аудита...", expanded=True) as status:
        st.write("**Шаг 1/2:** Запуск nmap и whatweb...")
        nmap_log, whatweb_log = run_all_scanners(target)
        st.session_state.raw_logs = {"nmap": nmap_log, "whatweb": whatweb_log}
        st.write("Сканирование завершено.")

        st.write("**Шаг 2/2:** Анализ Claude (маппинг CVE)...")
        analyzer = ClaudeAnalyzer(api_key=api_key)
        try:
            analysis = analyzer.analyze(nmap_log, whatweb_log)
        except RuntimeError as exc:
            status.update(label="Ошибка аудита", state="error")
            st.error(str(exc))
            return

        st.session_state.audit_result = analysis
        status.update(label="Аудит завершён", state="complete")


def main() -> None:
    _init_session()

    st.title(f"🛡️ {APP_TITLE}")
    st.caption(
        "Легальное сканирование и сопоставление CVE. "
        "Используйте только на системах с письменным разрешением."
    )

    deps_ok = _render_sidebar()
    if not deps_ok:
        st.warning(
            "Основной функционал заблокирован до установки всех зависимостей. "
            "См. боковую панель."
        )
        st.stop()

    # Проверка API-ключа (без TARGET в .env)
    settings = try_load_settings()
    if settings is None:
        st.error(
            "Не настроен `CLAUDE_API_KEY`. "
            "Создайте файл `.env` на основе `.env.example`."
        )
        st.stop()

    st.divider()

    target = st.text_input(
        "TARGET (IP, домен или URL)",
        placeholder="192.168.1.10 или https://example.com",
        help="Цель задаётся только через интерфейс, не через .env",
    )

    run_clicked = st.button(
        "Запустить аудит",
        type="primary",
        use_container_width=False,
    )

    if run_clicked:
        if not target or not target.strip():
            st.warning("Укажите TARGET перед запуском.")
        else:
            _run_audit(target.strip(), settings.claude_api_key)
            st.rerun()

    # Вывод результатов предыдущего аудита
    if st.session_state.audit_result and st.session_state.raw_logs:
        st.divider()
        tab_ai, tab_raw = st.tabs(["Отчет AI (CVE)", "Сырые логи сканеров"])

        with tab_ai:
            _render_ai_tab(st.session_state.audit_result)

        with tab_raw:
            logs = st.session_state.raw_logs
            _render_raw_tab(logs.get("nmap", ""), logs.get("whatweb", ""))

        with st.expander("JSON-ответ AI (отладка)"):
            st.json(st.session_state.audit_result)


if __name__ == "__main__":
    main()
