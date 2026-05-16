#!/usr/bin/env python3
"""
MARS SOLUTIONS - Security Assessment Hub (Swarm Edition)
Streamlit UI для легального Vulnerability Assessment (Kali Linux).
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pandas as pd
import streamlit as st

from core.config import try_load_settings
from core.dependency_manager import (
    _APT_PACKAGES,
    all_tools_ready,
    check_tools,
    missing_tools,
)
from core.scanner import run_parallel_scans
from core.shodan_client import run_shodan_recon
from core.swarm.orchestrator import MARSSwarmManager


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
    """Боковая панель: статус утилит, ошибки, кнопка перепроверки."""
    st.sidebar.header("Зависимости системы")
    status: dict[str, bool] = st.session_state.tool_status

    for tool, available in status.items():
        icon = "✅" if available else "❌"
        st.sidebar.write(f"{icon} **{tool}**")

    missing = missing_tools(status)
    if missing:
        for tool in missing:
            package = _APT_PACKAGES.get(tool, tool)
            hint = f"sudo apt install {package}"
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


def _run_audit(target: str) -> None:
    """Выполняет сканирование и AI-анализ внутри st.status."""
    with st.status("Выполнение аудита...", expanded=True) as status:
        st.write("🔄 **Шаг 1/2:** Запуск параллельного сканирования (nmap, whatweb, nuclei, dirb)...")
        
        try:
            bundle = asyncio.run(run_parallel_scans(target))
        except Exception as e:
            status.update(label="Ошибка сканирования", state="error")
            st.error(f"Не удалось выполнить сканирование: {e}")
            return
            
        logs = bundle.to_log_text()
        st.session_state.raw_logs = logs
        st.write("✅ Сканирование завершено.")

        st.write("🤖 **Шаг 2/3:** Пассивный OSINT (Shodan)...")
        shodan_res = run_shodan_recon(target, api_key=st.session_state.get("shodan_api_key"))
        if shodan_res.get("success"):
            st.write(f"✅ Shodan нашел {len(shodan_res.get('open_ports', []))} портов")
        else:
            st.write(f"⚠️ Shodan: {shodan_res.get('error')}")

        osint_data = f"SHODAN: {json.dumps(shodan_res, ensure_ascii=False)}\n\n"
        subfinder_res = next((r for r in bundle.results if r.tool == "subfinder"), None)
        if subfinder_res and subfinder_res.success:
            osint_data += f"SUBFINDER:\n{subfinder_res.stdout}\n"

        st.write("🤖 **Шаг 3/3:** Запуск мультиагентного роя (CrewAI)...")
        
        def step_callback(step_info):
            st.write(f"⚙️ Рой агентов выполняет шаг: {getattr(step_info, 'name', 'анализ')}")

        manager = MARSSwarmManager(step_callback=step_callback)
        swarm_results = manager.run_analysis(logs, osint_data=osint_data)

        if not swarm_results.get("success"):
            status.update(label="Ошибка AI-анализа", state="error")
            st.error(swarm_results.get("error"))
            return

        st.session_state.audit_result = swarm_results
        status.update(label="Аудит завершён", state="complete")


def main() -> None:
    _init_session()

    st.title(f"🛡️ {APP_TITLE}")
    st.caption(
        "Легальное сканирование и сопоставление CVE с использованием Multi-Agent Swarm. "
        "Используйте только на системах с письменным разрешением."
    )

    deps_ok = _render_sidebar()
    if not deps_ok:
        st.warning(
            "Основной функционал заблокирован до установки всех зависимостей. "
            "См. боковую панель."
        )
        st.stop()

    settings = try_load_settings()
    if settings is None:
        st.error(
            "Не настроен `CLAUDE_API_KEY` в файле `.env`. "
            "Ключ Anthropic обязателен для работы роя агентов."
        )
        st.stop()
        
    # Store settings in session for run_audit
    st.session_state.shodan_api_key = settings.shodan_api_key

    st.divider()

    target = st.text_input(
        "TARGET (IP, домен или URL)",
        placeholder="192.168.1.10 или https://example.com",
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
            _run_audit(target.strip())
            st.rerun()

    # Вывод результатов
    res = st.session_state.audit_result
    if res and st.session_state.raw_logs:
        st.divider()
        
        tab_parsed, tab_cve, tab_sigma, tab_osint, tab_raw = st.tabs([
            "Нормализованные данные", 
            "Уязвимости (CVE)", 
            "Sigma Правила & Playbook", 
            "OSINT & Dorking",
            "Сырые логи сканеров"
        ])

        with tab_parsed:
            st.subheader("Извлеченные данные (Parser Agent)")
            st.markdown(res.get("parsed_data", "Данные отсутствуют."))

        with tab_cve:
            st.subheader("Обогащение и CVE (Threat Intel Agent)")
            st.markdown(res.get("cve_data", "Уязвимости не найдены."))

        with tab_sigma:
            st.subheader("Защитный Playbook (SOC Engineer Agent)")
            st.markdown(res.get("sigma_playbook", "План защиты не сгенерирован."))

        with tab_osint:
            st.subheader("Поверхность атаки и Google Dorks (OSINT Agent)")
            st.markdown(res.get("osint_dorking", "Google Dorks не сгенерированы."))

        with tab_raw:
            st.markdown("#### Комбинированный лог сканирования")
            st.code(st.session_state.raw_logs, language="text")


if __name__ == "__main__":
    main()
