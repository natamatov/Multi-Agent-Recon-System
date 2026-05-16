#!/usr/bin/env python3
"""
MARS SOLUTIONS - Security Assessment Hub (Swarm Edition)
Streamlit UI для легального Vulnerability Assessment (Kali Linux).
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import streamlit as st

from core.config import try_load_settings
from core.dependency_manager import (
    _APT_PACKAGES,
    check_tools,
    missing_tools,
)
from core.ping_checker import check_target_alive
from core.scanner import run_parallel_scans
from core.shodan_client import run_shodan_recon
from core.virustotal_client import run_virustotal_recon
from core.swarm.orchestrator import MARSSwarmManager


# ——— Конфигурация страницы ———
st.set_page_config(
    page_title="M.A.R.S. Security Assessment Hub",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

APP_TITLE = "M.A.R.S. — Multi-Agent Recon System"


def _init_session() -> None:
    if "tool_status" not in st.session_state:
        st.session_state.tool_status = check_tools()
    if "audit_result" not in st.session_state:
        st.session_state.audit_result = None
    if "raw_logs" not in st.session_state:
        st.session_state.raw_logs = None
    if "ping_result" not in st.session_state:
        st.session_state.ping_result = None


def _render_sidebar() -> bool:
    st.sidebar.header("🔧 Зависимости системы")
    status: dict[str, bool] = st.session_state.tool_status

    all_ok = all(status.values())
    if all_ok:
        st.sidebar.success("✅ Все утилиты доступны")
    else:
        st.sidebar.warning("⚠️ Некоторые утилиты отсутствуют")

    with st.sidebar.expander("Статус утилит", expanded=not all_ok):
        for tool, available in status.items():
            icon = "✅" if available else "❌"
            st.write(f"{icon} `{tool}`")

    missing = missing_tools(status)
    if missing:
        st.sidebar.divider()
        for tool in missing:
            package = _APT_PACKAGES.get(tool, tool)
            st.sidebar.code(f"sudo apt install {package}", language="bash")

        if st.sidebar.button("🔄 Проверить снова", use_container_width=True):
            st.session_state.tool_status = check_tools()
            st.rerun()
        return False

    if st.sidebar.button("🔄 Обновить статус", use_container_width=True):
        st.session_state.tool_status = check_tools()
        st.rerun()

    # Показать сетевые настройки если заданы
    settings = st.session_state.get("_settings")
    if settings:
        st.sidebar.divider()
        st.sidebar.caption("🌐 Сетевые настройки")
        if settings.network_interface:
            st.sidebar.info(f"Интерфейс: `{settings.network_interface}`")
        if settings.http_proxy:
            st.sidebar.info(f"Прокси: `{settings.http_proxy}`")
        if settings.source_ip:
            st.sidebar.info(f"Source IP: `{settings.source_ip}`")

    return True


def _run_audit(target: str) -> None:
    """Выполняет полный цикл аудита с детальным прогрессом."""
    settings = st.session_state.get("_settings")

    with st.status("🚀 Выполнение аудита...", expanded=True) as audit_status:

        # ─── Шаг 0: Проверка доступности цели ───────────────────────────────
        st.write("---")
        st.write("**[0/4] 📡 Проверка доступности цели...**")
        ping_result = asyncio.run(check_target_alive(target))
        st.session_state.ping_result = ping_result

        if ping_result.is_alive:
            lat = f" ({ping_result.latency_ms:.1f} ms)" if ping_result.latency_ms else ""
            ip_info = f" → `{ping_result.resolved_ip}`" if ping_result.resolved_ip else ""
            st.success(f"✅ Цель доступна via **{ping_result.method}**{lat}{ip_info}")
        else:
            # Хост недоступен — предупреждаем, но не останавливаем
            # (файрвол может блокировать ping, но сканеры всё равно попробуют)
            st.warning(
                f"⚠️ Цель не отвечает на ping ({ping_result.error}). "
                "Сканирование будет продолжено — возможно, ICMP заблокирован файрволом."
            )

        # ─── Шаг 1: Параллельное сканирование ───────────────────────────────
        st.write("---")
        st.write("**[1/4] 🔍 Параллельный запуск сканеров...**")

        scanners_info = [
            ("nmap", "Порты и версии сервисов"),
            ("whatweb", "Fingerprint веб-стека"),
            ("nuclei", "CVE и misconfig шаблоны"),
            ("subfinder", "Поиск поддоменов"),
            ("wpscan", "WordPress аудит"),
            ("nikto", "Уязвимости веб-сервера"),
            ("waf", "Детекция WAF/CDN (WebCheck)"),
        ]
        cols = st.columns(3)
        for i, (tool, desc) in enumerate(scanners_info):
            with cols[i % 3]:
                st.info(f"⏳ **{tool}**\n{desc}")

        try:
            bundle = asyncio.run(run_parallel_scans(
                target,
                wpscan_api_key=settings.wpscan_api_key if settings else None,
                network_interface=settings.network_interface if settings else None,
                source_ip=settings.source_ip if settings else None,
                http_proxy=settings.http_proxy if settings else None,
            ))
        except Exception as e:
            audit_status.update(label="❌ Ошибка сканирования", state="error")
            st.error(f"Критическая ошибка сканирования: {e}")
            return

        logs = bundle.to_log_text()
        st.session_state.raw_logs = logs

        # Вывод итогов по каждому сканеру
        st.write("📊 **Результаты сканирования:**")
        cols2 = st.columns(3)
        for i, result in enumerate(bundle.results):
            with cols2[i % 3]:
                if result.success:
                    lines = result.stdout.strip().count("\n") + 1 if result.stdout.strip() else 0
                    st.success(f"✅ **{result.tool}** — {lines} строк")
                else:
                    st.error(f"❌ **{result.tool}** — {result.error_message}")
        if bundle.nuclei:
            n = len(bundle.nuclei.findings)
            if bundle.nuclei.success:
                st.success(f"✅ **nuclei** — {n} находок")
            else:
                st.warning(f"⚠️ **nuclei** — {bundle.nuclei.error_message}")
        
        if bundle.waf:
            if bundle.waf.get("detected"):
                st.error(f"🛡️ **WAF/CDN** — Обнаружен ({', '.join(bundle.waf.get('providers', []))})")
            else:
                st.success("✅ **WAF/CDN** — Не обнаружен")

        # ─── Шаг 2: OSINT ────────────────────────────────────────────────────
        st.write("---")
        st.write("**[2/4] 🌐 Пассивная разведка (OSINT)...**")

        col_s, col_v = st.columns(2)
        with col_s:
            with st.spinner("Запрос к Shodan..."):
                shodan_res = run_shodan_recon(
                    target,
                    api_key=settings.shodan_api_key if settings else None
                )
            if shodan_res.get("success"):
                ports = shodan_res.get("open_ports", [])
                st.success(f"✅ Shodan: {len(ports)} открытых портов {ports[:5]}")
            else:
                st.info(f"ℹ️ Shodan: {shodan_res.get('error')}")

        with col_v:
            with st.spinner("Запрос к VirusTotal..."):
                vt_res = run_virustotal_recon(
                    target,
                    api_key=settings.virustotal_api_key if settings else None
                )
            if vt_res.get("success"):
                mal = vt_res.get("malicious", 0)
                if mal > 0:
                    st.error(f"🚨 VirusTotal: {mal} движков считают цель вредоносной!")
                else:
                    st.success("✅ VirusTotal: цель чистая (0 детектов)")
            else:
                st.info(f"ℹ️ VirusTotal: {vt_res.get('error')}")

        osint_data = f"SHODAN: {json.dumps(shodan_res, ensure_ascii=False)}\n\n"
        osint_data += f"VIRUSTOTAL: {json.dumps(vt_res, ensure_ascii=False)}\n\n"
        subfinder_res = next((r for r in bundle.results if r.tool == "subfinder"), None)
        if subfinder_res and subfinder_res.success and subfinder_res.stdout.strip():
            subs = subfinder_res.stdout.strip().splitlines()
            st.info(f"🔗 Subfinder нашёл {len(subs)} поддоменов")
            osint_data += f"SUBFINDER:\n{subfinder_res.stdout}\n"
            
        if bundle.waf:
            osint_data += f"WAF/CDN DETECTION:\n{json.dumps(bundle.waf, ensure_ascii=False, indent=2)}\n"

        # ─── Шаг 3: AI Swarm ─────────────────────────────────────────────────
        st.write("---")
        st.write("**[3/4] 🤖 Запуск мультиагентного роя (CrewAI)...**")

        agent_steps = []

        def step_callback(step_info):
            name = getattr(step_info, "name", None) or "выполняет анализ"
            agent_steps.append(name)
            st.write(f"  ⚙️ Агент: *{name}*")

        with st.spinner("Агенты анализируют данные... Это займёт 1-3 минуты."):
            manager = MARSSwarmManager(step_callback=step_callback)
            swarm_results = manager.run_analysis(logs, osint_data=osint_data)

        if not swarm_results.get("success"):
            audit_status.update(label="❌ Ошибка AI-анализа", state="error")
            st.error(f"Ошибка роя агентов: {swarm_results.get('error')}")
            return

        st.success(f"✅ AI Swarm завершён ({len(agent_steps)} шагов)")

        # ─── Шаг 4: Готово ───────────────────────────────────────────────────
        st.write("---")
        st.write("**[4/4] 📋 Отчёт готов!** Перейдите к вкладкам ниже.")

        st.session_state.audit_result = swarm_results
        audit_status.update(label="✅ Аудит завершён успешно!", state="complete")


def main() -> None:
    _init_session()

    st.title(f"🛡️ {APP_TITLE}")
    st.caption(
        "Легальный Vulnerability Assessment с Multi-Agent AI Swarm. "
        "**Используйте только на системах с письменным разрешением.**"
    )

    deps_ok = _render_sidebar()

    settings = try_load_settings()
    if settings is None:
        st.error(
            "❌ Не задан `CLAUDE_API_KEY` в файле `.env`. "
            "Скопируйте `.env.example` → `.env` и вставьте ваш ключ Anthropic."
        )
        st.stop()

    st.session_state["_settings"] = settings

    if not deps_ok:
        st.warning("⚠️ Установите все системные утилиты (см. боковую панель) и обновите статус.")
        st.stop()

    st.divider()

    col_input, col_btn = st.columns([4, 1])
    with col_input:
        target = st.text_input(
            "🎯 TARGET (IP, домен или URL)",
            placeholder="192.168.1.10 или https://example.com",
            label_visibility="collapsed",
        )
    with col_btn:
        run_clicked = st.button("🚀 Запустить аудит", type="primary", use_container_width=True)

    if run_clicked:
        if not target or not target.strip():
            st.warning("⚠️ Укажите TARGET перед запуском.")
        else:
            # Очищаем предыдущие результаты
            st.session_state.audit_result = None
            st.session_state.raw_logs = None
            st.session_state.ping_result = None
            _run_audit(target.strip())

    # ─── Вывод результатов ───────────────────────────────────────────────────
    res = st.session_state.audit_result
    if res and st.session_state.raw_logs:
        st.divider()
        st.subheader("📊 Результаты аудита")

        tab_parsed, tab_cve, tab_exploit, tab_sigma, tab_osint, tab_raw = st.tabs([
            "📄 Нормализованные данные",
            "🚨 Уязвимости (CVE)",
            "💣 Эксплойты (PoC)",
            "🛡️ Sigma & Playbook",
            "🌐 OSINT & Dorking",
            "📜 Сырые логи",
        ])

        with tab_parsed:
            st.subheader("Извлечённые данные (Parser Agent)")
            st.markdown(res.get("parsed_data", "_Нет данных._"))

        with tab_cve:
            st.subheader("Анализ уязвимостей (Threat Intel Agent)")
            st.markdown(res.get("cve_data", "_Уязвимости не обнаружены._"))

        with tab_exploit:
            st.subheader("Верификация эксплойтов (Red Team Agent)")
            st.markdown(res.get("exploit_data", "_Эксплойты не загружены._"))

        with tab_sigma:
            st.subheader("Защитный Playbook & Sigma-правила (SOC Engineer)")
            st.markdown(res.get("sigma_playbook", "_Playbook не сгенерирован._"))

        with tab_osint:
            st.subheader("Поверхность атаки & Google Dorks (OSINT Agent)")
            ping = st.session_state.get("ping_result")
            if ping:
                st.info(ping.summary())
            st.markdown(res.get("osint_dorking", "_OSINT данные не сгенерированы._"))

        with tab_raw:
            st.subheader("Сырые логи сканирования")
            st.code(st.session_state.raw_logs, language="text")


if __name__ == "__main__":
    main()
