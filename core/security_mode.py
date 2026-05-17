"""
Режимы аудита M.A.R.S.: VA (по умолчанию) vs Full Pentest (опционально).
Централизованная логика — без активной эксплуатации в production по умолчанию.
"""

from __future__ import annotations

import os
from enum import Enum


class AuditMode(str, Enum):
    """
    assessment      — только сканирование + CVE/отчёты (Red Team выключен).
    pentest_poc     — Red Team: поиск/загрузка PoC, статический разбор (без запуска).
    pentest_exploit — Red Team + запуск команд (только при ALLOW_EXPLOIT_EXECUTION=true).
    """

    ASSESSMENT = "assessment"
    PENTEST_POC = "pentest_poc"
    PENTEST_EXPLOIT = "pentest_exploit"


def parse_bool_env(name: str, default: bool = False) -> bool:
    """Парсит переменную окружения как bool (1/true/yes/on)."""
    raw = os.getenv(name)
    if raw is None or not str(raw).strip():
        return default
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


def mode_from_env() -> AuditMode:
    """
    Определяет режим из .env (для CLI).

    ENABLE_RED_TEAM=false (default) → assessment
    ENABLE_RED_TEAM=true + ALLOW_EXPLOIT_EXECUTION=false → pentest_poc
    ENABLE_RED_TEAM=true + ALLOW_EXPLOIT_EXECUTION=true → pentest_exploit
    """
    if not parse_bool_env("ENABLE_RED_TEAM", default=False):
        return AuditMode.ASSESSMENT
    if parse_bool_env("ALLOW_EXPLOIT_EXECUTION", default=False):
        return AuditMode.PENTEST_EXPLOIT
    return AuditMode.PENTEST_POC


def resolve_mode(
    ui_mode: str | AuditMode | None,
    *,
    env_enable_red_team: bool = False,
    env_allow_execution: bool = False,
    ui_confirmed_execution: bool = False,
) -> AuditMode:
    """
    Итоговый режим: UI имеет приоритет над .env для Streamlit.

    :param ui_mode: значение из st.session_state / radio.
    :param ui_confirmed_execution: двойное подтверждение в UI для pentest_exploit.
    """
    execution_ok = env_allow_execution or ui_confirmed_execution

    if ui_mode is not None:
        if isinstance(ui_mode, AuditMode):
            mode = ui_mode
        else:
            try:
                mode = AuditMode(ui_mode)
            except ValueError:
                mode = AuditMode.ASSESSMENT

        if mode == AuditMode.PENTEST_EXPLOIT and not execution_ok:
            return AuditMode.PENTEST_POC
        if mode in (AuditMode.PENTEST_POC, AuditMode.PENTEST_EXPLOIT):
            return mode
        return AuditMode.ASSESSMENT

    if env_enable_red_team:
        return AuditMode.PENTEST_EXPLOIT if execution_ok else AuditMode.PENTEST_POC
    return AuditMode.ASSESSMENT


def mode_label(mode: AuditMode) -> str:
    """Человекочитаемое название режима."""
    labels = {
        AuditMode.ASSESSMENT: "Security Assessment (VA)",
        AuditMode.PENTEST_POC: "Full Pentest — PoC Analysis (без запуска)",
        AuditMode.PENTEST_EXPLOIT: "Full Pentest — Exploit Verification",
    }
    return labels.get(mode, mode.value)


def red_team_enabled(mode: AuditMode) -> bool:
    return mode in (AuditMode.PENTEST_POC, AuditMode.PENTEST_EXPLOIT)


def exploit_execution_enabled(mode: AuditMode) -> bool:
    return mode == AuditMode.PENTEST_EXPLOIT
