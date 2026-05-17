"""Тесты режимов аудита."""

import pytest

from core.security_mode import (
    AuditMode,
    exploit_execution_enabled,
    mode_from_env,
    red_team_enabled,
    resolve_mode,
)


def test_assessment_by_default():
    assert resolve_mode("assessment") == AuditMode.ASSESSMENT
    assert not red_team_enabled(AuditMode.ASSESSMENT)


def test_pentest_poc_enables_red_team():
    mode = resolve_mode("pentest_poc", ui_confirmed_execution=True)
    assert mode == AuditMode.PENTEST_POC
    assert red_team_enabled(mode)
    assert not exploit_execution_enabled(mode)


def test_exploit_downgrade_without_confirmation():
    mode = resolve_mode(
        "pentest_exploit",
        env_allow_execution=False,
        ui_confirmed_execution=False,
    )
    assert mode == AuditMode.PENTEST_POC


def test_exploit_with_env_flag(monkeypatch):
    monkeypatch.setenv("ENABLE_RED_TEAM", "true")
    monkeypatch.setenv("ALLOW_EXPLOIT_EXECUTION", "true")
    assert mode_from_env() == AuditMode.PENTEST_EXPLOIT
