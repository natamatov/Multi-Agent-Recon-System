"""
Проверка scope: ticket, allowlist, запрет внутренних сетей без флага.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from core.config import validate_target_string
from core.security_mode import parse_bool_env
from core.utils import extract_host


@dataclass
class ScopeCheckResult:
    allowed: bool
    message: str = ""


def _parse_allowlist() -> list[str]:
    raw = os.getenv("ALLOWED_TARGETS", "")
    if not raw.strip():
        return []
    return [p.strip().lower() for p in raw.split(",") if p.strip()]


def _is_private_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def _matches_allowlist(target: str, patterns: list[str]) -> bool:
    if not patterns:
        return True
    host = extract_host(target).lower()
    t = target.lower()
    for pat in patterns:
        if pat == host or pat in t:
            return True
        if pat.startswith("*.") and host.endswith(pat[1:]):
            return True
        if re.fullmatch(pat.replace(".", r"\.").replace("*", ".*"), host):
            return True
    return False


def validate_scope(
    target: str,
    *,
    ticket_id: str | None = None,
    ui_confirmed: bool = False,
) -> ScopeCheckResult:
    """
    Проверяет цель и опционально номер заявки.

    :param ticket_id: ID тикета/договора (если SCOPE_TICKET_REQUIRED=true).
    :param ui_confirmed: подтверждение в UI.
    """
    try:
        normalized = validate_target_string(target)
    except ValueError as exc:
        return ScopeCheckResult(False, str(exc))

    if parse_bool_env("SCOPE_TICKET_REQUIRED", default=False):
        if not ticket_id or not ticket_id.strip():
            return ScopeCheckResult(
                False,
                "Укажите номер заявки/договора (SCOPE_TICKET_REQUIRED=true).",
            )

    host = extract_host(normalized)
    allowlist = _parse_allowlist()
    if allowlist and not _matches_allowlist(normalized, allowlist):
        return ScopeCheckResult(
            False,
            f"Цель '{normalized}' не в ALLOWED_TARGETS: {', '.join(allowlist)}",
        )

    if _is_private_ip(host) or host in ("localhost", "127.0.0.1"):
        if not parse_bool_env("ALLOW_INTERNAL_TARGETS", default=False):
            return ScopeCheckResult(
                False,
                "Внутренние/localhost цели запрещены. "
                "Задайте ALLOW_INTERNAL_TARGETS=true для lab-сетей.",
            )

    if parse_bool_env("REQUIRE_SCOPE_CONFIRMATION", default=False) and not ui_confirmed:
        return ScopeCheckResult(
            False,
            "Подтвердите авторизацию на тестирование в интерфейсе.",
        )

    return ScopeCheckResult(True, f"Scope OK: {normalized}")
