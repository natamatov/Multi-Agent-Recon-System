#!/usr/bin/env python3
"""
CLI-оркестратор M.A.R.S. (единый пайплайн с Streamlit).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from core.audit_pipeline import run_audit_async, save_reports
from core.audit_profile import AuditProfile, profile_label
from core.config import load_settings, validate_target_string
from core.dependency_manager import ensure_tools_available
from core.logger import get_logger, setup_logging
from core.scope_guard import validate_scope
from core.security_mode import mode_from_env, mode_label

log = get_logger("mars.cli")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="M.A.R.S. Security Audit CLI")
    parser.add_argument(
        "--profile",
        choices=("light", "full"),
        default="full",
        help="light = nmap+whatweb+Claude; full = все сканеры + CrewAI",
    )
    return parser.parse_args()


def main() -> None:
    setup_logging()
    args = _parse_args()
    profile = AuditProfile.LIGHT if args.profile == "light" else AuditProfile.FULL

    print("=" * 60)
    print("  M.A.R.S. — Multi-Agent Recon System (CLI)")
    print("=" * 60)

    settings = load_settings()
    target = settings.target
    if not target:
        raw = input("TARGET (IP, домен или URL): ").strip()
        try:
            target = validate_target_string(raw)
        except ValueError as exc:
            log.error("%s", exc)
            sys.exit(1)

    scope = validate_scope(
        target,
        ticket_id=os.getenv("SCOPE_TICKET_ID"),
        ui_confirmed=True,
    )
    if not scope.allowed:
        log.error("Scope: %s", scope.message)
        sys.exit(1)

    mode = mode_from_env()
    print(f"[+] Цель: {target}")
    print(f"[+] Профиль: {profile_label(profile)}")
    print(f"[+] Режим AI: {mode_label(mode)}")

    print("[*] Проверка утилит...")
    tools = ensure_tools_available()
    print(f"[+] {', '.join(tools)}")

    try:
        report = asyncio.run(
            run_audit_async(
                target,
                settings,
                profile=profile,
                audit_mode=mode,
                on_progress=lambda m: print(f"[*] {m}"),
            )
        )
    except Exception as exc:
        log.error("Аудит прерван: %s", exc)
        sys.exit(1)

    paths = save_reports(report, Path(__file__).resolve().parent)
    print("\n[+] Отчёты:")
    for kind, path in paths.items():
        print(f"    {kind}: {path}")
    if report.get("success") or report.get("ai_summary"):
        print("\n" + (report.get("ai_summary") or "")[:500])


if __name__ == "__main__":
    main()
