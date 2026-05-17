"""
Персистентное состояние аудита (переживает обновление страницы Streamlit).
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

STATE_DIR = Path("logs")
STATE_FILE = STATE_DIR / "mars_audit_state.json"
_STATE_LOCK = threading.Lock()


@dataclass
class AuditState:
    status: str = "idle"  # idle | running | completed | cancelled | error
    target: str = ""
    profile: str = "full"  # light | full
    message: str = ""
    started_at: float = 0.0
    updated_at: float = 0.0
    thread_id: int | None = None
    child_pids: list[int] = field(default_factory=list)
    error: str | None = None
    report_ready: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditState:
        return cls(
            status=data.get("status", "idle"),
            target=data.get("target", ""),
            profile=data.get("profile", "full"),
            message=data.get("message", ""),
            started_at=float(data.get("started_at", 0)),
            updated_at=float(data.get("updated_at", 0)),
            thread_id=data.get("thread_id"),
            child_pids=list(data.get("child_pids", [])),
            error=data.get("error"),
            report_ready=bool(data.get("report_ready", False)),
        )


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def load_state() -> AuditState:
    """Загружает состояние с диска."""
    with _STATE_LOCK:
        if not STATE_FILE.exists():
            return AuditState()
        try:
            data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            return AuditState.from_dict(data)
        except (json.JSONDecodeError, OSError):
            return AuditState()


def save_state(state: AuditState) -> None:
    """Сохраняет состояние на диск."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    state.updated_at = time.time()
    with _STATE_LOCK:
        STATE_FILE.write_text(
            json.dumps(state.to_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )


def mark_running(target: str, profile: str, message: str = "Старт") -> AuditState:
    state = AuditState(
        status="running",
        target=target,
        profile=profile,
        message=message,
        started_at=time.time(),
        updated_at=time.time(),
        thread_id=threading.get_ident(),
        report_ready=False,
        error=None,
    )
    save_state(state)
    return state


def update_progress(message: str, child_pids: list[int] | None = None) -> None:
    state = load_state()
    if state.status != "running":
        return
    state.message = message
    if child_pids is not None:
        state.child_pids = child_pids
    save_state(state)


def mark_completed(message: str = "Готово", report_ready: bool = True) -> None:
    state = load_state()
    state.status = "completed"
    state.message = message
    state.report_ready = report_ready
    save_state(state)


def mark_cancelled(message: str = "Отменено пользователем") -> None:
    state = load_state()
    state.status = "cancelled"
    state.message = message
    save_state(state)


def mark_error(error: str) -> None:
    state = load_state()
    state.status = "error"
    state.error = error
    state.message = error
    save_state(state)


def mark_idle() -> None:
    save_state(AuditState())


def is_still_running() -> bool:
    """
    True если аудит помечен running и есть живые дочерние PID
    или обновление было недавно (< 3 часов без завершения).
    """
    state = load_state()
    if state.status != "running":
        return False

    alive_pids = [p for p in state.child_pids if _pid_alive(p)]
    if alive_pids:
        return True

    # Нет живых PID — если недавно обновлялось, считаем ещё running (AI/API)
    if state.updated_at and (time.time() - state.updated_at) < 300:
        return True

    # Зависшее состояние — сброс
    if state.updated_at and (time.time() - state.updated_at) > 10800:
        mark_error("Сессия аудита истекла (таймаут). Запустите снова.")
        return False

    return state.status == "running"
