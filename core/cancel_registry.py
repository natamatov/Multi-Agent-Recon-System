"""
Отмена аудита: флаг, учёт PID дочерних процессов, убийство при stop.
"""

from __future__ import annotations

import os
import signal
import threading
from typing import Any


class AuditCancelledError(Exception):
    """Аудит прерван пользователем или по таймауту отмены."""


class AuditCancellation:
    """Синглтон контекста отмены текущего аудита."""

    _lock = threading.Lock()
    _instance: AuditCancellation | None = None

    def __init__(self) -> None:
        self.cancel_event = threading.Event()
        self._pids: set[int] = set()

    @classmethod
    def get(cls) -> AuditCancellation:
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def reset(self) -> None:
        """Сброс перед новым аудитом."""
        self.cancel_event.clear()
        with self._lock:
            self._pids.clear()

    def register_pid(self, pid: int) -> None:
        if isinstance(pid, int) and pid > 0:
            with self._lock:
                self._pids.add(pid)

    def unregister_pid(self, pid: int) -> None:
        with self._lock:
            self._pids.discard(pid)

    def is_cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def request_cancel(self) -> list[int]:
        """Устанавливает флаг и завершает дочерние процессы."""
        self.cancel_event.set()
        killed: list[int] = []
        with self._lock:
            pids = list(self._pids)
        for pid in pids:
            try:
                if os.name == "nt":
                    os.kill(pid, signal.SIGTERM)
                else:
                    os.kill(pid, signal.SIGKILL)
                killed.append(pid)
            except (ProcessLookupError, PermissionError, OSError):
                pass
        return killed

    def snapshot_pids(self) -> list[int]:
        with self._lock:
            return sorted(self._pids)


def is_audit_cancelled() -> bool:
    return AuditCancellation.get().is_cancelled()


def ensure_not_cancelled() -> None:
    if is_audit_cancelled():
        raise AuditCancelledError("Аудит отменён")
