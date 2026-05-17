"""
Очередь rate-limit для внешних API (NVD, Shodan, VirusTotal).
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Callable, TypeVar

T = TypeVar("T")


class ApiRateLimiter:
    """
    Ограничивает частоту вызовов: min_interval между запросами + опциональный лимит в минуту.
    """

    def __init__(
        self,
        name: str,
        min_interval_sec: float = 1.0,
        max_per_minute: int | None = None,
    ) -> None:
        self.name = name
        self.min_interval_sec = min_interval_sec
        self.max_per_minute = max_per_minute
        self._lock = threading.Lock()
        self._last_call = 0.0
        self._timestamps: deque[float] = deque()

    def _wait_slot(self) -> None:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_call
            if elapsed < self.min_interval_sec:
                time.sleep(self.min_interval_sec - elapsed)
                now = time.monotonic()

            if self.max_per_minute:
                cutoff = now - 60.0
                while self._timestamps and self._timestamps[0] < cutoff:
                    self._timestamps.popleft()
                if len(self._timestamps) >= self.max_per_minute:
                    sleep_for = 60.0 - (now - self._timestamps[0]) + 0.05
                    if sleep_for > 0:
                        time.sleep(sleep_for)
                    now = time.monotonic()
                    cutoff = now - 60.0
                    while self._timestamps and self._timestamps[0] < cutoff:
                        self._timestamps.popleft()

            self._last_call = time.monotonic()
            if self.max_per_minute:
                self._timestamps.append(self._last_call)

    def call(self, func: Callable[[], T], *, is_cancelled: Callable[[], bool] | None = None) -> T:
        """
        Выполняет func после ожидания слота в очереди.

        :raises AuditCancelledError: если is_cancelled() == True до/после ожидания.
        """
        from core.cancel_registry import AuditCancelledError, is_audit_cancelled

        check = is_cancelled or is_audit_cancelled
        if check():
            raise AuditCancelledError("Запрос отменён пользователем")

        self._wait_slot()

        if check():
            raise AuditCancelledError("Запрос отменён пользователем")

        return func()


# Глобальные лимитеры для одного прогона аудита
NVD_LIMITER = ApiRateLimiter("NVD", min_interval_sec=6.5, max_per_minute=5)
SHODAN_LIMITER = ApiRateLimiter("Shodan", min_interval_sec=1.0, max_per_minute=10)
VT_LIMITER = ApiRateLimiter("VirusTotal", min_interval_sec=15.0, max_per_minute=4)
