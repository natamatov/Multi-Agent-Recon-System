"""
Утилита проверки доступности цели перед сканированием.
Использует ICMP ping (subprocess) и TCP-connect fallback.
"""

from __future__ import annotations

import asyncio
import platform
import socket
from dataclasses import dataclass
from typing import Any


@dataclass
class PingResult:
    host: str
    is_alive: bool
    method: str          # "icmp", "tcp", "dns_only"
    latency_ms: float | None = None
    resolved_ip: str | None = None
    error: str | None = None

    def summary(self) -> str:
        if self.is_alive:
            lat = f" ({self.latency_ms:.1f} ms)" if self.latency_ms else ""
            ip = f" [{self.resolved_ip}]" if self.resolved_ip else ""
            return f"✅ {self.host}{ip} доступен via {self.method}{lat}"
        return f"❌ {self.host} недоступен ({self.error or 'нет ответа'})"


def _resolve_host(target: str) -> str | None:
    """Резолвит домен/URL в IP."""
    import re
    host = re.sub(r"^https?://", "", target.strip()).split(":")[0].rstrip("/")
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


async def ping_icmp_async(host: str, count: int = 2, timeout: int = 5) -> PingResult:
    """
    ICMP ping через системную утилиту (работает на Linux/macOS/Windows).
    Не требует root на большинстве систем.
    """
    ip = _resolve_host(host)
    
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), host]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(timeout), host]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_b, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 3)
        stdout = stdout_b.decode("utf-8", errors="replace")

        is_alive = proc.returncode == 0

        # Извлекаем задержку из вывода ping
        latency: float | None = None
        import re
        # Linux: "rtt min/avg/max/mdev = 1.23/2.34/3.45/0.56 ms"
        m = re.search(r"rtt .+?= [\d.]+/([\d.]+)/", stdout)
        if not m:
            # Windows: "Average = 23ms"
            m = re.search(r"Average\s*=\s*([\d.]+)ms", stdout)
        if m:
            latency = float(m.group(1))

        return PingResult(
            host=host,
            is_alive=is_alive,
            method="icmp",
            latency_ms=latency,
            resolved_ip=ip,
            error=None if is_alive else "ICMP timeout / host unreachable",
        )

    except asyncio.TimeoutError:
        return PingResult(host=host, is_alive=False, method="icmp",
                          resolved_ip=ip, error="Ping timeout")
    except FileNotFoundError:
        # ping не найден — используем TCP fallback
        return await ping_tcp_async(host, resolved_ip=ip)
    except Exception as e:
        return PingResult(host=host, is_alive=False, method="icmp",
                          resolved_ip=ip, error=str(e))


async def ping_tcp_async(
    host: str,
    ports: list[int] | None = None,
    timeout: int = 5,
    resolved_ip: str | None = None,
) -> PingResult:
    """
    TCP-connect fallback: пробуем подключиться к распространённым портам.
    Работает даже если ICMP заблокирован файрволом.
    """
    if ports is None:
        ports = [80, 443, 22, 8080, 8443, 21, 25]

    ip = resolved_ip or _resolve_host(host)
    if not ip:
        return PingResult(
            host=host, is_alive=False, method="tcp",
            error="DNS resolution failed — хост не существует или нет сети"
        )

    for port in ports:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return PingResult(
                host=host, is_alive=True, method=f"tcp:{port}",
                resolved_ip=ip,
            )
        except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
            continue

    return PingResult(
        host=host, is_alive=False, method="tcp",
        resolved_ip=ip,
        error="Все TCP-порты закрыты или недоступны (возможно, хост за файрволом)"
    )


async def check_target_alive(target: str) -> PingResult:
    """
    Главная функция: пробует ICMP, при неудаче — TCP fallback.
    Возвращает PingResult с подробным статусом.
    """
    result = await ping_icmp_async(target)
    if not result.is_alive and result.method == "icmp":
        # ICMP мог быть заблокирован — пробуем TCP
        tcp_result = await ping_tcp_async(target, resolved_ip=result.resolved_ip)
        if tcp_result.is_alive:
            return tcp_result
    return result
