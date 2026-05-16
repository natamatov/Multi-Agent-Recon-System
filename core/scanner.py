"""
Запуск nmap и whatweb через subprocess (только сбор данных, без эксплуатации).
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Sequence
from urllib.parse import urlparse


@dataclass
class ScanOutput:
    """Результат одного сканера."""

    tool: str
    command: list[str]
    stdout: str
    stderr: str
    success: bool
    error_message: str | None = None


def _normalize_host(target: str) -> str:
    """Извлекает hostname/IP из TARGET."""
    target = target.strip()
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        return parsed.hostname or target
    return target.split(":")[0]


def _normalize_url(target: str) -> str:
    """Формирует URL для WhatWeb."""
    target = target.strip()
    if target.startswith(("http://", "https://")):
        return target
    return f"http://{target}"


def _run(
    tool: str,
    command: Sequence[str],
    timeout: int = 600,
) -> ScanOutput:
    """
    Безопасный запуск команды без shell=True.

    :param tool: метка сканера (nmap / whatweb).
    :param command: argv для subprocess.
    :param timeout: лимит времени в секундах.
    """
    argv = list(command)
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        success = completed.returncode == 0
        error_msg: str | None = None

        if not success:
            error_msg = f"Код возврата: {completed.returncode}"

        combined = (stdout + stderr).lower()
        unreachable = (
            "failed to resolve",
            "no route to host",
            "connection refused",
            "could not resolve",
            "0 hosts up",
            "unable to connect",
            "name or service not known",
        )
        if any(marker in combined for marker in unreachable):
            success = False
            error_msg = (error_msg or "") + " | Хост недоступен или не отвечает"

        return ScanOutput(
            tool=tool,
            command=argv,
            stdout=stdout,
            stderr=stderr,
            success=success,
            error_message=error_msg.strip() if error_msg else None,
        )
    except subprocess.TimeoutExpired:
        return ScanOutput(
            tool=tool,
            command=argv,
            stdout="",
            stderr="",
            success=False,
            error_message=f"Превышен таймаут ({timeout} с)",
        )
    except FileNotFoundError:
        return ScanOutput(
            tool=tool,
            command=argv,
            stdout="",
            stderr="",
            success=False,
            error_message=f"Утилита {tool} не найдена в PATH",
        )
    except OSError as exc:
        return ScanOutput(
            tool=tool,
            command=argv,
            stdout="",
            stderr="",
            success=False,
            error_message=f"Ошибка ОС: {exc}",
        )


def run_nmap(target: str, timeout: int = 600) -> str:
    """
    Сканирование портов и версий сервисов (nmap -sV).

    :param target: IP, hostname или URL.
    :return: текстовый stdout (при ошибке — сообщение в stdout).
    """
    host = _normalize_host(target)
    command = ["nmap", "-sV", "-T4", "--open", "-oN", "-", host]
    result = _run("nmap", command, timeout=timeout)
    if result.error_message:
        return (
            f"[NMAP ERROR] {result.error_message}\n\n"
            f"STDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}"
        )
    return result.stdout


def run_whatweb(target: str, timeout: int = 300) -> str:
    """
    Fingerprinting веб-технологий (WhatWeb).

    :param target: IP, hostname или URL.
    :return: текстовый stdout.
    """
    url = _normalize_url(target)
    command = ["whatweb", "-a", "3", url]
    result = _run("whatweb", command, timeout=timeout)
    if result.error_message:
        return (
            f"[WHATWEB ERROR] {result.error_message}\n\n"
            f"STDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}"
        )
    return result.stdout


def run_all_scanners(target: str) -> tuple[str, str]:
    """
    Последовательно запускает nmap и whatweb.

    :return: кортеж (nmap_log, whatweb_log).
    """
    nmap_log = run_nmap(target)
    whatweb_log = run_whatweb(target)
    return nmap_log, whatweb_log
