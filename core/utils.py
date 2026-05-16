"""
Общие утилиты проекта: проверка бинарников, нормализация цели, извлечение CVE.
"""

from __future__ import annotations

import re
import shutil
from typing import Iterable
from urllib.parse import urlparse

# Стандартный формат идентификатора CVE
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# Утилиты, проверяемые на уровне utils (дублируют логику dependency_manager)
SCANNER_TOOLS: tuple[str, ...] = ("nmap", "whatweb", "dirb", "nuclei", "searchsploit")


def is_tool_available(tool_name: str) -> bool:
    """
    Проверяет наличие исполняемого файла в PATH через shutil.which.

    :param tool_name: имя бинарника (nmap, nuclei, searchsploit).
    :return: True, если утилита доступна.
    """
    return shutil.which(tool_name) is not None


def check_nuclei_available() -> bool:
    """
    Специализированная проверка Nuclei (используется перед запуском воркера).
    """
    return is_tool_available("nuclei")


def extract_host(target: str) -> str:
    """Извлекает hostname или IP из TARGET (URL или host:port)."""
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        return parsed.hostname or target
    return target.split(":")[0]


def build_url(target: str) -> str:
    """Формирует HTTP(S) URL для веб-сканеров."""
    if target.startswith(("http://", "https://")):
        return target
    return f"http://{target}"


def extract_cve_ids(text: str) -> list[str]:
    """
    Извлекает уникальные CVE-ID из произвольного текста (логи, JSON Nuclei).

    :param text: stdout сканеров или сериализованный JSON.
    :return: отсортированный список CVE в верхнем регистре.
    """
    found = {match.group(0).upper() for match in CVE_PATTERN.finditer(text)}
    return sorted(found)


def merge_unique_cves(*sources: Iterable[str]) -> list[str]:
    """Объединяет несколько итерируемых наборов CVE без дубликатов."""
    merged: set[str] = set()
    for source in sources:
        merged.update(c.upper() for c in source)
    return sorted(merged)
