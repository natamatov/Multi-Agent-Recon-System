"""
Клиент VirusTotal API v3: проверка домена/IP на репутацию, угрозы, категории.
Работает только при наличии VIRUSTOTAL_API_KEY в .env.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

VT_API_BASE = "https://www.virustotal.com/api/v3"


def _vt_request(endpoint: str, api_key: str) -> dict[str, Any] | None:
    """Выполняет GET запрос к VirusTotal API v3."""
    url = f"{VT_API_BASE}/{endpoint}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError):
        return None


def check_domain(domain: str, api_key: str) -> dict[str, Any]:
    """Проверяет репутацию домена через VirusTotal."""
    data = _vt_request(f"domains/{domain}", api_key)
    if not data:
        return {"success": False, "error": f"Не удалось получить данные VirusTotal для {domain}"}

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    reputation = attrs.get("reputation", 0)
    categories = attrs.get("categories", {})

    return {
        "success": True,
        "domain": domain,
        "reputation": reputation,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "categories": categories,
        "tags": attrs.get("tags", []),
    }


def check_ip(ip: str, api_key: str) -> dict[str, Any]:
    """Проверяет репутацию IP-адреса через VirusTotal."""
    data = _vt_request(f"ip_addresses/{ip}", api_key)
    if not data:
        return {"success": False, "error": f"Не удалось получить данные VirusTotal для {ip}"}

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    return {
        "success": True,
        "ip": ip,
        "reputation": attrs.get("reputation", 0),
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "country": attrs.get("country", "Unknown"),
        "asn": attrs.get("asn", ""),
        "as_owner": attrs.get("as_owner", ""),
        "tags": attrs.get("tags", []),
    }


def run_virustotal_recon(target: str, api_key: str | None = None) -> dict[str, Any]:
    """
    Пассивная проверка цели через VirusTotal.
    Определяет, является ли цель доменом или IP и вызывает нужную функцию.
    """
    import os
    if not api_key:
        api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key or not api_key.strip():
        return {
            "success": False,
            "error": "VIRUSTOTAL_API_KEY не задан. Проверка репутации отключена."
        }

    import re
    import socket

    # Нормализуем цель (убираем схему)
    clean = re.sub(r"^https?://", "", target.strip()).rstrip("/")
    host = clean.split(":")[0]  # убираем порт если есть

    # Определяем: IP или домен
    try:
        socket.inet_aton(host)
        is_ip = True
    except socket.error:
        is_ip = False

    try:
        if is_ip:
            return check_ip(host, api_key.strip())
        else:
            return check_domain(host, api_key.strip())
    except Exception as e:
        return {"success": False, "error": f"Ошибка VirusTotal клиента: {e}"}
