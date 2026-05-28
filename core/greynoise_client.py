"""
GreyNoise — классификация IP-адресов: интернет-шум vs. целевая атака.
API: https://docs.greynoise.io/

Зачем нужно:
  - Отсекает false positives: если IP в логах — просто Shodan/массовый сканер,
    это не атака на вашу систему.
  - malicious classification → реальная угроза.
  - riot (reasonable internet traffic) → легитимные сервисы (Google, Cloudflare).
"""

from __future__ import annotations

import re
from typing import Any

from core.logger import get_logger

log = get_logger("mars.greynoise")

_COMMUNITY_URL = "https://api.greynoise.io/v3/community/{ip}"
_IPV4_RE       = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _is_ipv4(s: str) -> bool:
    return bool(_IPV4_RE.match(s.strip()))


async def classify_ip(ip: str, api_key: str) -> dict[str, Any]:
    """
    Классифицирует IP-адрес через GreyNoise Community API.

    Возвращает:
    {
        "success":        True,
        "ip":             "1.2.3.4",
        "noise":          True/False,    # массовый сканер интернета
        "riot":           True/False,    # легитимный сервис
        "classification": "malicious" / "benign" / "unknown",
        "name":           "Shodan.io",
        "last_seen":      "2024-01-01",
        "interpretation": "...",         # человекочитаемое объяснение
    }
    """
    if not _is_ipv4(ip):
        return {"success": False, "error": f"Не является IPv4: {ip}", "ip": ip}

    try:
        import httpx as _httpx
    except ImportError:
        log.warning("httpx не установлен — GreyNoise недоступен (pip install httpx)")
        return {"success": False, "error": "httpx not installed", "ip": ip}

    headers = {
        "key":        api_key,
        "User-Agent": "M.A.R.S.-Security-Platform/2.0",
    }

    async with _httpx.AsyncClient(timeout=10) as client:
        try:
            r = await client.get(_COMMUNITY_URL.format(ip=ip), headers=headers)
        except Exception as exc:
            log.warning("GreyNoise сетевая ошибка для %s: %s", ip, exc)
            return {"success": False, "error": str(exc), "ip": ip}

    if r.status_code == 200:
        d = r.json()
        result: dict[str, Any] = {
            "success":        True,
            "ip":             ip,
            "noise":          d.get("noise", False),
            "riot":           d.get("riot", False),
            "classification": d.get("classification", "unknown"),
            "name":           d.get("name", ""),
            "link":           d.get("link", ""),
            "last_seen":      d.get("last_seen", ""),
            "message":        d.get("message", ""),
        }
        result["interpretation"] = interpret_greynoise(result)
        return result

    if r.status_code == 404:
        result = {
            "success":        True,
            "ip":             ip,
            "noise":          False,
            "riot":           False,
            "classification": "unknown",
            "message":        "IP не обнаружен в GreyNoise",
        }
        result["interpretation"] = interpret_greynoise(result)
        return result

    if r.status_code == 401:
        log.warning("GreyNoise: неверный API ключ")
        return {"success": False, "error": "Invalid API key", "ip": ip}

    log.warning("GreyNoise HTTP %d для %s", r.status_code, ip)
    return {"success": False, "error": f"HTTP {r.status_code}", "ip": ip}


def interpret_greynoise(result: dict[str, Any]) -> str:
    """Краткое человекочитаемое объяснение результата."""
    if not result.get("success"):
        return f"GreyNoise недоступен: {result.get('error', '?')}"

    ip   = result.get("ip", "?")
    name = result.get("name", "")

    if result.get("riot"):
        return (
            f"✅ {ip} — легитимный сервис"
            + (f" ({name})" if name else "")
            + " — можно исключить из подозреваемых"
        )
    if result.get("noise"):
        cls = result.get("classification", "unknown")
        return (
            f"⚠️ {ip} — массовый интернет-сканер (класс: {cls})"
            + (f", известен как {name}" if name else "")
            + " — вероятно шум, не целевая атака"
        )

    cls = result.get("classification", "unknown")
    if cls == "malicious":
        return f"🔴 {ip} — классифицирован GreyNoise как ВРЕДОНОСНЫЙ — высокий приоритет расследования"
    return (
        f"🎯 {ip} — не является известным сканером/сервисом"
        + (f" (класс: {cls})" if cls != "unknown" else "")
        + " — может быть целевой активностью"
    )


async def run_greynoise_recon(
    target: str,
    api_key: str,
) -> dict[str, Any]:
    """
    Запускает GreyNoise для target (извлекает IP если это hostname/URL).
    Используется из audit_pipeline.
    """
    import socket
    from urllib.parse import urlparse

    # Извлечь hostname/IP из target
    parsed = urlparse(target if "://" in target else f"https://{target}")
    host = parsed.hostname or target

    # Резолвим если это hostname
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        log.warning("GreyNoise: не удалось разрезолвить %s", host)
        return {"success": False, "error": f"DNS resolution failed: {host}", "target": target}

    log.info("GreyNoise: проверка %s → %s", host, ip)
    result = await classify_ip(ip, api_key)
    result["resolved_ip"] = ip
    result["hostname"]    = host
    return result
