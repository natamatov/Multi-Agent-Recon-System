"""
Клиент NVD API 2.0 (NIST): верификация и обогащение CVE из результатов сканирования.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from core.cancel_registry import AuditCancelledError, is_audit_cancelled
from core.nvd_cache import get_cached, set_cached
from core.rate_limiter import NVD_LIMITER

from .utils import extract_cve_ids


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _fetch_cve(cve_id: str, api_key: str | None = None) -> dict[str, Any] | None:
    """
    Запрашивает одну запись CVE в NVD REST API 2.0.

    :param cve_id: идентификатор CVE-YYYY-NNNNN.
    :param api_key: опциональный NVD_API_KEY (увеличивает лимиты).
    :return: нормализованный словарь или None при ошибке.
    """
    query = f"{NVD_API_URL}?cveId={cve_id}"
    headers = {"User-Agent": "PentestPlatform/1.0 (security-audit)"}
    if api_key:
        headers["apiKey"] = api_key

    request = urllib.request.Request(query, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError):
        return None

    vulnerabilities = payload.get("vulnerabilities", [])
    if not vulnerabilities:
        return None

    cve_item = vulnerabilities[0].get("cve", {})
    metrics = cve_item.get("metrics", {})

    cvss_score: float | None = None
    severity = "unknown"
    vector: str | None = None

    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(metric_key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            severity = (cvss_data.get("baseSeverity") or "unknown").lower()
            vector = cvss_data.get("vectorString")
            break

    descriptions = cve_item.get("descriptions", [])
    description = ""
    for desc in descriptions:
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break
    if not description and descriptions:
        description = descriptions[0].get("value", "")

    return {
        "id": cve_id.upper(),
        "verified": True,
        "source": "NVD",
        "cvss_score": cvss_score,
        "severity": severity,
        "vector": vector,
        "description": description,
        "published": cve_item.get("published"),
        "last_modified": cve_item.get("lastModified"),
    }


def enrich_cves_from_text(
    text: str,
    *,
    api_key: str | None = None,
    max_cves: int = 15,
) -> list[dict[str, Any]]:
    """
    Извлекает CVE из текста и обогащает их данными NVD.

    :param text: агрегированные логи сканирования.
    :param api_key: опциональный ключ NVD (env NVD_API_KEY).
    :param max_cves: лимит запросов за один прогон (rate limit).
    """
    cve_ids = extract_cve_ids(text)[:max_cves]
    enriched: list[dict[str, Any]] = []

    for cve_id in cve_ids:
        if is_audit_cancelled():
            raise AuditCancelledError("NVD: аудит отменён")

        cached = get_cached(cve_id)
        if cached is not None:
            record = cached
        else:
            def _fetch_one(cid: str = cve_id) -> dict[str, Any] | None:
                return _fetch_cve(cid, api_key=api_key)

            record = NVD_LIMITER.call(_fetch_one, is_cancelled=is_audit_cancelled)
            set_cached(cve_id, record)
        if record:
            enriched.append(record)
        else:
            enriched.append({
                "id": cve_id,
                "verified": False,
                "source": "NVD",
                "description": "Запись не найдена или ошибка API",
            })

    return enriched


def enrich_cve_list(
    cve_ids: list[str],
    *,
    api_key: str | None = None,
) -> list[dict[str, Any]]:
    """Обогащает явный список CVE-ID через NVD."""
    combined_text = " ".join(cve_ids)
    return enrich_cves_from_text(combined_text, api_key=api_key, max_cves=len(cve_ids))
