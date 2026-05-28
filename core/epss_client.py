"""
EPSS (Exploit Prediction Scoring System) — вероятность эксплуатации CVE в ближайшие 30 дней.
Бесплатный API от FIRST.org: https://api.first.org/data/1.0/epss

Интерпретация:
  EPSS > 0.7  → активно эксплуатируется прямо сейчас — СРОЧНО
  EPSS > 0.3  → высокий риск — приоритет
  EPSS < 0.1  → теоретическая угроза — нижний приоритет
"""

from __future__ import annotations

import json
import time
from datetime import date
from pathlib import Path
from typing import Any

from core.logger import get_logger

log = get_logger("mars.epss")

EPSS_API        = "https://api.first.org/data/1.0/epss"
EPSS_CACHE_DIR  = Path("logs/cache/epss")
EPSS_CACHE_TTL  = 86400  # 24 часа


# ── Cache helpers ─────────────────────────────────────────────────────────────

def _cache_path(date_str: str) -> Path:
    return EPSS_CACHE_DIR / f"{date_str}.json"


def _load_cache(date_str: str) -> dict[str, dict[str, float]] | None:
    p = _cache_path(date_str)
    if not p.exists():
        return None
    try:
        if time.time() - p.stat().st_mtime > EPSS_CACHE_TTL:
            return None
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _save_cache(date_str: str, data: dict[str, dict[str, float]]) -> None:
    EPSS_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    _cache_path(date_str).write_text(
        json.dumps(data, ensure_ascii=False), encoding="utf-8"
    )


def _chunks(lst: list, n: int):
    for i in range(0, len(lst), n):
        yield lst[i : i + n]


# ── Main API call ─────────────────────────────────────────────────────────────

async def get_epss_scores(cve_ids: list[str]) -> dict[str, dict[str, float]]:
    """
    Возвращает EPSS score + percentile для каждого CVE.

    Пример:
    {
        "CVE-2021-44228": {"epss": 0.975, "percentile": 0.999},  # Log4Shell
        "CVE-2023-1234":  {"epss": 0.032, "percentile": 0.740},
    }
    """
    if not cve_ids:
        return {}

    try:
        import httpx as _httpx
    except ImportError:
        log.warning("httpx не установлен — EPSS scoring недоступен (pip install httpx)")
        return {}

    today = date.today().isoformat()
    cached = _load_cache(today) or {}

    # Какие CVE нужно запросить
    needed = [c for c in set(cve_ids) if c not in cached]

    if needed:
        async with _httpx.AsyncClient(timeout=20) as client:
            for batch in _chunks(needed, 100):
                try:
                    r = await client.get(EPSS_API, params={"cve": ",".join(batch)})
                    if r.status_code == 200:
                        for item in r.json().get("data", []):
                            cid = str(item.get("cve", "")).upper()
                            cached[cid] = {
                                "epss":       float(item.get("epss", 0)),
                                "percentile": float(item.get("percentile", 0)),
                            }
                except Exception as exc:
                    log.warning("EPSS API ошибка (batch %s…): %s", batch[0], exc)
                    break

        _save_cache(today, cached)
        log.info("EPSS: получено %d scores (из %d запрошено)", len(needed), len(cve_ids))

    return {c: cached[c] for c in cve_ids if c in cached}


# ── Enrichment helper ─────────────────────────────────────────────────────────

def enrich_findings_with_epss(
    findings: list[dict[str, Any]],
    epss_scores: dict[str, dict[str, float]],
) -> list[dict[str, Any]]:
    """Вставляет epss_score и epss_percentile в каждый finding dict."""
    for f in findings:
        cid = str(f.get("id", "")).upper()
        data = epss_scores.get(cid)
        f["epss_score"]      = data["epss"]        if data else None
        f["epss_percentile"] = data["percentile"]  if data else None
    return findings


def prioritize_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Сортирует по комбинированному риску: CVSS × (1 + EPSS×5).
    Без EPSS — по severity + CVSS.
    """
    _SEV = {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 1.0, "info": 0.1, "unknown": 0.5}

    def _risk(f: dict[str, Any]) -> float:
        cvss = float(f.get("cvss_score") or 0)
        epss = float(f.get("epss_score") or 0)
        sev  = _SEV.get(str(f.get("severity", "")).lower(), 0.5)
        if cvss > 0 and epss > 0:
            return cvss * (1.0 + epss * 5.0)
        if cvss > 0:
            return cvss
        return sev

    return sorted(findings, key=_risk, reverse=True)


def epss_label(score: float | None) -> str:
    """Человекочитаемая метка риска по EPSS."""
    if score is None:
        return "N/A"
    if score >= 0.7:
        return f"🔴 КРИТИЧНО ({score:.1%})"
    if score >= 0.3:
        return f"🟠 ВЫСОКИЙ ({score:.1%})"
    if score >= 0.1:
        return f"🟡 СРЕДНИЙ ({score:.1%})"
    return f"🟢 НИЗКИЙ ({score:.1%})"
