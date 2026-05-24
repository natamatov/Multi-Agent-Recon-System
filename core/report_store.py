"""
История аудитов: reports/<target>_<ts>/ + индекс + diff CVE.
"""

from __future__ import annotations

import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.findings import merge_all_findings, severity_counts

REPORTS_DIR = Path("reports")
INDEX_FILE = REPORTS_DIR / "index.json"
MAX_HISTORY = 50


def _safe_slug(target: str) -> str:
    slug = re.sub(r"[^\w.\-]+", "_", target.strip())[:80]
    return slug or "unknown"


def _audit_id(target: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"{_safe_slug(target)}_{ts}"


def _load_index() -> list[dict[str, Any]]:
    if not INDEX_FILE.exists():
        return []
    try:
        return json.loads(INDEX_FILE.read_text(encoding="utf-8"))  # type: ignore
    except json.JSONDecodeError:
        return []


def _save_index(entries: list[dict[str, Any]]) -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    INDEX_FILE.write_text(
        json.dumps(entries[:MAX_HISTORY], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def archive_report(report: dict[str, Any], paths: dict[str, str]) -> str:
    """
    Копирует отчёт в reports/<audit_id>/ и обновляет индекс.

    :return: audit_id
    """
    target = report.get("audit", {}).get("target", "unknown")
    aid = _audit_id(target)
    dest = REPORTS_DIR / aid
    dest.mkdir(parents=True, exist_ok=True)

    (dest / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    for kind, src in paths.items():
        src_path = Path(src)
        if src_path.exists():
            shutil.copy2(src_path, dest / f"audit_report.{kind}")

    entry = {
        "audit_id": aid,
        "target": target,
        "timestamp_utc": report.get("audit", {}).get("timestamp_utc", ""),
        "profile": report.get("audit", {}).get("profile", ""),
        "path": str(dest),
        "cve_count": len(report.get("unified_findings", report.get("cves", []))),
        "critical_high": _count_critical_high(report),
    }
    entries = [entry] + _load_index()
    _save_index(entries)
    return aid


def _count_critical_high(report: dict[str, Any]) -> int:
    findings = report.get("unified_findings", [])
    n = 0
    for f in findings:
        sev = (f.get("severity") if isinstance(f, dict) else "").lower()  # type: ignore
        if sev in ("critical", "high"):
            n += 1
    return n


def list_recent_audits(limit: int = 10) -> list[dict[str, Any]]:
    return _load_index()[:limit]


def load_archived_report(audit_id: str) -> dict[str, Any] | None:
    path = REPORTS_DIR / audit_id / "report.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))  # type: ignore


def diff_cve_reports(
    previous: dict[str, Any],
    current: dict[str, Any],
) -> dict[str, Any]:
    """
    Сравнивает два отчёта: новые / исчезнувшие / общие CVE.
    """
    prev_ids = {f["id"] for f in previous.get("unified_findings", []) if f.get("id")}
    curr_ids = {f["id"] for f in current.get("unified_findings", []) if f.get("id")}

    curr_map = {f["id"]: f for f in current.get("unified_findings", [])}
    prev_map = {f["id"]: f for f in previous.get("unified_findings", [])}

    return {
        "new": [curr_map[i] for i in sorted(curr_ids - prev_ids)],
        "resolved": [prev_map[i] for i in sorted(prev_ids - curr_ids)],
        "unchanged": [curr_map[i] for i in sorted(prev_ids & curr_ids)],
        "previous_audit_id": previous.get("audit", {}).get("timestamp_utc"),
        "current_audit_id": current.get("audit", {}).get("timestamp_utc"),
    }


def find_previous_report(target: str, exclude_audit_id: str | None = None) -> dict[str, Any] | None:
    """Последний архивный отчёт для того же TARGET."""
    slug = _safe_slug(target)
    for entry in _load_index():
        if exclude_audit_id and entry.get("audit_id") == exclude_audit_id:
            continue
        if _safe_slug(entry.get("target", "")) == slug or entry.get("target") == target:
            return load_archived_report(entry["audit_id"])
    return None


def enrich_report_with_unified_findings(report: dict[str, Any]) -> dict[str, Any]:
    """Добавляет unified_findings в отчёт перед сохранением."""
    findings = merge_all_findings(
        nvd_records=report.get("nvd_enrichment", []),
        nuclei_findings=report.get("nuclei_findings", []),
        ai_cves=report.get("cves", []),
    )
    report["unified_findings"] = [f.to_dict() for f in findings]
    report["cves"] = report["unified_findings"]
    report["severity_summary"] = severity_counts(findings)
    return report
