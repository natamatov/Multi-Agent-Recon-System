"""
Единая модель находок и слияние CVE из NVD, Nuclei, AI.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


@dataclass
class UnifiedFinding:
    """Нормализованная находка (CVE + misc уязвимости)."""

    id: str
    severity: str = "unknown"
    cvss_score: float | None = None
    description: str = ""
    remediation: str = ""
    affected_component: str = ""
    sources: list[str] = field(default_factory=list)
    nvd_verified: bool = False
    evidence: str = ""
    # EPSS — вероятность эксплуатации в ближайшие 30 дней (0.0–1.0)
    epss_score: float | None = None
    epss_percentile: float | None = None
    # Дополнительный контекст от сканеров
    tool: str = ""         # какой сканер нашёл (sqlmap, testssl, dalfox, …)
    url: str = ""          # конкретный URL/endpoint
    parameter: str = ""    # уязвимый параметр (для SQLi, XSS)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _norm_severity(val: str | None, cvss: float | None = None) -> str:
    if cvss is not None:
        if cvss >= 9.0:
            return "critical"
        if cvss >= 7.0:
            return "high"
        if cvss >= 4.0:
            return "medium"
        if cvss >= 0.1:
            return "low"
    if not val:
        return "unknown"
    return str(val).lower().strip()


def _parse_ai_cves(ai_cves: list[Any]) -> list[UnifiedFinding]:
    out: list[UnifiedFinding] = []
    for item in ai_cves:
        if isinstance(item, str):
            m = CVE_RE.search(item)
            if m:
                out.append(UnifiedFinding(id=m.group(0).upper(), sources=["ai"]))
            continue
        if not isinstance(item, dict):
            continue
        cid = str(item.get("id", "")).upper()
        if not cid.startswith("CVE-"):
            continue
        out.append(
            UnifiedFinding(
                id=cid,
                severity=_norm_severity(item.get("severity"), item.get("cvss_score")),
                cvss_score=item.get("cvss_score"),
                description=str(item.get("description", "")),
                remediation=str(item.get("remediation", item.get("fix", ""))),
                affected_component=str(
                    item.get("affected_component", item.get("component", ""))
                ),
                sources=["ai"],
            )
        )
    return out


def merge_all_findings(
    *,
    nvd_records: list[dict[str, Any]],
    nuclei_findings: list[dict[str, Any]],
    ai_cves: list[Any],
) -> list[UnifiedFinding]:
    """
    Объединяет CVE с приоритетом полей: NVD > Nuclei > AI.
    """
    merged: dict[str, UnifiedFinding] = {}

    for rec in nvd_records:
        cid = str(rec.get("id", "")).upper()
        if not cid.startswith("CVE-"):
            continue
        merged[cid] = UnifiedFinding(
            id=cid,
            severity=_norm_severity(rec.get("severity"), rec.get("cvss_score")),
            cvss_score=rec.get("cvss_score"),
            description=str(rec.get("description", "")),
            nvd_verified=bool(rec.get("verified", True)),
            sources=["nvd"],
        )

    for nf in nuclei_findings:
        for cid in nf.get("cve_ids", []):
            cid = str(cid).upper()
            if not cid.startswith("CVE-"):
                continue
            if cid in merged:
                merged[cid].sources = sorted(set(merged[cid].sources + ["nuclei"]))
                if not merged[cid].evidence:
                    merged[cid].evidence = nf.get("name", "")
            else:
                merged[cid] = UnifiedFinding(
                    id=cid,
                    severity=_norm_severity(nf.get("severity")),
                    description=str(nf.get("description", nf.get("name", ""))),
                    affected_component=str(nf.get("matched_at", "")),
                    evidence=str(nf.get("name", "")),
                    sources=["nuclei"],
                )

    for af in _parse_ai_cves(ai_cves):
        if af.id in merged:
            cur = merged[af.id]
            cur.sources = sorted(set(cur.sources + ["ai"]))
            if not cur.description and af.description:
                cur.description = af.description
            if not cur.remediation and af.remediation:
                cur.remediation = af.remediation
            if not cur.affected_component and af.affected_component:
                cur.affected_component = af.affected_component
        else:
            merged[af.id] = af

    result = list(merged.values())
    result.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.id))
    return result


def findings_to_cve_dicts(findings: list[UnifiedFinding]) -> list[dict[str, Any]]:
    return [f.to_dict() for f in findings]


def severity_counts(findings: list[UnifiedFinding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts
