"""Экспорт unified_findings в CSV."""

from __future__ import annotations

import csv
import io
from typing import Any


def findings_to_csv(findings: list[dict[str, Any]]) -> str:
    output = io.StringIO()
    fields = [
        "id",
        "severity",
        "cvss_score",
        "affected_component",
        "description",
        "remediation",
        "nvd_verified",
        "sources",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in findings:
        r = dict(row)
        if isinstance(r.get("sources"), list):
            r["sources"] = ";".join(r["sources"])
        writer.writerow(r)
    return output.getvalue()
