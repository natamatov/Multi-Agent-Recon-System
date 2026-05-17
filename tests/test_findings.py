from core.findings import merge_all_findings


def test_merge_cve_priority():
    findings = merge_all_findings(
        nvd_records=[{
            "id": "CVE-2024-0001",
            "severity": "high",
            "cvss_score": 8.0,
            "description": "from nvd",
            "verified": True,
        }],
        nuclei_findings=[{
            "cve_ids": ["CVE-2024-0001"],
            "severity": "critical",
            "name": "test template",
        }],
        ai_cves=[{"id": "CVE-2024-0002", "severity": "Low", "description": "ai"}],
    )
    ids = {f.id for f in findings}
    assert "CVE-2024-0001" in ids
    assert "CVE-2024-0002" in ids
    nvd_one = next(f for f in findings if f.id == "CVE-2024-0001")
    assert nvd_one.nvd_verified
    assert "nvd" in nvd_one.sources
