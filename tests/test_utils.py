from core.utils import build_url, extract_host, merge_unique_cves


def test_extract_host():
    assert extract_host("https://example.com") == "example.com"
    assert extract_host("http://10.0.0.1:8080") == "10.0.0.1"
    assert extract_host("example.com") == "example.com"

def test_build_url():
    assert build_url("example.com") == "http://example.com"
    assert build_url("https://example.com") == "https://example.com"
    assert build_url("10.0.0.1") == "http://10.0.0.1"

def test_merge_unique_cves():
    list1 = ["CVE-2021-1234", "CVE-2022-5678"]
    list2 = ["CVE-2022-5678", "CVE-2023-9999"]

    merged = merge_unique_cves(list1, list2)
    assert len(merged) == 3
    assert "CVE-2021-1234" in merged
    assert "CVE-2022-5678" in merged
    assert "CVE-2023-9999" in merged
