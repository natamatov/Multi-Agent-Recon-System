import pytest
from unittest.mock import patch, MagicMock
from core.nvd_client import _fetch_cve, enrich_cves_from_text

@patch("core.nvd_client.urllib.request.urlopen")
def test_fetch_cve_success(mock_urlopen):
    mock_response = MagicMock()
    mock_response.read.return_value = b'''{
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2023-1234",
                    "descriptions": [{"lang": "en", "value": "Test Description"}],
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]
                    }
                }
            }
        ]
    }'''
    
    # We must mock the context manager return of urlopen
    mock_urlopen.return_value.__enter__.return_value = mock_response

    result = _fetch_cve("CVE-2023-1234", "dummy_key")
    assert result["verified"] is True
    assert result["id"] == "CVE-2023-1234"
    assert result["cvss_score"] == 9.8
    assert result["severity"] == "critical"

@patch("core.nvd_client.urllib.request.urlopen")
def test_enrich_cves_from_text(mock_urlopen):
    mock_response = MagicMock()
    mock_response.read.return_value = b'{"vulnerabilities": []}' # simulate not found
    mock_urlopen.return_value.__enter__.return_value = mock_response
    
    text = "We found CVE-2021-34527 and CVE-2022-1234 in the logs."
    results = enrich_cves_from_text(text, api_key="dummy")
    assert len(results) == 2
    assert results[0]["id"] == "CVE-2021-34527"
    assert results[1]["id"] == "CVE-2022-1234"
