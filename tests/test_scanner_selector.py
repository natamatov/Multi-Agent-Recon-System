from core.scanner_selector import build_scanner_plan


def test_skip_web_when_no_ports():
    nmap = "Starting Nmap\n22/tcp open ssh\n"
    whatweb = "Apache"
    plan = build_scanner_plan(nmap, whatweb)
    assert "nikto" not in plan.web


def test_web_scanners_when_443_open():
    nmap = "443/tcp open https\n"
    whatweb = "nginx"
    plan = build_scanner_plan(nmap, whatweb)
    assert "nuclei" in plan.web
    assert "nikto" in plan.web


def test_wpscan_when_wordpress():
    nmap = "80/tcp open http\n"
    whatweb = "WordPress 6.0"
    plan = build_scanner_plan(nmap, whatweb)
    assert "wpscan" in plan.web
