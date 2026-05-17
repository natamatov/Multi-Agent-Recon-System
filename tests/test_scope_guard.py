
from core.scope_guard import validate_scope


def test_scope_blocks_private_without_flag(monkeypatch):
    monkeypatch.delenv("ALLOW_INTERNAL_TARGETS", raising=False)
    monkeypatch.setenv("ALLOW_INTERNAL_TARGETS", "false")
    r = validate_scope("192.168.1.1", ticket_id="T-1", ui_confirmed=True)
    assert not r.allowed


def test_scope_allows_public():
    r = validate_scope("scanme.nmap.org", ticket_id="T-1", ui_confirmed=True)
    assert r.allowed
