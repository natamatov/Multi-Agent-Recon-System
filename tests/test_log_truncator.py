from core.log_truncator import truncate_for_ai


def test_truncate_short_unchanged():
    text = "hello"
    assert truncate_for_ai(text, max_chars=100) == text


def test_truncate_long():
    text = "x" * 100_000
    out = truncate_for_ai(text, max_chars=1000)
    assert len(out) < len(text)
    assert "УСЕЧЕНО" in out
