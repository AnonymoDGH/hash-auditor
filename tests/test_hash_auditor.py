import pytest

from hash_auditor import analyze, crack, hash_text, identify


def test_hash_known_values():
    assert hash_text("hello", "md5") == "5d41402abc4b2a76b9719d911017c592"
    assert hash_text("hello", "sha256") == \
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_identify_by_length():
    assert identify(hash_text("x", "md5")) == "md5"
    assert identify(hash_text("x", "sha1")) == "sha1"
    assert identify(hash_text("x", "sha256")) == "sha256"
    assert identify("zz") is None


def test_weak_password_flagged():
    rep = analyze("password123")
    assert rep["verdict"] == "weak"
    assert any("weak" in f for f in rep["flags"])


def test_pin_flagged():
    rep = analyze("12345678")
    assert rep["verdict"] == "weak"
    assert any("PIN" in f for f in rep["flags"])


def test_strong_password_passes():
    rep = analyze("Tr0ub4dor&3-Klux")
    assert rep["verdict"] in ("ok", "acceptable")
    assert rep["entropy_bits"] >= 40


def test_crack_from_wordlist(tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("letmein\nsunshine\nhunter2\n", encoding="utf-8")
    target = hash_text("sunshine", "md5")
    assert crack(target, str(wl), "md5", mutate=False) == "sunshine"


def test_crack_with_mutation(tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("snowball\n", encoding="utf-8")
    target = hash_text("Snowball123", "sha256")
    assert crack(target, str(wl), "sha256", mutate=True) == "Snowball123"


def test_crack_miss_returns_none(tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("nothing\n", encoding="utf-8")
    target = hash_text("nowayjose", "md5")
    assert crack(target, str(wl), "md5") is None
