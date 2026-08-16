"""Tests for hash_auditor.policy."""

from __future__ import annotations

import pytest

from hash_auditor.policy import (
    PRESETS,
    Policy,
    PolicyReport,
    Violation,
    char_classes,
    check_password,
    grade_wordlist,
)


class TestCharClasses:
    def test_all_classes(self):
        assert char_classes("aA1!") == {
            "lower": True, "upper": True, "digit": True, "symbol": True}

    def test_empty(self):
        assert not any(char_classes("").values())


class TestBasicChecks:
    def test_good_password_passes(self):
        rep = check_password("Tr0ub4dor&3xtra")
        assert rep.passed
        assert rep.grade in ("A", "B")

    def test_too_short(self):
        rep = check_password("Ab1!")
        rules = {v.rule for v in rep.violations}
        assert "min_length" in rules
        assert not rep.passed

    def test_too_long(self):
        rep = check_password("a" * 100)
        assert any(v.rule == "max_length" for v in rep.violations)

    def test_max_length_disabled(self):
        policy = Policy(max_length=None)
        rep = check_password("a" * 500, policy)
        assert not any(v.rule == "max_length" for v in rep.violations)

    def test_min_classes(self):
        policy = Policy(min_classes=3)
        rep = check_password("alllowercase", policy)
        assert any(v.rule == "min_classes" for v in rep.violations)
        assert check_password("Mixed1case", policy).passed

    def test_require_each(self):
        policy = Policy(require_each=True)
        rep = check_password("NoDigitsOrSymbols", policy)
        msgs = [v.message for v in rep.violations if v.rule == "require_each"]
        assert msgs and "digit" in msgs[0]


class TestBanLists:
    def test_banned_exact(self):
        policy = Policy(banned=("Password",))
        assert not check_password("password", policy).passed
        assert any(v.rule == "banned"
                   for v in check_password("PASSWORD", policy).violations)

    def test_banned_substring(self):
        policy = Policy(banned_substrings=("admin",))
        rep = check_password("superADMIN99x", policy)
        assert any(v.rule == "banned_substrings" for v in rep.violations)

    def test_empty_substring_ignored(self):
        policy = Policy(banned_substrings=("",))
        assert not any(v.rule == "banned_substrings"
                       for v in check_password("anything123", policy).violations)


class TestPatterns:
    def test_repeat(self):
        rep = check_password("Xaaaa9q!")
        assert any(v.rule == "max_repeat" for v in rep.violations)

    def test_repeat_disabled(self):
        policy = Policy(max_repeat=None)
        rep = check_password("aaaaaaaaaaaa1!", policy)
        assert not any(v.rule == "max_repeat" for v in rep.violations)

    def test_sequence_ascending(self):
        rep = check_password("Xabcdef9!")
        assert any(v.rule == "max_sequence" for v in rep.violations)

    def test_sequence_descending(self):
        rep = check_password("X9fedcba!")
        assert any(v.rule == "max_sequence" for v in rep.violations)

    def test_keyboard_walk(self):
        rep = check_password("Qwerty99!!")
        assert any(v.rule == "max_keyboard_walk" for v in rep.violations)

    def test_keyboard_walk_vertical(self):
        rep = check_password("Xqazxs2!")
        assert any(v.rule == "max_keyboard_walk" for v in rep.violations)

    def test_unique_ratio(self):
        policy = Policy(min_unique_ratio=0.7)
        rep = check_password("abababab1!", policy)
        assert any(v.rule == "min_unique_ratio" for v in rep.violations)

    def test_whitespace(self):
        rep = check_password("has a space 1!")
        assert any(v.rule == "no_whitespace" for v in rep.violations)

    def test_whitespace_allowed(self):
        policy = Policy(no_whitespace=False)
        rep = check_password("correct horse battery 1", policy)
        assert not any(v.rule == "no_whitespace" for v in rep.violations)


class TestReport:
    def test_score_floor(self):
        policy = Policy(banned=("aaa",), banned_substrings=("aa",),
                        min_classes=4, require_each=True)
        rep = check_password("aaa", policy)
        assert len(rep.errors) >= 5
        assert rep.score == 0
        assert rep.grade == "F"

    def test_warnings_do_not_fail(self):
        rep = PolicyReport(password_length=8, violations=[
            Violation("x", "minor", severity="warning")])
        assert rep.passed
        assert rep.score == 95

    def test_to_dict(self):
        rep = check_password("Ab1!xyzw")
        d = rep.to_dict()
        assert d["passed"] is True
        assert d["grade"] in "ABCDF"
        assert isinstance(d["violations"], list)

    def test_violation_describe(self):
        v = Violation("min_length", "too short")
        assert v.describe() == "[-] min_length: too short"
        w = Violation("x", "hm", severity="warning")
        assert w.describe().startswith("[~]")


class TestPolicySerialisation:
    def test_roundtrip(self):
        p = PRESETS["corporate"]
        d = p.to_dict()
        assert isinstance(d["banned"], list)
        p2 = Policy.from_dict(d)
        assert p2 == p

    def test_unknown_key(self):
        with pytest.raises(TypeError):
            Policy.from_dict({"bogus": 1})


class TestGradeWordlist:
    def test_aggregates(self):
        words = ["password", "Ab3!kqzwmv9", "12345678", "Xk9$mQ2vLp7w"]
        report = grade_wordlist(words, PRESETS["corporate"])
        assert report["total"] == 4
        assert report["passed"] + report["failed"] == 4
        assert 0.0 <= report["pass_rate"] <= 1.0
        assert sum(report["grades"].values()) == 4
        assert len(report["worst"]) <= 10
        # both 'password' (banned) and '12345678' (sequence+classes) fail;
        # ties sort alphabetically
        assert report["worst"][0] == "12345678"
        assert "password" in report["worst"][:2]

    def test_empty(self):
        report = grade_wordlist([])
        assert report["total"] == 0
        assert report["pass_rate"] == 0.0
        assert report["average_score"] == 0.0

    def test_presets_exist(self):
        assert set(PRESETS) == {"basic", "corporate", "nist"}
        # NIST preset allows whitespace and long passwords.
        rep = check_password("correct horse battery staple", PRESETS["nist"])
        assert rep.passed
