"""Tests for hash_auditor.report."""

from __future__ import annotations

import json

import pytest

from hash_auditor.report import (
    AuditReport,
    ascii_table,
    severity_of,
    summarize_findings,
)

TS = "2024-01-01T00:00:00+00:00"


class TestSeverity:
    @pytest.mark.parametrize("score,label", [
        (100, "critical"), (80, "critical"),
        (79, "high"), (60, "high"),
        (59, "medium"), (40, "medium"),
        (39, "low"), (1, "low"),
        (0, "none"),
    ])
    def test_bands(self, score, label):
        assert severity_of(score) == label


class TestAsciiTable:
    def test_basic(self):
        text = ascii_table(("name", "score"), [("pw", 42), ("longer", 7)])
        lines = text.splitlines()
        assert lines[0].startswith("name")
        assert set(lines[1]) <= {"-", "+"}
        assert "42" in lines[2]

    def test_numbers_right_aligned(self):
        text = ascii_table(("n",), [("1",), ("1000",)])
        lines = text.splitlines()
        assert lines[2].endswith("   1")
        assert lines[3].endswith("1000")

    def test_text_left_aligned(self):
        text = ascii_table(("name",), [("ab",), ("x",)])
        lines = text.splitlines()
        assert lines[2].startswith("ab")

    def test_short_row_padded(self):
        text = ascii_table(("a", "b", "c"), [("only",)])
        assert len(text.splitlines()) == 3

    def test_empty_rows(self):
        text = ascii_table(("h",), [])
        assert len(text.splitlines()) == 2

    def test_min_width(self):
        text = ascii_table(("a",), [("b",)], min_width=10)
        # the rule line keeps the full column width
        assert len(text.splitlines()[1]) >= 10


class TestAuditReport:
    def _report(self):
        return AuditReport(title="Test Report", timestamp=TS)

    def test_password_finding_pass(self):
        r = self._report()
        f = r.add_password_finding("pw1", {
            "length": 14, "entropy_bits": 70.0, "verdict": "ok", "flags": []})
        assert f["status"] == "pass"
        assert f["exposure_severity"] == "none"

    def test_password_finding_fail_weak(self):
        r = self._report()
        f = r.add_password_finding("pw2", {
            "length": 4, "entropy_bits": 10.0, "verdict": "weak",
            "flags": ["too short (< 8)"]})
        assert f["status"] == "fail"

    def test_password_finding_fail_exposed(self):
        r = self._report()
        f = r.add_password_finding("pw3", {
            "length": 12, "entropy_bits": 60.0, "verdict": "ok", "flags": []},
            exposure={"found": True, "score": 90,
                      "matched_variant": "password"})
        assert f["status"] == "fail"
        assert f["exposure_severity"] == "critical"

    def test_password_finding_warn(self):
        r = self._report()
        f = r.add_password_finding("pw4", {
            "length": 12, "entropy_bits": 60.0, "verdict": "ok",
            "flags": ["contains a year"]},
            exposure={"found": True, "score": 30, "matched_variant": "x"})
        assert f["status"] == "warn"
        assert f["exposure_severity"] == "low"

    def test_hash_finding_with_candidates(self):
        r = self._report()
        f = r.add_hash_finding("d41d8cd98f00b204e9800998ecf8427e", [
            {"name": "md5", "confidence": 0.5},
            {"name": "ntlm", "confidence": 0.25},
        ], cracked=True, plaintext_label="empty")
        assert f["best_guess"] == "md5"
        assert f["cracked"]

    def test_hash_finding_no_candidates(self):
        r = self._report()
        f = r.add_hash_finding("???", [])
        assert f["best_guess"] is None

    def test_hash_finding_accepts_dataclasses(self):
        from hash_auditor.hashid import HashCandidate
        r = self._report()
        f = r.add_hash_finding("ab" * 16,
                               [HashCandidate("md5", 0.5, ("r",))])
        assert f["candidates"][0]["name"] == "md5"

    def test_policy_and_exposure_summaries(self):
        r = self._report()
        r.add_policy_summary({"total": 4, "passed": 2, "failed": 2,
                              "pass_rate": 0.5,
                              "grades": {"A": 1, "F": 3}})
        r.add_exposure_summary({"total": 3, "exposed": 1,
                                "exposed_fraction": 0.333,
                                "rows": [{"password": "x"}]})
        d = r.to_dict()
        assert d["policy"]["total"] == 4
        assert "rows" not in d["exposure"]  # elided

    def test_notes(self):
        r = self._report()
        r.add_note("first")
        r.add_note("second")
        assert r.to_dict()["notes"] == ["first", "second"]

    def test_to_json_roundtrip(self):
        r = self._report()
        r.add_password_finding("pw", {"length": 8, "entropy_bits": 40.0,
                                      "verdict": "acceptable", "flags": []})
        data = json.loads(r.to_json())
        assert data["title"] == "Test Report"
        assert data["timestamp"] == TS
        assert len(data["passwords"]) == 1

    def test_to_text_sections(self):
        r = self._report()
        r.add_password_finding("hunter2!", {
            "length": 8, "entropy_bits": 30.0, "verdict": "weak",
            "flags": ["in the known-weak list"]},
            exposure={"found": True, "score": 95, "matched_variant": "hunter2"})
        r.add_hash_finding("d41d8cd98f00b204e9800998ecf8427e",
                           [{"name": "md5", "confidence": 0.5}], cracked=True)
        r.add_policy_summary({"total": 1, "passed": 0, "failed": 1,
                              "pass_rate": 0.0, "grades": {"F": 1}})
        r.add_exposure_summary({"total": 1, "exposed": 1,
                                "exposed_fraction": 1.0})
        r.add_note("audit complete")
        text = r.to_text()
        for section in ("PASSWORDS", "HASHES", "POLICY", "BREACH EXPOSURE",
                        "SUMMARY", "NOTES", "Test Report"):
            assert section in text
        assert "md5" in text
        assert "audit complete" in text

    def test_to_text_empty(self):
        text = self._report().to_text()
        assert "Test Report" in text
        assert "PASSWORDS" not in text

    def test_long_hash_truncated_in_text(self):
        r = self._report()
        r.add_hash_finding("ab" * 32, [{"name": "sha256", "confidence": 0.7}])
        assert "..." in r.to_text()


class TestSummarize:
    def test_counts(self):
        r = AuditReport(timestamp=TS)
        r.add_password_finding("ok", {"length": 14, "entropy_bits": 70.0,
                                      "verdict": "ok", "flags": []})
        r.add_password_finding("bad", {"length": 3, "entropy_bits": 5.0,
                                       "verdict": "weak", "flags": ["x"]})
        r.add_hash_finding("h1", [{"name": "md5", "confidence": 0.5}],
                           cracked=True)
        r.add_hash_finding("h2", [{"name": "sha256", "confidence": 0.7}])
        s = summarize_findings(r)
        assert s["passwords_total"] == 2
        assert s["passwords_failed"] == 1
        assert s["passwords_passed"] == 1
        assert s["hashes_total"] == 2
        assert s["hashes_cracked"] == 1
        assert s["weak_algorithms"] == ["md5"]

    def test_empty(self):
        s = summarize_findings(AuditReport(timestamp=TS))
        assert s["passwords_total"] == 0
        assert s["weak_algorithms"] == []
