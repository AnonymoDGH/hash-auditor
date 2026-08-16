"""Tests for hash_auditor.audit."""

from __future__ import annotations

import pytest

from hash_auditor.audit import (
    audit_batch,
    audit_password,
    risk_score,
    verdict_for,
)


class TestVerdictFor:
    @pytest.mark.parametrize("score,label", [
        (100, "critical"), (80, "critical"),
        (79, "high"), (60, "high"),
        (59, "medium"), (40, "medium"),
        (39, "low"), (20, "low"),
        (19, "minimal"), (0, "minimal"),
    ])
    def test_bands(self, score, label):
        assert verdict_for(score) == label


class TestAuditPassword:
    def test_weak_leaked(self):
        audit = audit_password("password")
        assert audit["verdict"] in ("critical", "high")
        assert audit["risk_score"] >= 60
        assert audit["exposure"]["found"]
        assert any("breach corpus" in i for i in audit["issues"])

    def test_strong_clean(self):
        audit = audit_password("Xk9$mQ2vLp7wZr")
        assert audit["verdict"] in ("minimal", "low", "medium")
        assert audit["risk_score"] < 60
        assert not audit["exposure"]["found"]

    def test_leet_detected(self):
        audit = audit_password("p4ssw0rd")
        assert audit["leet_matches"]
        assert any("leet-mutation" in i for i in audit["issues"])

    def test_date_detected(self):
        audit = audit_password("1990-07-04")
        assert audit["date_score"] >= 0.8
        assert any("date" in i for i in audit["issues"])

    def test_walk_detected(self):
        audit = audit_password("qwertyuiop")
        assert audit["walk_score"] >= 0.8
        assert any("keyboard walk" in i for i in audit["issues"])

    def test_shape(self):
        audit = audit_password("hunter2")
        for key in ("password_length", "strength", "exposure", "randomness",
                    "date_score", "dates", "walk_score", "leet_matches",
                    "risk_score", "verdict", "issues"):
            assert key in audit
        assert 0 <= audit["risk_score"] <= 100

    def test_empty(self):
        audit = audit_password("")
        assert audit["password_length"] == 0
        assert 0 <= audit["risk_score"] <= 100


class TestRiskScore:
    def _findings(self, **overrides):
        base = {
            "exposure": {"score": 0, "found": False,
                         "matched_variant": None},
            "strength": {"verdict": "ok", "flags": []},
            "leet_matches": [],
            "date_score": 0.0,
            "walk_score": 0.0,
            "randomness": {"score": 100},
        }
        base.update(overrides)
        return base

    def test_clean_low(self):
        assert risk_score(self._findings()) < 20

    def test_exposed_high(self):
        score = risk_score(self._findings(
            exposure={"score": 100, "found": True, "matched_variant": "x"}))
        assert score >= 40

    def test_weak_strength(self):
        score = risk_score(self._findings(
            strength={"verdict": "weak", "flags": ["a", "b"]}))
        assert score >= 20

    def test_all_bad(self):
        score = risk_score(self._findings(
            exposure={"score": 100, "found": True, "matched_variant": "x"},
            strength={"verdict": "weak", "flags": ["a"]},
            leet_matches=["password"],
            date_score=1.0,
            walk_score=1.0,
            randomness={"score": 0}))
        assert score >= 90

    def test_bounded(self):
        assert 0 <= risk_score(self._findings()) <= 100


class TestAuditBatch:
    def test_aggregates(self):
        report = audit_batch(["password", "Xk9$mQ2vLp7wZr", "123456"])
        assert report["total"] == 3
        assert sum(report["histogram"].values()) == 3
        assert report["average_risk"] > 0
        assert len(report["ranked"]) == 3

    def test_ranked_worst_first(self):
        report = audit_batch(["Xk9$mQ2vLp7wZr", "password"])
        scores = [r["risk_score"] for r in report["ranked"]]
        assert scores == sorted(scores, reverse=True)
        assert report["ranked"][0]["password"] == "password"

    def test_empty(self):
        report = audit_batch([])
        assert report["total"] == 0
        assert report["average_risk"] == 0.0
        assert report["ranked"] == []

    def test_deterministic(self):
        a = audit_batch(["hunter2", "dragon"])
        b = audit_batch(["hunter2", "dragon"])
        assert a == b
