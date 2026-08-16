"""Tests for hash_auditor.history."""

from __future__ import annotations

import pytest

from hash_auditor.history import (
    PasswordHistory,
    RotationPolicy,
    check_rotation,
    hash_password,
)


class TestHashPassword:
    def test_deterministic(self):
        assert hash_password("pw", b"salt") == hash_password("pw", b"salt")

    def test_salt_matters(self):
        assert hash_password("pw", b"a") != hash_password("pw", b"b")

    def test_str_salt(self):
        assert hash_password("pw", "salt") == hash_password("pw", b"salt")


class TestPasswordHistory:
    def test_add_and_len(self):
        h = PasswordHistory()
        h.add("first")
        h.add("second")
        assert len(h) == 2
        # newest first
        assert h.shadows()[0] == "second"

    def test_verify_reuse(self):
        h = PasswordHistory()
        h.add("hunter2")
        assert h.verify_reuse("hunter2")
        assert not h.verify_reuse("hunter3")

    def test_no_shadow_mode(self):
        h = PasswordHistory(keep_shadow=False)
        h.add("hunter2")
        assert h.shadows() == []
        assert h.verify_reuse("hunter2")

    def test_trim(self):
        h = PasswordHistory()
        for i in range(10):
            h.add(f"pw{i}")
        h.trim(3)
        assert len(h) == 3
        assert h.shadows() == ["pw9", "pw8", "pw7"]

    def test_export_load_roundtrip(self):
        h = PasswordHistory()
        h.add("alpha", created_at=100.0)
        h.add("beta", created_at=200.0)
        loaded = PasswordHistory.load(h.export())
        assert loaded.shadows() == h.shadows()
        assert loaded.verify_reuse("alpha")
        assert loaded.newest_at() == 200.0

    def test_newest_at_empty(self):
        assert PasswordHistory().newest_at() is None


class TestCheckRotation:
    def _history(self):
        h = PasswordHistory()
        h.add("Summer2023", created_at=1000.0)
        h.add("Dragon1", created_at=500.0)
        return h

    def test_fresh_password_allowed(self):
        rep = check_rotation("Xk9$mQ2vLp7wZr", self._history())
        assert rep["allowed"]
        assert rep["reasons"] == []

    def test_exact_reuse_blocked(self):
        rep = check_rotation("Summer2023", self._history())
        assert not rep["allowed"]
        assert rep["reused"]
        assert any("exact reuse" in r for r in rep["reasons"])

    def test_digit_increment_blocked(self):
        rep = check_rotation("Dragon2", self._history())
        assert not rep["allowed"]
        assert any("digit_increment" in r for r in rep["reasons"])

    def test_suffix_swap_blocked(self):
        # 2023 -> 2025 is a suffix rotation (not a +1 increment)
        rep = check_rotation("Summer2025", self._history())
        assert not rep["allowed"]
        assert any("suffix_swap" in r for r in rep["reasons"])

    def test_case_flip_blocked(self):
        rep = check_rotation("summer2023", self._history())
        assert not rep["allowed"]

    def test_similarity_gate(self):
        policy = RotationPolicy(block_mutations=False, min_similarity_gap=0.3)
        rep = check_rotation("Summer2023x", self._history(), policy)
        assert not rep["allowed"]
        assert any("too similar" in r for r in rep["reasons"])

    def test_similarity_gate_disabled(self):
        policy = RotationPolicy(block_mutations=False, min_similarity_gap=0.0)
        rep = check_rotation("Summer2023x", self._history(), policy)
        assert rep["allowed"]

    def test_min_age(self):
        policy = RotationPolicy(min_age_seconds=3600.0)
        rep = check_rotation("Xk9$mQ2vLp7wZr", self._history(), policy,
                             now=2000.0)
        assert not rep["allowed"]
        assert any("too recently" in r for r in rep["reasons"])

    def test_min_age_ok(self):
        policy = RotationPolicy(min_age_seconds=3600.0)
        rep = check_rotation("Xk9$mQ2vLp7wZr", self._history(), policy,
                             now=10000.0)
        assert rep["allowed"]

    def test_closest_reported(self):
        rep = check_rotation("Summer2025", self._history())
        assert rep["closest"] is not None
        assert rep["closest"]["password"] == "Summer2023"
        assert rep["closest"]["similarity"] > 0.8

    def test_empty_history(self):
        rep = check_rotation("anything", PasswordHistory())
        assert rep["allowed"]
        assert rep["closest"] is None

    def test_history_depth_limits_shadow_window(self):
        h = PasswordHistory()
        h.add("Dragon1")
        h.add("CompletelyUnrelated9x")
        policy = RotationPolicy(history_depth=1)
        # only the newest (CompletelyUnrelated9x) is considered
        rep = check_rotation("Dragon2", h, policy)
        assert rep["closest"]["password"] == "CompletelyUnrelated9x"

    def test_reasons_deduplicated(self):
        h = PasswordHistory()
        h.add("Summer2023")
        h.add("Summer2023")  # duplicate entry
        rep = check_rotation("Summer2023", h)
        assert rep["reasons"].count("exact reuse of a previous password") == 1
