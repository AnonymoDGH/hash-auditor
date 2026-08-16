"""Tests for hash_auditor.fingerprint."""

from __future__ import annotations

import pytest

from hash_auditor.fingerprint import (
    char_class,
    cluster_by_fingerprint,
    fingerprint,
    fingerprint_stats,
    fingerprint_verbose,
    parse_fingerprint,
    shape_similarity,
)


class TestCharClass:
    def test_classes(self):
        assert char_class("A") == "U"
        assert char_class("a") == "L"
        assert char_class("5") == "D"
        assert char_class("!") == "S"

    def test_unicode(self):
        # CJK ideograph: alphanumeric but neither upper nor lower
        assert char_class("\u5b57") == "X"


class TestFingerprint:
    def test_basic(self):
        assert fingerprint("Password123!") == "ULDS"

    def test_runs_collapsed(self):
        assert fingerprint("aaBB11!!") == "LUDS"

    def test_all_lower(self):
        assert fingerprint("password") == "L"

    def test_empty(self):
        assert fingerprint("") == ""

    def test_symbols_only(self):
        assert fingerprint("!@#") == "S"


class TestFingerprintVerbose:
    def test_basic(self):
        assert fingerprint_verbose("Password123!") == "U1L7D3S1"

    def test_single(self):
        assert fingerprint_verbose("a") == "L1"

    def test_empty(self):
        assert fingerprint_verbose("") == ""


class TestParseFingerprint:
    def test_roundtrip(self):
        fp = fingerprint_verbose("Password123!")
        assert parse_fingerprint(fp) == [("U", 1), ("L", 7), ("D", 3),
                                         ("S", 1)]

    def test_multi_digit_length(self):
        assert parse_fingerprint("L12") == [("L", 12)]

    def test_bad_class(self):
        with pytest.raises(ValueError):
            parse_fingerprint("Z3")

    def test_missing_length(self):
        with pytest.raises(ValueError):
            parse_fingerprint("L")

    def test_empty(self):
        assert parse_fingerprint("") == []


class TestFingerprintStats:
    def test_basic(self):
        words = ["Password1", "Dragon99", "abc", "xyz"]
        stats = fingerprint_stats(words)
        assert stats["total"] == 4
        assert stats["unique_shapes"] == 2  # UL D and L
        assert stats["top_shapes"][0]["count"] == 2
        assert stats["shape_entropy"] > 0

    def test_homogeneous(self):
        stats = fingerprint_stats(["abc", "def", "ghi"])
        assert stats["unique_shapes"] == 1
        assert stats["shape_entropy"] == 0.0

    def test_empty(self):
        stats = fingerprint_stats([])
        assert stats["total"] == 0
        assert stats["unique_shapes"] == 0

    def test_examples_present(self):
        stats = fingerprint_stats(["Password1"])
        assert stats["top_shapes"][0]["example"] == "Password1"


class TestCluster:
    def test_basic(self):
        clusters = cluster_by_fingerprint(["Abc1", "Xyz9", "hello"])
        assert clusters["UL D".replace(" ", "")] == ["Abc1", "Xyz9"]
        assert clusters["L"] == ["hello"]

    def test_order_preserved(self):
        clusters = cluster_by_fingerprint(["a1", "b2", "c"])
        assert list(clusters) == ["LD", "L"]


class TestShapeSimilarity:
    def test_identical(self):
        assert shape_similarity("ULDS", "ULDS") == 1.0

    def test_disjoint(self):
        assert shape_similarity("U", "D") == 0.0

    def test_partial(self):
        sim = shape_similarity("ULDS", "ULD")
        assert 0.0 < sim < 1.0

    def test_empty(self):
        assert shape_similarity("", "ULD") == 0.0
        assert shape_similarity("", "") == 1.0

    def test_symmetric(self):
        assert shape_similarity("UL", "ULD") == shape_similarity("ULD", "UL")
