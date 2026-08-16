"""Tests for hash_auditor.leet."""

from __future__ import annotations

import pytest

from hash_auditor.leet import (
    REVERSE_LEET,
    deleet_variants,
    leet_crack_candidates,
    leet_dictionary_match,
    leet_variants,
)


class TestDeleet:
    def test_plain_passthrough(self):
        assert deleet_variants("hello") == ["hello"]

    def test_single_sub(self):
        variants = deleet_variants("p4ss")
        assert "pass" in variants
        assert variants[0] == "p4ss"  # original first

    def test_multiple_subs(self):
        variants = deleet_variants("p4ssw0rd")
        assert "password" in variants

    def test_ambiguous(self):
        # '1' maps to both i and l
        variants = deleet_variants("1ove")
        assert "iove" in variants
        assert "love" in variants

    def test_empty(self):
        assert deleet_variants("") == [""]

    def test_limit(self):
        # many ambiguous chars, capped
        variants = deleet_variants("111111111111", limit=8)
        assert len(variants) <= 8

    def test_case_insensitive(self):
        variants = deleet_variants("P4SS")
        assert "pass" in variants

    def test_no_duplicates(self):
        variants = deleet_variants("4444")
        assert len(variants) == len(set(variants))


class TestLeetVariants:
    def test_original_first(self):
        out = leet_variants("password")
        assert out[0] == "password"

    def test_applies_subs(self):
        out = leet_variants("password", max_subs=1)
        assert any("4" in w for w in out)  # a->4
        assert any("0" in w for w in out)  # o->0

    def test_max_subs_respected(self):
        out = leet_variants("ae", max_subs=1)
        # only single substitutions, not both at once
        assert "43" not in out

    def test_max_subs_two(self):
        out = leet_variants("ae", max_subs=2)
        assert "43" in out

    def test_empty(self):
        assert leet_variants("") == [""]

    def test_no_subs_available(self):
        assert leet_variants("xyz") == ["xyz"]

    def test_deterministic(self):
        assert leet_variants("dragon") == leet_variants("dragon")

    def test_no_duplicates(self):
        out = leet_variants("leet", max_subs=3)
        assert len(out) == len(set(out))


class TestDictionaryMatch:
    def test_finds_leet_word(self):
        words = ["password", "dragon", "monkey"]
        assert leet_dictionary_match("p4ssw0rd", words) == ["password"]

    def test_no_match(self):
        assert leet_dictionary_match("zzzz", ["password"]) == []

    def test_case_insensitive(self):
        assert leet_dictionary_match("P4SSWORD", ["password"]) == ["password"]

    def test_multiple_matches(self):
        # '1' -> i or l, so '1ist' could be 'list' or 'iist'
        words = ["list", "iist"]
        matches = leet_dictionary_match("1ist", words)
        assert "list" in matches

    def test_preserves_order(self):
        words = ["dragon", "password"]
        matches = leet_dictionary_match("dr4g0n", words)
        assert matches == ["dragon"]


class TestCrackCandidates:
    def test_includes_original_and_leet(self):
        out = list(leet_crack_candidates(["pass"], max_subs=1))
        assert "pass" in out
        assert any("4" in w for w in out)

    def test_dedupes(self):
        out = list(leet_crack_candidates(["pass", "pass"], max_subs=1))
        assert len(out) == len(set(out))

    def test_lazy(self):
        gen = leet_crack_candidates(["ae"], max_subs=2)
        first = next(gen)
        assert first == "ae"


class TestReverseLeet:
    def test_inverted(self):
        assert "4" in REVERSE_LEET["a"]
        assert "@" in REVERSE_LEET["a"]
        assert "0" in REVERSE_LEET["o"]
        assert "5" in REVERSE_LEET["s"]
        assert "$" in REVERSE_LEET["s"]

    def test_ambiguous_letters(self):
        # '1' maps to both i and l
        assert "1" in REVERSE_LEET["i"]
        assert "1" in REVERSE_LEET["l"]
