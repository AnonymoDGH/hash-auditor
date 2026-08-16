"""Tests for hash_auditor.combinator."""

from __future__ import annotations

import hashlib

import pytest

from hash_auditor.combinator import (
    attack_stats,
    combinator,
    hybrid_word_mask,
    rule_chain,
    separator_join,
    toggle_attack,
)


class TestCombinator:
    def test_basic(self):
        out = list(combinator(["a", "b"], ["1", "2"]))
        assert out == ["a1", "a2", "b1", "b2"]

    def test_separator(self):
        out = list(combinator(["sun"], ["shine"], separator="-"))
        assert out == ["sun-shine"]

    def test_dedupe(self):
        out = list(combinator(["a", "a"], ["1"]))
        assert out == ["a1"]

    def test_no_dedupe(self):
        out = list(combinator(["a", "a"], ["1"], dedupe=False))
        assert out == ["a1", "a1"]

    def test_lazy_a(self):
        # words_a can be a generator
        out = list(combinator((w for w in ["x"]), ["y"]))
        assert out == ["xy"]

    def test_cracks_combined_password(self):
        target = hashlib.md5(b"sunshine2023").hexdigest()
        found = None
        for cand in combinator(["sunshine"], ["2023", "2024"]):
            if hashlib.md5(cand.encode()).hexdigest() == target:
                found = cand
                break
        assert found == "sunshine2023"


class TestHybridWordMask:
    def test_append(self):
        out = list(hybrid_word_mask(["pass"], "?d?d"))
        assert out[0] == "pass00"
        assert out[-1] == "pass99"
        assert len(out) == 100

    def test_prepend(self):
        out = list(hybrid_word_mask(["word"], "?d", position="prepend"))
        assert out == [f"{d}word" for d in "0123456789"]

    def test_bad_position(self):
        with pytest.raises(ValueError):
            list(hybrid_word_mask(["w"], "?d", position="sideways"))

    def test_dedupe(self):
        out = list(hybrid_word_mask(["a", "a"], "?d"))
        assert len(out) == 10


class TestToggleAttack:
    def test_single_position(self):
        out = list(toggle_attack(["abc"], [0]))
        assert out == ["abc", "Abc"]

    def test_two_positions(self):
        out = list(toggle_attack(["ab"], [0, 1]))
        assert out == ["ab", "Ab", "aB", "AB"]

    def test_out_of_range_ignored(self):
        out = list(toggle_attack(["a"], [5]))
        assert out == ["a", "a"]

    def test_non_letter_noop(self):
        out = list(toggle_attack(["1a"], [0]))
        assert out == ["1a", "1a"]

    def test_deterministic(self):
        assert list(toggle_attack(["abc"], [1, 2])) == \
            list(toggle_attack(["abc"], [2, 1]))


class TestSeparatorJoin:
    def test_basic(self):
        out = list(separator_join(["red", "blue"], separators=["-"], count=2))
        assert "red-red" in out
        assert "red-blue" in out
        assert "blue-red" in out
        assert "blue-blue" in out
        assert len(out) == 4

    def test_multiple_separators(self):
        out = list(separator_join(["a"], separators=["-", "_"], count=2))
        assert out == ["a-a", "a_a"]

    def test_dedupe(self):
        out = list(separator_join(["a", "a"], separators=["-"], count=1))
        assert out == ["a"]

    def test_invalid_count(self):
        with pytest.raises(ValueError):
            list(separator_join(["a"], count=0))


class TestRuleChain:
    def test_applies_rules(self):
        out = list(rule_chain(["abc"], [":", "u"]))
        assert out == ["abc", "ABC"]

    def test_dedupes(self):
        out = list(rule_chain(["abc", "abc"], [":"]))
        assert out == ["abc"]


class TestAttackStats:
    def test_basic(self):
        stats = attack_stats(["a", "bb", "ccc", "a"])
        assert stats["count"] == 4
        assert stats["unique"] == 3
        assert stats["min_length"] == 1
        assert stats["max_length"] == 3
        assert stats["avg_length"] == 1.75

    def test_empty(self):
        stats = attack_stats([])
        assert stats["count"] == 0
        assert stats["min_length"] == 0
        assert stats["avg_length"] == 0.0
