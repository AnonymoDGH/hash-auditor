"""Tests for hash_auditor.rules."""

from __future__ import annotations

import pytest

from hash_auditor.rules import (
    RULE_SETS,
    RuleError,
    apply_rule,
    apply_rules,
    mutate_stream,
    parse_rule_file,
    rule_stats,
)


class TestApplyRule:
    def test_identity(self):
        assert apply_rule("abc", ":") == "abc"
        assert apply_rule("", ":") == ""

    def test_lowercase(self):
        assert apply_rule("ABC", "l") == "abc"
        assert apply_rule("AbC123", "l") == "abc123"

    def test_uppercase(self):
        assert apply_rule("abc", "u") == "ABC"

    def test_capitalize(self):
        assert apply_rule("password", "c") == "Password"
        assert apply_rule("PASSWORD", "c") == "Password"
        assert apply_rule("", "c") == ""

    def test_capitalize_alias(self):
        assert apply_rule("hello", "C") == "Hello"

    def test_toggle_case(self):
        assert apply_rule("Password", "t") == "pASSWORD"
        assert apply_rule("abc123", "t") == "ABC123"

    def test_toggle_at_position(self):
        assert apply_rule("password", "T0") == "Password"
        assert apply_rule("password", "T7") == "passworD"
        assert apply_rule("abc", "T1") == "aBc"

    def test_toggle_at_position_clamps(self):
        # Out-of-range positions clamp instead of raising.
        assert apply_rule("abc", "T9") == "abC"
        assert apply_rule("", "T0") == ""

    def test_duplicate(self):
        assert apply_rule("abc", "d") == "abcabc"
        assert apply_rule("", "d") == ""

    def test_reverse(self):
        assert apply_rule("abc", "r") == "cba"
        assert apply_rule("abcd", "r") == "dcba"

    def test_append_char(self):
        assert apply_rule("abc", "$1") == "abc1"
        assert apply_rule("abc", "$!") == "abc!"

    def test_prepend_char(self):
        assert apply_rule("abc", "^1") == "1abc"
        assert apply_rule("abc", "^@") == "@abc"

    def test_truncate(self):
        assert apply_rule("password", "x4") == "pass"
        assert apply_rule("ab", "x9") == "ab"  # clamped

    def test_drop_prefix(self):
        assert apply_rule("password", "o1") == "assword"
        assert apply_rule("ab", "o9") == ""  # clamped

    def test_repeat_first_char(self):
        assert apply_rule("abc", "z2") == "aaabc"
        assert apply_rule("", "z2") == ""

    def test_repeat_last_char(self):
        assert apply_rule("abc", "y2") == "abccc"
        assert apply_rule("", "y2") == ""

    def test_chained_operations(self):
        assert apply_rule("abc", "u$1") == "ABC1"
        assert apply_rule("password", "c$1$2$3") == "Password123"
        assert apply_rule("abc", "dr") == "cbacba"
        assert apply_rule("abc", "rd") == "cbacba"
        assert apply_rule("abc", "^!$!") == "!abc!"

    def test_unknown_operation_raises(self):
        with pytest.raises(RuleError):
            apply_rule("abc", "Q")

    def test_missing_argument_raises(self):
        for bad in ("$", "^", "T", "x", "o", "z", "y"):
            with pytest.raises(RuleError):
                apply_rule("abc", bad)

    def test_non_digit_position_raises(self):
        with pytest.raises(RuleError):
            apply_rule("abc", "Ta")

    def test_whitespace_in_rule_ignored(self):
        assert apply_rule("abc", " u ") == "ABC"


class TestApplyRules:
    def test_applies_every_rule_in_order(self):
        out = apply_rules("abc", [":", "u", "$1"])
        assert out == ["abc", "ABC", "abc1"]

    def test_empty_rules(self):
        assert apply_rules("abc", []) == []

    def test_preserves_duplicates(self):
        assert apply_rules("abc", [":", ":"]) == ["abc", "abc"]


class TestParseRuleFile:
    def test_basic_file(self):
        text = ":\nl\n# comment\n\nu$1\n"
        assert parse_rule_file(text) == [":", "l", "u$1"]

    def test_inline_comments_stripped(self):
        text = "u$1  # append one\nc\n"
        assert parse_rule_file(text) == ["u$1", "c"]

    def test_windows_line_endings(self):
        text = ":\r\nl\r\n"
        assert parse_rule_file(text) == [":", "l"]

    def test_empty_file(self):
        assert parse_rule_file("") == []
        assert parse_rule_file("\n\n# only comments\n") == []

    def test_hash_inside_rule_kept(self):
        # '$#' appends a literal '#'; only ' #' starts a comment.
        assert parse_rule_file("$#\n") == ["$#"]


class TestRuleSets:
    def test_named_presets_exist(self):
        assert set(RULE_SETS) == {"basic", "append-years", "l33t", "full"}

    def test_full_is_union(self):
        assert RULE_SETS["full"] == (
            RULE_SETS["basic"] + RULE_SETS["append-years"] + RULE_SETS["l33t"]
        )

    def test_every_preset_rule_is_valid(self):
        for name, rules in RULE_SETS.items():
            for rule in rules:
                apply_rule("word", rule)  # must not raise

    def test_basic_covers_case_variants(self):
        out = set(apply_rules("word", RULE_SETS["basic"]))
        assert {"word", "WORD", "Word", "drow", "wordword"} <= out

    def test_append_years_produces_years(self):
        out = apply_rules("pass", RULE_SETS["append-years"])
        assert "pass1990" in out
        assert "pass2024" in out
        assert "pass123" in out

    def test_l33t_appends_symbols(self):
        out = apply_rules("pass", RULE_SETS["l33t"])
        assert "pass!" in out
        assert "!pass" in out


class TestMutateStream:
    def test_dedupes_across_words_and_rules(self):
        words = ["ab", "ba"]
        out = list(mutate_stream(words, [":", "r"]))
        # ab, ba from ':'; 'r' gives ba, ab again -- both already seen.
        assert out == ["ab", "ba"]

    def test_order_is_word_major(self):
        out = list(mutate_stream(["x"], [":", "u", "$1"]))
        assert out == ["x", "X", "x1"]

    def test_empty_inputs(self):
        assert list(mutate_stream([], [":"])) == []
        assert list(mutate_stream(["x"], [])) == []

    def test_lazy_generation(self):
        gen = mutate_stream(iter(["abc", "def"]), [":", "u"])
        assert next(gen) == "abc"
        assert next(gen) == "ABC"


class TestRuleStats:
    def test_basic_stats(self):
        stats = rule_stats(["abc", "ABC", "abc1", "abc1"])
        assert stats["count"] == 4
        assert stats["unique"] == 3
        assert stats["min_length"] == 3
        assert stats["max_length"] == 4
        assert stats["digit_suffix"] == 2
        assert stats["upper"] == 1
        assert stats["lower"] == 3  # 'abc', 'abc1', 'abc1' are all-lowercase
        assert stats["mixed"] == 0
        assert stats["empty"] == 0

    def test_empty_input(self):
        stats = rule_stats([])
        assert stats["count"] == 0
        assert stats["unique"] == 0
        assert stats["avg_length"] == 0.0
        assert stats["min_length"] == 0

    def test_empty_candidates_counted(self):
        stats = rule_stats(["", "a"])
        assert stats["empty"] == 1
        assert stats["min_length"] == 0

    def test_mixed_case(self):
        stats = rule_stats(["Password"])
        assert stats["mixed"] == 1

    def test_avg_length(self):
        stats = rule_stats(["aa", "aaaa"])
        assert stats["avg_length"] == 3.0
