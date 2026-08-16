"""Tests for hash_auditor.wordlist_tools."""

from __future__ import annotations

import pytest

from hash_auditor.wordlist_tools import (
    TRANSFORMS,
    clean_lines,
    dedupe,
    expand_pipeline,
    filter_words,
    merge_wordlists,
    sample_evenly,
    split_by_length,
)


class TestCleanLines:
    def test_basic(self):
        text = "one\n\ntwo\n# comment\nthree\n"
        assert clean_lines(text) == ["one", "two", "three"]

    def test_strips_whitespace(self):
        assert clean_lines("  padded  \n") == ["padded"]

    def test_crlf(self):
        assert clean_lines("a\r\nb\r\nc") == ["a", "b", "c"]

    def test_bom(self):
        assert clean_lines("\ufefffirst\n") == ["first"]

    def test_empty(self):
        assert clean_lines("") == []


class TestDedupe:
    def test_preserves_order(self):
        assert dedupe(["b", "a", "b", "c", "a"]) == ["b", "a", "c"]

    def test_case_sensitive(self):
        assert dedupe(["Abc", "abc"]) == ["Abc", "abc"]

    def test_case_insensitive(self):
        assert dedupe(["Abc", "abc", "ABC"], case_sensitive=False) == ["Abc"]

    def test_empty(self):
        assert dedupe([]) == []


class TestFilterWords:
    WORDS = ["ab", "abc123", "longword", "x!", "123", "ABC"]

    def test_min_len(self):
        assert list(filter_words(self.WORDS, min_len=4)) == \
            ["abc123", "longword"]

    def test_max_len(self):
        assert list(filter_words(self.WORDS, max_len=3)) == \
            ["ab", "x!", "123", "ABC"]

    def test_require_digit(self):
        assert list(filter_words(self.WORDS, require_digit=True)) == \
            ["abc123", "123"]

    def test_require_symbol(self):
        assert list(filter_words(self.WORDS, require_symbol=True)) == ["x!"]

    def test_require_alpha(self):
        assert "123" not in list(filter_words(self.WORDS, require_alpha=True))

    def test_charset(self):
        assert list(filter_words(self.WORDS, charset="abc")) == ["ab"]

    def test_combined(self):
        out = list(filter_words(self.WORDS, min_len=4, require_digit=True))
        assert out == ["abc123"]


class TestSplitByLength:
    def test_basic(self):
        groups = split_by_length(["a", "bb", "cc", "ddd"])
        assert list(groups) == [1, 2, 3]
        assert groups[2] == ["bb", "cc"]

    def test_empty(self):
        assert split_by_length([]) == {}


class TestMergeWordlists:
    def test_interleave(self):
        out = merge_wordlists([["a1", "a2"], ["b1", "b2"]], interleave=True)
        assert out == ["a1", "b1", "a2", "b2"]

    def test_concatenate(self):
        out = merge_wordlists([["a"], ["b"]], interleave=False)
        assert out == ["a", "b"]

    def test_dedupe(self):
        out = merge_wordlists([["x", "y"], ["y", "z"]])
        assert out == ["x", "y", "z"]

    def test_uneven(self):
        out = merge_wordlists([["a", "b", "c"], ["x"]], interleave=True)
        assert out == ["a", "x", "b", "c"]

    def test_empty(self):
        assert merge_wordlists([]) == []


class TestSampleEvenly:
    def test_spread(self):
        out = sample_evenly(list(range(100)), 5)
        assert len(out) == 5
        assert out[0] == 0
        assert out[-1] >= 75  # near the end

    def test_n_larger_than_list(self):
        assert sample_evenly([1, 2], 10) == [1, 2]

    def test_zero(self):
        assert sample_evenly([1, 2, 3], 0) == []

    def test_deterministic(self):
        assert sample_evenly(list(range(50)), 7) == \
            sample_evenly(list(range(50)), 7)


class TestExpandPipeline:
    def test_identity(self):
        assert expand_pipeline(["a", "b"], ["identity"]) == ["a", "b"]

    def test_upper(self):
        assert expand_pipeline(["abc"], ["upper"]) == ["ABC"]

    def test_chained(self):
        out = expand_pipeline(["abc"], ["upper", "reverse"])
        assert out == ["CBA"]

    def test_digit_suffix(self):
        out = expand_pipeline(["x"], ["digit-suffix"])
        assert out[0] == "x"
        assert "x0" in out and "x9" in out
        assert len(out) == 11

    def test_leet(self):
        out = expand_pipeline(["aeiost"], ["leet"])
        assert out == ["431057"]

    def test_dedupe(self):
        out = expand_pipeline(["a", "A"], ["lower"])
        assert out == ["a"]

    def test_unknown_stage(self):
        with pytest.raises(ValueError):
            expand_pipeline(["a"], ["bogus"])

    def test_registry_complete(self):
        assert set(TRANSFORMS) == {
            "identity", "lower", "upper", "capitalize", "reverse",
            "digit-suffix", "year-suffix", "leet"}

    def test_year_suffix(self):
        out = expand_pipeline(["x"], ["year-suffix"])
        assert "x1970" in out and "x2029" in out
