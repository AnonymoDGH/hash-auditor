"""Tests for hash_auditor.stats."""

from __future__ import annotations

import pytest

from hash_auditor.stats import (
    capitalization_rate,
    class_distribution,
    corpus_report,
    digit_suffix_rate,
    length_histogram,
    markov_transitions,
    top_repeats,
    zipf_fit,
)

SAMPLE = [
    "password", "password", "password", "123456", "123456",
    "qwerty", "Password1", "Dragon2023", "abc", "abc", "Xk9$mQ",
]


class TestLengthHistogram:
    def test_basic(self):
        hist = length_histogram(["a", "bb", "cc", "ddd"])
        assert hist == {1: 1, 2: 2, 3: 1}

    def test_empty(self):
        assert length_histogram([]) == {}

    def test_skips_empty_strings(self):
        assert length_histogram(["", "ab"]) == {2: 1}


class TestClassDistribution:
    def test_labels(self):
        dist = class_distribution(["abc", "ABC", "abc1", "a!"])
        assert dist["lower"] == 1
        assert dist["upper"] == 1
        assert dist["lower+digit"] == 1
        assert dist["lower+symbol"] == 1

    def test_sorted_by_count(self):
        dist = class_distribution(["a", "b", "A"])
        keys = list(dist)
        assert keys[0] == "lower"

    def test_empty_word(self):
        # empty strings are filtered out upstream
        assert class_distribution([]) == {}


class TestRates:
    def test_digit_suffix(self):
        assert digit_suffix_rate(["abc1", "abc", "x9"]) ==             pytest.approx(2 / 3)

    def test_digit_suffix_empty(self):
        assert digit_suffix_rate([]) == 0.0

    def test_capitalization(self):
        assert capitalization_rate(["Abc", "abc", "Xyz"]) == \
            pytest.approx(2 / 3)

    def test_capitalization_empty(self):
        assert capitalization_rate([]) == 0.0


class TestTopRepeats:
    def test_basic(self):
        reps = top_repeats(SAMPLE)
        assert reps[0] == ("password", 3)
        assert ("123456", 2) in reps
        assert all(c > 1 for _, c in reps)

    def test_no_repeats(self):
        assert top_repeats(["a", "b", "c"]) == []

    def test_limit(self):
        reps = top_repeats(["a", "a", "b", "b", "c", "c"], n=2)
        assert len(reps) == 2


class TestZipfFit:
    def test_natural_corpus(self):
        # Build a synthetic Zipf corpus: rank r appears ~100/r times.
        words = []
        for rank in range(1, 30):
            words.extend([f"w{rank}"] * max(1, 100 // rank))
        fit = zipf_fit(words)
        assert fit["exponent"] is not None
        assert 0.7 < fit["exponent"] < 1.3
        assert fit["r_squared"] > 0.9
        assert fit["distinct"] == 29

    def test_uniform_corpus(self):
        fit = zipf_fit([f"w{i}" for i in range(20)])
        assert fit["exponent"] == pytest.approx(0.0, abs=1e-6)

    def test_too_small(self):
        fit = zipf_fit(["only", "only"])
        assert fit["exponent"] is None
        assert fit["distinct"] == 1

    def test_empty(self):
        fit = zipf_fit([])
        assert fit["exponent"] is None
        assert fit["distinct"] == 0


class TestMarkov:
    def test_normalized_rows(self):
        table = markov_transitions(["abab", "ac"])
        assert table["a"]["b"] == pytest.approx(2 / 3)
        assert table["a"]["c"] == pytest.approx(1 / 3)
        assert sum(table["a"].values()) == pytest.approx(1.0)

    def test_raw_counts(self):
        table = markov_transitions(["aaa"], normalize=False)
        assert table["a"]["a"] == 2

    def test_single_char_words(self):
        assert markov_transitions(["a", "b"]) == {}


class TestCorpusReport:
    def test_shape(self):
        rep = corpus_report(SAMPLE)
        assert rep["total"] == 11
        assert rep["unique"] == 7
        assert rep["duplicate_rate"] == pytest.approx(1 - 7 / 11, abs=1e-3)
        assert rep["min_length"] == 3
        assert rep["max_length"] == 10
        assert rep["average_length"] > 0
        assert rep["digit_suffix_rate"] > 0
        assert rep["capitalization_rate"] > 0
        assert rep["top_repeats"][0] == ("password", 3)
        assert rep["zipf"]["distinct"] == 7

    def test_empty(self):
        rep = corpus_report([])
        assert rep["total"] == 0
        assert rep["unique"] == 0
        assert rep["min_length"] == 0
        assert rep["average_length"] == 0.0
        assert rep["duplicate_rate"] == 0.0
