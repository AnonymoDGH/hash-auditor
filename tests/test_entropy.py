"""Tests for hash_auditor.entropy."""

from __future__ import annotations

import math
import random
import string

import pytest

from hash_auditor.entropy import (
    char_distribution,
    chi_squared,
    effective_bits,
    markov_entropy,
    randomness_report,
    shannon_entropy,
)


class TestCharDistribution:
    def test_basic(self):
        dist = char_distribution("aab")
        assert dist["a"] == pytest.approx(2 / 3)
        assert dist["b"] == pytest.approx(1 / 3)

    def test_empty(self):
        assert char_distribution("") == {}

    def test_sums_to_one(self):
        dist = char_distribution("abracadabra")
        assert sum(dist.values()) == pytest.approx(1.0, abs=1e-4)


class TestShannon:
    def test_empty(self):
        assert shannon_entropy("") == 0.0

    def test_repeated(self):
        assert shannon_entropy("aaaa") == 0.0

    def test_uniform(self):
        assert shannon_entropy("abcd") == pytest.approx(2.0)

    def test_bounds(self):
        text = "abracadabra"
        assert 0 < shannon_entropy(text) <= math.log2(len(set(text)))


class TestChiSquared:
    def test_empty(self):
        assert chi_squared("") == 0.0

    def test_uniform_low(self):
        assert chi_squared("aabbccdd") == pytest.approx(0.0)

    def test_skewed_high(self):
        assert chi_squared("aaaaaaab") > chi_squared("aaaabbbb")

    def test_custom_expected(self):
        # expectation matching observation gives 0
        assert chi_squared("aaab", {"a": 0.75, "b": 0.25}) == \
            pytest.approx(0.0)

    def test_missing_expected_char(self):
        # observed char absent from expectation adds its count
        assert chi_squared("aaax", {"a": 1.0}) >= 1


class TestMarkov:
    def test_order_zero_equals_shannon(self):
        assert markov_entropy("abracadabra", order=0) == \
            shannon_entropy("abracadabra")

    def test_negative_order(self):
        with pytest.raises(ValueError):
            markov_entropy("abc", order=-1)

    def test_short_text_falls_back(self):
        assert markov_entropy("ab", order=5) == shannon_entropy("ab")

    def test_structure_lowers_entropy(self):
        # 'ababab...' is fully predictable at order 2
        structured = "ab" * 30
        assert markov_entropy(structured, order=2) < \
            shannon_entropy(structured)

    def test_random_text(self):
        rng = random.Random(42)
        text = "".join(rng.choice(string.ascii_lowercase) for _ in range(500))
        h = markov_entropy(text, order=1)
        assert 3.5 < h <= math.log2(26)


class TestEffectiveBits:
    def test_empty(self):
        assert effective_bits("") == 0.0

    def test_single_char(self):
        assert effective_bits("aaaaaaaa") == 0.0

    def test_well_mixed_keeps_most(self):
        pw = "Xk9$mQ2vLp7w"
        bits = effective_bits(pw)
        pool = len(pw) * math.log2(26 + 26 + 10 + 33)
        assert bits > 0.7 * pool

    def test_structured_penalised(self):
        assert effective_bits("ababababab") < effective_bits("Xk9$mQ2vLp")


class TestRandomnessReport:
    def test_empty(self):
        rep = randomness_report("")
        assert rep["score"] == 0
        assert rep["verdict"] == "pattern"

    def test_repeated_is_pattern(self):
        rep = randomness_report("aaaaaaaaaa")
        assert rep["verdict"] == "pattern"
        assert rep["score"] == 0

    def test_random_scores_high(self):
        rng = random.Random(7)
        text = "".join(rng.choice(string.ascii_letters + string.digits +
                                  "!@#$%^&*") for _ in range(40))
        rep = randomness_report(text)
        assert rep["score"] >= 60
        assert rep["verdict"] in ("random", "mixed")

    def test_word_is_structured(self):
        rep = randomness_report("passwordpassword")
        assert rep["score"] < 75

    def test_report_shape(self):
        rep = randomness_report("hunter2")
        assert set(rep) == {"score", "verdict", "shannon_bits",
                            "chi_squared", "unique_ratio", "effective_bits"}
        assert 0 <= rep["score"] <= 100

    def test_deterministic(self):
        assert randomness_report("abc123") == randomness_report("abc123")
