"""Tests for hash_auditor.breach."""

from __future__ import annotations

import pytest

from hash_auditor.breach import (
    BreachCorpus,
    build_corpus_blob,
    corpus_stats,
    cross_reference,
    default_corpus,
    exposure_score,
)


class TestCorpus:
    def test_add_and_frequency(self):
        c = BreachCorpus([("abc", 5), ("def", 3)])
        assert c.frequency("abc") == 5
        assert c.frequency("missing") == 0
        c.add("abc", 2)
        assert c.frequency("abc") == 7

    def test_add_invalid_count(self):
        with pytest.raises(ValueError):
            BreachCorpus([("x", 0)])

    def test_contains(self):
        c = BreachCorpus([("abc", 1)])
        assert c.contains("abc")
        assert not c.contains("zzz")

    def test_rank(self):
        c = BreachCorpus([("first", 100), ("second", 50), ("third", 1)])
        assert c.rank("first") == 1
        assert c.rank("second") == 2
        assert c.rank("third") == 3
        assert c.rank("missing") is None

    def test_rank_tie_breaks_by_insertion(self):
        c = BreachCorpus([("a", 10), ("b", 10)])
        assert c.rank("a") == 1
        assert c.rank("b") == 2

    def test_top(self):
        c = BreachCorpus([("low", 1), ("high", 99), ("mid", 50)])
        assert c.top(2) == [("high", 99), ("mid", 50)]

    def test_totals(self):
        c = BreachCorpus([("a", 3), ("b", 4)])
        assert c.total() == 7
        assert c.unique() == 2

    def test_passwords_iterator(self):
        c = BreachCorpus([("a", 1), ("b", 1)])
        assert list(c.passwords()) == ["a", "b"]

    def test_stats(self):
        c = BreachCorpus([("a", 1), ("b", 2)])
        s = c.stats()
        assert s["unique"] == 2
        assert s["total"] == 3
        assert s["top5"][0] == ("b", 2)


class TestEmbeddedCorpus:
    def test_blob_roundtrip(self):
        blob = build_corpus_blob()
        c = BreachCorpus.from_blob(blob)
        assert c.unique() > 300
        assert c.contains("password")
        assert c.frequency("password") > c.frequency("zombie")

    def test_default_corpus_cached(self):
        assert default_corpus() is default_corpus()

    def test_default_corpus_has_synthetic_extras(self):
        c = default_corpus()
        assert c.contains("hunter2")
        assert c.contains("porsche911")

    def test_zipf_ordering(self):
        c = default_corpus()
        top = c.top(5)
        counts = [count for _, count in top]
        assert counts == sorted(counts, reverse=True)
        assert top[0][0] == "password"


class TestExposureScore:
    def test_direct_hit_scores_high(self):
        rep = exposure_score("password")
        assert rep["found"]
        assert rep["direct_match"]
        assert rep["matched_variant"] == "password"
        assert rep["rank"] == 1
        assert rep["score"] >= 85

    def test_case_variant(self):
        rep = exposure_score("PASSWORD")
        assert rep["found"]
        assert not rep["direct_match"]
        assert rep["matched_variant"] == "password"
        assert rep["score"] < exposure_score("password")["score"]

    def test_digit_tail_variant(self):
        rep = exposure_score("dragon2023!")
        assert rep["found"]
        assert rep["matched_variant"] in ("dragon2023", "dragon")

    def test_capitalized_variant(self):
        rep = exposure_score("Monkey")
        assert rep["found"]
        assert rep["matched_variant"] == "monkey"

    def test_absent_scores_zero(self):
        rep = exposure_score("Xk9$mQ2vLp7wZr")
        assert not rep["found"]
        assert rep["score"] == 0
        assert rep["rank"] is None

    def test_empty_password(self):
        rep = exposure_score("")
        assert not rep["found"]
        assert rep["score"] == 0

    def test_score_bounds(self):
        c = default_corpus()
        for pw in ("password", "123456", "zombie", "Xk9$mQ2vLp7wZr"):
            assert 0 <= exposure_score(pw, c)["score"] <= 100

    def test_rare_scores_lower_than_common(self):
        common = exposure_score("password")["score"]
        rare = exposure_score("zombie")["score"]
        assert common > rare

    def test_custom_corpus(self):
        c = BreachCorpus([("only", 10)])
        assert exposure_score("only", c)["found"]
        assert not exposure_score("password", c)["found"]


class TestCrossReference:
    def test_batch(self):
        report = cross_reference(["password", "Xk9$mQ2vLp7wZr", "qwerty"])
        assert report["total"] == 3
        assert report["exposed"] == 2
        assert abs(report["exposed_fraction"] - 2 / 3) < 1e-3
        # rows sorted worst-first
        scores = [r["score"] for r in report["rows"]]
        assert scores == sorted(scores, reverse=True)
        assert report["rows"][0]["password"] == "password"

    def test_empty(self):
        report = cross_reference([])
        assert report["total"] == 0
        assert report["exposed_fraction"] == 0.0
        assert report["rows"] == []


class TestCorpusStats:
    def test_stats_shape(self):
        s = corpus_stats(top_n=5)
        assert s["unique"] > 300
        assert len(s["top"]) == 5
        assert s["average_length"] > 4
        hist = s["length_histogram"]
        assert sum(hist.values()) == s["unique"]
        assert list(hist) == sorted(hist)

    def test_custom_corpus_stats(self):
        c = BreachCorpus([("ab", 1), ("abcd", 2)])
        s = corpus_stats(c)
        assert s["length_histogram"] == {2: 1, 4: 1}
        assert s["average_length"] == 3.0
