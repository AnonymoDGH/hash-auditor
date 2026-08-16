"""Tests for hash_auditor.similarity."""

from __future__ import annotations

import pytest

from hash_auditor.similarity import (
    MUTATION_LABELS,
    cluster_passwords,
    detect_mutation,
    edit_script,
    levenshtein,
    similarity_ratio,
)


class TestLevenshtein:
    def test_identical(self):
        assert levenshtein("abc", "abc") == 0

    def test_empty(self):
        assert levenshtein("", "") == 0
        assert levenshtein("abc", "") == 3
        assert levenshtein("", "xyz") == 3

    def test_substitution(self):
        assert levenshtein("kitten", "sitten") == 1

    def test_classic(self):
        assert levenshtein("kitten", "sitting") == 3

    def test_insertion(self):
        assert levenshtein("abc", "abcd") == 1

    def test_symmetric(self):
        assert levenshtein("abc", "xyzw") == levenshtein("xyzw", "abc")


class TestEditScript:
    def test_apply_script(self):
        # Replaying the script must transform a into b.
        for a, b in [("kitten", "sitting"), ("abc", "abc"), ("", "ab"),
                     ("password", "p4ssw0rd")]:
            script = edit_script(a, b)
            non_keep = [op for op, _, _ in script if op != "keep"]
            assert len(non_keep) == levenshtein(a, b), (a, b)

    def test_keep_only(self):
        script = edit_script("same", "same")
        assert all(op == "keep" for op, _, _ in script)

    def test_ops_valid(self):
        script = edit_script("abc", "axc")
        ops = {op for op, _, _ in script}
        assert ops <= {"keep", "substitute", "insert", "delete"}
        assert "substitute" in ops


class TestSimilarityRatio:
    def test_identical(self):
        assert similarity_ratio("abc", "abc") == 1.0

    def test_both_empty(self):
        assert similarity_ratio("", "") == 1.0

    def test_disjoint(self):
        assert similarity_ratio("abc", "xyz") == 0.0

    def test_range(self):
        assert 0.0 <= similarity_ratio("password", "p4ssw0rd") <= 1.0

    def test_symmetric(self):
        assert similarity_ratio("abc", "abd") == similarity_ratio("abd", "abc")


class TestDetectMutation:
    def test_identical(self):
        assert detect_mutation("abc", "abc")["label"] == "identical"

    def test_case_flip(self):
        assert detect_mutation("Password", "pASSWORD")["label"] == "case_flip"

    def test_digit_increment(self):
        rep = detect_mutation("hunter2", "hunter3")
        assert rep["label"] == "digit_increment"
        assert "2 -> 3" in rep["detail"]

    def test_digit_increment_multi(self):
        assert detect_mutation("pass12", "pass13")["label"] == "digit_increment"

    def test_suffix_swap(self):
        rep = detect_mutation("summer2023", "summer2025")
        assert rep["label"] == "suffix_swap"
        assert "2023 -> 2025" in rep["detail"]

    def test_reversed(self):
        assert detect_mutation("password", "drowssap")["label"] == "reversed"

    def test_appended(self):
        assert detect_mutation("password", "password123")["label"] == "appended"

    def test_prepended(self):
        assert detect_mutation("dragon", "xxdragon")["label"] == "prepended"

    def test_leet_flip(self):
        rep = detect_mutation("password", "p4ssw0rd")
        assert rep["label"] == "leet_flip"

    def test_substitution(self):
        rep = detect_mutation("password", "passwurd")
        assert rep["label"] == "substitution"

    def test_unrelated(self):
        rep = detect_mutation("abc", "completely-different")
        assert rep["label"] == "unrelated"

    def test_result_shape(self):
        rep = detect_mutation("a", "b")
        assert set(rep) == {"label", "similarity", "distance", "detail"}
        assert rep["label"] in MUTATION_LABELS

    def test_labels_complete(self):
        assert len(MUTATION_LABELS) == 11


class TestCluster:
    def test_basic_clusters(self):
        words = ["password", "password1", "Password", "dragon", "dragon99"]
        clusters = cluster_passwords(words, threshold=0.7)
        # password family together, dragon family together
        flat = [sorted(c) for c in clusters]
        assert sorted(["Password", "password", "password1"]) in flat
        assert sorted(["dragon", "dragon99"]) in flat

    def test_singletons(self):
        clusters = cluster_passwords(["abc", "xyz123456"], threshold=0.9)
        assert len(clusters) == 2

    def test_empty(self):
        assert cluster_passwords([]) == []

    def test_transitive(self):
        # a~b and b~c => one cluster even if a!~c directly
        clusters = cluster_passwords(["abcd", "abcde", "abcdef"],
                                     threshold=0.7)
        assert len(clusters) == 1

    def test_order_preserved(self):
        clusters = cluster_passwords(["zz", "aa", "zz1"], threshold=0.6)
        assert clusters[0][0] == "zz"
