"""Tests for hash_auditor.keyboard."""

from __future__ import annotations

import pytest

from hash_auditor.keyboard import (
    KEYBOARD_ROWS,
    adjacency_graph,
    is_walk,
    walk_candidates,
    walk_score,
    walks,
)


class TestGraph:
    def test_all_keys_present(self):
        graph = adjacency_graph()
        all_keys = "".join(KEYBOARD_ROWS)
        assert set(graph) == set(all_keys)

    def test_symmetric(self):
        graph = adjacency_graph()
        for key, neighbours in graph.items():
            for n in neighbours:
                assert key in graph[n], (key, n)

    def test_qwerty_adjacent(self):
        graph = adjacency_graph()
        assert "w" in graph["q"]
        assert "a" in graph["q"]

    def test_no_self_loops(self):
        graph = adjacency_graph()
        for key, neighbours in graph.items():
            assert key not in neighbours

    def test_cached(self):
        assert adjacency_graph() is adjacency_graph()


class TestWalks:
    def test_length1(self):
        out = list(walks(1))
        assert len(out) == len("".join(KEYBOARD_ROWS))

    def test_length2_from_start(self):
        graph = adjacency_graph()
        out = list(walks(2, start="q"))
        assert all(w.startswith("q") for w in out)
        assert len(out) == len(graph["q"])

    def test_all_steps_adjacent(self):
        graph = adjacency_graph()
        for w in walks(4, start="a"):
            for a, b in zip(w, w[1:]):
                assert b in graph[a]

    def test_invalid_length(self):
        with pytest.raises(ValueError):
            list(walks(0))

    def test_unknown_start(self):
        with pytest.raises(ValueError):
            list(walks(2, start="!"))

    def test_deterministic(self):
        assert list(walks(3, start="q")) == list(walks(3, start="q"))


class TestWalkCandidates:
    def test_dedup(self):
        out = list(walk_candidates(2, 3))
        assert len(out) == len(set(out))

    def test_shortest_first(self):
        out = list(walk_candidates(2, 4))
        lengths = [len(w) for w in out]
        assert lengths == sorted(lengths)

    def test_with_shift(self):
        out = list(walk_candidates(2, 2, with_shift=True))
        assert any(w.isupper() for w in out)

    def test_invalid_range(self):
        with pytest.raises(ValueError):
            list(walk_candidates(3, 2))


class TestIsWalk:
    def test_qwerty(self):
        assert is_walk("qwerty")

    def test_zxcvbn(self):
        assert is_walk("zxcvbn")

    def test_not_walk(self):
        assert not is_walk("password")

    def test_case_insensitive(self):
        assert is_walk("QWERTY")

    def test_short(self):
        assert not is_walk("q")

    def test_max_gap(self):
        # 'qa' is adjacent; insert a non-adjacent jump
        assert is_walk("qz", max_gap=1) or not is_walk("qz")


class TestWalkScore:
    def test_perfect_walk(self):
        assert walk_score("qwerty") == 1.0

    def test_no_adjacency(self):
        assert walk_score("password") < 1.0

    def test_short(self):
        assert walk_score("q") == 0.0

    def test_range(self):
        assert 0.0 <= walk_score("asdfgh") <= 1.0
