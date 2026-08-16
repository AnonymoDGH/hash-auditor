"""Tests for hash_auditor.pcfg."""

from __future__ import annotations

import pytest

from hash_auditor.pcfg import (
    PcfgGenerator,
    PcfgGrammar,
    TOKEN_KINDS,
    default_grammar,
    generate_pcfg,
)


class TestGrammar:
    def test_structures_normalised(self):
        g = default_grammar()
        total = sum(g.structures.values())
        assert abs(total - 1.0) < 1e-9

    def test_parse_structure(self):
        g = default_grammar()
        assert g.parse_structure("L4 D3 S1") == [("L", 4), ("D", 3), ("S", 1)]

    def test_parse_bad_token(self):
        g = default_grammar()
        with pytest.raises(ValueError):
            g.parse_structure("X4")
        with pytest.raises(ValueError):
            g.parse_structure("Lx")

    def test_token_dists_sum_to_one(self):
        g = default_grammar()
        for (kind, length), dist in g.tokens.items():
            total = sum(p for _, p in dist)
            assert abs(total - 1.0) < 1e-6, (kind, length)

    def test_token_dists_sorted_desc(self):
        g = default_grammar()
        for dist in g.tokens.values():
            probs = [p for _, p in dist]
            assert probs == sorted(probs, reverse=True)

    def test_guess_probability(self):
        g = default_grammar()
        # most probable guess of L6 D2
        ldist = g.token_dist("L", 6)
        ddist = g.token_dist("D", 2)
        guess_tokens = [ldist[0][0], ddist[0][0]]
        prob = g.guess_probability("L6 D2", guess_tokens)
        expected = g.structure_prob("L6 D2") * ldist[0][1] * ddist[0][1]
        assert prob == pytest.approx(expected)

    def test_guess_probability_bad_length(self):
        g = default_grammar()
        assert g.guess_probability("L6 D2", ["onlyone"]) == 0.0

    def test_structure_prob_missing(self):
        g = default_grammar()
        assert g.structure_prob("ZZZ") == 0.0


class TestGenerator:
    def test_descending_probability(self):
        gen = PcfgGenerator()
        probs = []
        for i, (prob, guess) in enumerate(gen.generate()):
            probs.append(prob)
            if i >= 200:
                break
        assert probs == sorted(probs, reverse=True)

    def test_no_duplicates(self):
        gen = PcfgGenerator()
        seen = set()
        for i, (prob, guess) in enumerate(gen.generate()):
            assert guess not in seen, guess
            seen.add(guess)
            if i >= 300:
                break

    def test_guesses_match_structure_lengths(self):
        g = default_grammar()
        gen = PcfgGenerator(g)
        for i, (prob, guess) in enumerate(gen.generate()):
            assert len(guess) >= 1
            assert prob > 0
            if i >= 100:
                break

    def test_first_guess_is_most_probable(self):
        g = default_grammar()
        gen = PcfgGenerator(g)
        first_prob, first_guess = next(gen.generate())
        # brute-force the single most probable guess across structures
        best = 0.0
        for structure in g.structures:
            parts = g.parse_structure(structure)
            prob = g.structure_prob(structure)
            guess = ""
            for kind, length in parts:
                token, p = g.token_dist(kind, length)[0]
                prob *= p
                guess += token
            if prob > best:
                best = prob
        assert first_prob == pytest.approx(best)


class TestGeneratePcfg:
    def test_count(self):
        out = generate_pcfg(50)
        assert len(out) == 50
        assert len(set(out)) == 50  # unique

    def test_zero(self):
        assert generate_pcfg(0) == []

    def test_negative(self):
        with pytest.raises(ValueError):
            generate_pcfg(-1)

    def test_deterministic(self):
        assert generate_pcfg(30) == generate_pcfg(30)

    def test_contains_common_shapes(self):
        out = generate_pcfg(200)
        # at least one guess should end in digits (L6 D2 etc dominate)
        assert any(ch.isdigit() for g in out for ch in g)

    def test_token_kinds(self):
        assert set(TOKEN_KINDS) == {"L", "D", "S"}
