"""Tests for hash_auditor.generator."""

from __future__ import annotations

import random

import pytest

from hash_auditor.generator import (
    KEYPAD_MAP,
    LEET_MAP,
    SYLLABLES,
    entropy_report,
    generate,
    generate_diceware,
    generate_leet,
    generate_pin,
    generate_syllable,
)


class TestDiceware:
    def test_deterministic_seed(self):
        assert generate_diceware(seed=1) == generate_diceware(seed=1)

    def test_different_seeds_differ(self):
        assert generate_diceware(seed=1) != generate_diceware(seed=2)

    def test_word_count(self):
        pw = generate_diceware(count=6, separator=" ", seed=3)
        assert len(pw.split(" ")) == 6

    def test_custom_separator(self):
        pw = generate_diceware(count=3, separator=".", seed=4)
        assert pw.count(".") == 2

    def test_custom_wordlist(self):
        pw = generate_diceware(count=4, words=["alpha", "beta"], seed=5)
        assert set(pw.split("-")) <= {"alpha", "beta"}

    def test_rng_object(self):
        rng = random.Random(99)
        assert generate_diceware(rng=rng) == generate_diceware(rng=random.Random(99))

    def test_invalid_count(self):
        with pytest.raises(ValueError):
            generate_diceware(count=0)

    def test_empty_wordlist(self):
        with pytest.raises(ValueError):
            generate_diceware(words=[])


class TestSyllable:
    def test_deterministic(self):
        assert generate_syllable(seed=7) == generate_syllable(seed=7)

    def test_capitalized(self):
        pw = generate_syllable(seed=8)
        assert pw[0].isupper()

    def test_no_capitalize(self):
        pw = generate_syllable(capitalize=False, tail=False, seed=9)
        assert pw == pw.lower()

    def test_tail(self):
        pw = generate_syllable(seed=10)
        assert pw[-1].isdigit()

    def test_no_tail(self):
        pw = generate_syllable(tail=False, seed=11)
        assert pw.isalpha()

    def test_invalid_count(self):
        with pytest.raises(ValueError):
            generate_syllable(count=0)

    def test_syllable_inventory(self):
        assert len(SYLLABLES) >= 50
        assert all(s for s in SYLLABLES)


class TestLeet:
    def test_deterministic(self):
        assert generate_leet("password", seed=1) == generate_leet("password", seed=1)

    def test_strength1_partial(self):
        pw = generate_leet("password", strength=1, seed=2)
        assert len(pw) == len("password")
        assert any(ch in LEET_MAP.values() for ch in pw)

    def test_strength2_full(self):
        pw = generate_leet("aeiob", strength=2, seed=3)
        assert pw == "43108"

    def test_strength3_tail(self):
        pw = generate_leet("dragon", strength=3, seed=4)
        assert pw[-1].isdigit()
        assert any(ch in "!?#$" for ch in pw[len("dragon"):])

    def test_empty_base(self):
        with pytest.raises(ValueError):
            generate_leet("")

    def test_bad_strength(self):
        with pytest.raises(ValueError):
            generate_leet("x", strength=9)

    def test_no_eligible_letters(self):
        assert generate_leet("12345", seed=5) == "12345"


class TestPin:
    def test_random_length(self):
        assert len(generate_pin(length=8, seed=1)) == 8

    def test_random_deterministic(self):
        assert generate_pin(seed=2) == generate_pin(seed=2)

    def test_random_digits_only(self):
        assert generate_pin(length=20, seed=3).isdigit()

    def test_strong_no_repeats_or_sequences(self):
        for seed in range(20):
            pin = generate_pin(length=6, mode="strong", seed=seed)
            assert len(pin) == 6
            for i in range(5):
                assert pin[i] != pin[i + 1]
            asc = all(ord(pin[i + 1]) - ord(pin[i]) == 1 for i in range(5))
            desc = all(ord(pin[i]) - ord(pin[i + 1]) == 1 for i in range(5))
            assert not asc and not desc

    def test_word_mode(self):
        assert generate_pin(mode="word", word="cat") == "228"
        assert generate_pin(mode="word", word="Zz") == "99"

    def test_word_mode_no_word(self):
        with pytest.raises(ValueError):
            generate_pin(mode="word")

    def test_word_mode_no_digits(self):
        with pytest.raises(ValueError):
            generate_pin(mode="word", word="!!!")

    def test_unknown_mode(self):
        with pytest.raises(ValueError):
            generate_pin(mode="bogus")

    def test_invalid_length(self):
        with pytest.raises(ValueError):
            generate_pin(length=0)

    def test_keypad_map_complete(self):
        for ch in "abcdefghijklmnopqrstuvwxyz":
            assert ch in KEYPAD_MAP


class TestDispatcher:
    def test_all_schemes(self):
        for scheme in ("diceware", "syllable", "pin"):
            assert generate(scheme, seed=1)
        assert generate("leet", seed=1, base="hunter")

    def test_seeded_dispatch_deterministic(self):
        assert generate("diceware", seed=5) == generate("diceware", seed=5)

    def test_unknown_scheme(self):
        with pytest.raises(ValueError):
            generate("bogus")


class TestEntropyReport:
    def test_diceware_bits(self):
        pw = generate_diceware(count=5, seed=1)
        rep = entropy_report(pw, "diceware")
        assert rep["bits"] > 45  # 5 words x ~9.7 bits
        assert rep["scheme"] == "diceware"
        assert "words" in rep["explanation"]

    def test_syllable_bits(self):
        rep = entropy_report(generate_syllable(seed=1), "syllable")
        assert rep["bits"] > 20

    def test_leet_bits(self):
        rep = entropy_report(generate_leet("password", seed=1), "leet")
        assert rep["bits"] > 0

    def test_pin_bits(self):
        rep = entropy_report("123456", "pin")
        assert abs(rep["bits"] - 6 * 3.3219) < 0.2

    def test_unknown_scheme(self):
        with pytest.raises(ValueError):
            entropy_report("x", "bogus")
