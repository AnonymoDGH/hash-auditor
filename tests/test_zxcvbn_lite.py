"""Tests for hash_auditor.zxcvbn_lite."""

from __future__ import annotations

import math

import pytest

from hash_auditor.zxcvbn_lite import (
    ATTACK_SPEEDS,
    L33T_MAP,
    QWERTY_GRAPH,
    date_matches,
    dictionary_matches,
    estimate,
    l33t_matches,
    repeat_matches,
    sequence_matches,
    spatial_matches,
)


class TestConstants:
    def test_l33t_map_covers_required_chars(self):
        assert L33T_MAP["4"] == ("a",)
        assert L33T_MAP["@"] == ("a",)
        assert L33T_MAP["3"] == ("e",)
        assert set(L33T_MAP["1"]) == {"i", "l"}
        assert L33T_MAP["0"] == ("o",)
        assert L33T_MAP["5"] == ("s",)
        assert L33T_MAP["$"] == ("s",)
        assert L33T_MAP["7"] == ("t",)

    def test_attack_speeds(self):
        assert set(ATTACK_SPEEDS) == {
            "online_throttling_100_per_hour",
            "online_no_throttling_10_per_second",
            "offline_slow_hashing_10k_per_second",
            "offline_fast_hashing_10b_per_second",
        }
        assert ATTACK_SPEEDS["offline_fast_hashing_10b_per_second"] == 1e10

    def test_qwerty_graph_sanity(self):
        assert "q" in QWERTY_GRAPH
        assert "w" in QWERTY_GRAPH["q"]
        assert "a" in QWERTY_GRAPH["q"]
        assert "m" not in QWERTY_GRAPH["q"]
        # Adjacency is symmetric.
        for key, neighbours in QWERTY_GRAPH.items():
            for nb in neighbours:
                assert key in QWERTY_GRAPH[nb]


class TestDictionaryMatches:
    def test_finds_embedded_password(self):
        ms = dictionary_matches("password")
        words = {m["matched_word"] for m in ms}
        assert "password" in words

    def test_rank_penalty(self):
        # 'password' ranks #1 in the passwords dict -> guesses == 1.
        ms = [m for m in dictionary_matches("password")
              if m["matched_word"] == "password" and m["dictionary"] == "passwords"]
        assert ms and ms[0]["guesses"] == 1

    def test_case_insensitive_with_uppercase_penalty(self):
        ms = [m for m in dictionary_matches("Password")
              if m["matched_word"] == "password" and m["dictionary"] == "passwords"]
        assert ms and ms[0]["guesses"] == 2  # leading capital doubles it

    def test_substring_match(self):
        ms = dictionary_matches("xxpasswordxx")
        assert any(m["matched_word"] == "password" for m in ms)

    def test_short_tokens_ignored(self):
        # Single characters never match (minimum token length is 2).
        assert dictionary_matches("a") == []


class TestL33tMatches:
    def test_reverses_common_substitutions(self):
        ms = l33t_matches("p@ssw0rd")
        assert any(m["matched_word"] == "password" for m in ms)

    def test_guesses_penalised_by_substitutions(self):
        ms = [m for m in l33t_matches("p@ssw0rd")
              if m["matched_word"] == "password"]
        assert ms
        plain = [m for m in dictionary_matches("password")
                 if m["matched_word"] == "password"
                 and m["dictionary"] == "passwords"][0]
        assert ms[0]["guesses"] > plain["guesses"]

    def test_no_l33t_chars_means_no_matches(self):
        assert l33t_matches("password") == []

    def test_l33t_char_count_recorded(self):
        ms = [m for m in l33t_matches("p@ssw0rd")
              if m["matched_word"] == "password"]
        assert ms and ms[0]["l33t_chars"] == 2


class TestSpatialMatches:
    def test_qwerty_walk(self):
        ms = spatial_matches("qwerty")
        assert len(ms) == 1
        assert ms[0]["token"] == "qwerty"
        assert ms[0]["pattern"] == "spatial"

    def test_short_walks_ignored(self):
        assert spatial_matches("qw") == []

    def test_non_walk_ignored(self):
        assert spatial_matches("banana") == []

    def test_zxcvbn_walk(self):
        ms = spatial_matches("zxcvbn")
        assert len(ms) == 1
        assert ms[0]["token"] == "zxcvbn"


class TestDateMatches:
    def test_year_alone(self):
        ms = date_matches("1995")
        assert len(ms) == 1
        assert ms[0]["token"] == "1995"
        assert ms[0]["guesses"] == 140

    def test_separated_date(self):
        ms = date_matches("12/25/1995")
        assert any(m["token"] == "12/25/1995" for m in ms)

    def test_raw_date(self):
        ms = date_matches("12251995")
        assert any(m["token"] == "12251995" for m in ms)

    def test_year_out_of_range_ignored(self):
        assert date_matches("1899") == []
        assert date_matches("2050") == []

    def test_year_inside_password(self):
        ms = date_matches("pass1995word")
        assert any(m["token"] == "1995" for m in ms)


class TestRepeatMatches:
    def test_simple_repeat(self):
        ms = repeat_matches("aaa")
        assert len(ms) == 1
        assert ms[0]["base_char"] == "a"
        assert ms[0]["guesses"] == 26 * 3

    def test_digit_repeat(self):
        ms = repeat_matches("1111")
        assert ms[0]["guesses"] == 10 * 4

    def test_short_runs_ignored(self):
        assert repeat_matches("aa") == []

    def test_multiple_runs(self):
        ms = repeat_matches("aaabbb")
        assert len(ms) == 2


class TestSequenceMatches:
    def test_ascending_letters(self):
        ms = sequence_matches("abc")
        assert len(ms) == 1
        assert ms[0]["ascending"] is True
        assert ms[0]["guesses"] == 4 * 3  # starts at 'a'

    def test_descending_digits(self):
        ms = sequence_matches("987")
        assert len(ms) == 1
        assert ms[0]["ascending"] is False

    def test_mixed_case_not_a_sequence(self):
        # 'aBc' breaks the ordinal run.
        assert sequence_matches("aBc") == []

    def test_short_runs_ignored(self):
        assert sequence_matches("ab") == []

    def test_mid_word_sequence(self):
        ms = sequence_matches("xxabcdxx")
        assert any(m["token"] == "abcd" for m in ms)


class TestEstimate:
    def test_result_shape(self):
        r = estimate("password")
        for key in ("password", "matches", "sequence", "guesses",
                    "log10_guesses", "crack_times_seconds",
                    "crack_times_display", "score"):
            assert key in r
        assert set(r["crack_times_seconds"]) == set(ATTACK_SPEEDS)
        assert set(r["crack_times_display"]) == set(ATTACK_SPEEDS)

    def test_empty_password(self):
        r = estimate("")
        assert r["guesses"] == 0
        assert r["score"] == 0
        assert r["sequence"] == []

    def test_sequence_covers_whole_password(self):
        for pw in ("password", "Tr0ub4dor&3", "xK9$mQ2vL", "qwerty123"):
            r = estimate(pw)
            covered = "".join(m["token"] for m in r["sequence"])
            assert covered == pw
            # Segments are contiguous and non-overlapping.
            pos = 0
            for m in r["sequence"]:
                assert m["i"] == pos
                pos = m["j"]
            assert pos == len(pw)

    def test_weak_password_scores_zero(self):
        assert estimate("password")["score"] == 0
        assert estimate("123456")["score"] == 0
        assert estimate("qwerty")["score"] == 0

    def test_strong_password_scores_high(self):
        assert estimate("xK9$mQ2vLpZ7!wR")["score"] >= 3

    def test_guesses_monotonic_with_length(self):
        short = estimate("xK9$mQ")["guesses"]
        long = estimate("xK9$mQ2vLpZ7")["guesses"]
        assert long > short

    def test_crack_times_scale_with_speed(self):
        r = estimate("correcthorsebattery")
        t = r["crack_times_seconds"]
        assert t["online_throttling_100_per_hour"] > \
            t["online_no_throttling_10_per_second"] > \
            t["offline_slow_hashing_10k_per_second"] > \
            t["offline_fast_hashing_10b_per_second"]

    def test_crack_time_math(self):
        r = estimate("password")
        fast = r["crack_times_seconds"]["offline_fast_hashing_10b_per_second"]
        assert fast == pytest.approx(r["guesses"] / 1e10)

    def test_display_strings_are_readable(self):
        assert estimate("password")["crack_times_display"][
            "offline_fast_hashing_10b_per_second"] == "less than a second"
        strong = estimate("xK9$mQ2vLpZ7!wR")["crack_times_display"]
        assert strong["offline_fast_hashing_10b_per_second"] in (
            "years", "centuries")

    def test_log10_guesses_consistent(self):
        r = estimate("sunshine1")
        assert r["log10_guesses"] == pytest.approx(math.log10(r["guesses"]))

    def test_deterministic(self):
        assert estimate("Tr0ub4dor&3") == estimate("Tr0ub4dor&3")

    def test_score_bounds(self):
        for pw in ("a", "password", "hunter2", "xK9$mQ2vLpZ7!wR"):
            assert 0 <= estimate(pw)["score"] <= 4

    def test_repeat_password_cheaper_than_random(self):
        # A repeat run is far cheaper than brute-forcing 8 random letters.
        assert estimate("aaaaaaaa")["guesses"] < 26 ** 8
        assert estimate("aaaaaaaa")["guesses"] < estimate("xkqmzvbt")["guesses"]

    def test_date_password_detected_in_sequence(self):
        r = estimate("12/25/1995")
        patterns = {m["pattern"] for m in r["sequence"]}
        assert "date" in patterns
