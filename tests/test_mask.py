"""Tests for hash_auditor.mask."""

from __future__ import annotations

import hashlib

import pytest

from hash_auditor.mask import (
    CHARSETS,
    MaskEngine,
    MaskError,
    estimate_mask_time,
    mask_info,
    parse_mask,
)


class TestParseMask:
    def test_tokens(self):
        alphas = parse_mask("?l?d")
        assert alphas[0] == "abcdefghijklmnopqrstuvwxyz"
        assert alphas[1] == "0123456789"

    def test_literals(self):
        assert parse_mask("ab?d") == ["a", "b", "0123456789"]

    def test_escaped_question(self):
        assert parse_mask("??") == ["?"]
        assert parse_mask("a??b") == ["a", "?", "b"]

    def test_all_builtin_tokens(self):
        for token in ("?l", "?u", "?d", "?s", "?a", "?h", "?H", "?b", "??"):
            assert len(parse_mask(token)) == 1

    def test_charset_sizes(self):
        assert len(CHARSETS["?l"]) == 26
        assert len(CHARSETS["?u"]) == 26
        assert len(CHARSETS["?d"]) == 10
        assert len(CHARSETS["?a"]) == 95
        assert len(CHARSETS["?h"]) == 16

    def test_empty_mask(self):
        with pytest.raises(MaskError):
            parse_mask("")

    def test_unknown_token(self):
        with pytest.raises(MaskError):
            parse_mask("?z")

    def test_dangling_question(self):
        with pytest.raises(MaskError):
            parse_mask("abc?")

    def test_custom_not_registered(self):
        with pytest.raises(MaskError):
            parse_mask("?1?1")

    def test_custom_supplied(self):
        alphas = parse_mask("?1", custom={"?1": "xyz"})
        assert alphas == ["xyz"]


class TestMaskInfo:
    def test_keyspace(self):
        info = mask_info("?d?d?d?d")
        assert info["keyspace_size"] == 10_000
        assert info["length"] == 4
        assert abs(info["entropy_bits"] - 13.29) < 0.01

    def test_mixed(self):
        info = mask_info("Pass?d?d")
        assert info["keyspace_size"] == 100

    def test_positions_labels(self):
        info = mask_info("?l?d")
        assert info["positions"][0]["label"] == "?l"
        assert info["positions"][1]["size"] == 10

    def test_single_char_keyspace(self):
        info = mask_info("a")
        assert info["keyspace_size"] == 1
        assert info["entropy_bits"] == 0.0


class TestMaskEngine:
    def test_candidates_order(self):
        eng = MaskEngine()
        assert list(eng.candidates("?d?d"))[:3] == ["00", "01", "02"]
        assert list(eng.candidates("?d?d"))[-1] == "99"

    def test_candidates_count(self):
        eng = MaskEngine()
        assert len(list(eng.candidates("?l?l"))) == 26 * 26

    def test_count_no_expansion(self):
        eng = MaskEngine()
        assert eng.count("?d?d?d?d?d?d?d?d") == 100_000_000

    def test_register_custom(self):
        eng = MaskEngine()
        eng.register(1, "ab")
        assert list(eng.candidates("?1?1")) == ["aa", "ab", "ba", "bb"]

    def test_register_bad_slot(self):
        eng = MaskEngine()
        with pytest.raises(MaskError):
            eng.register(5, "ab")

    def test_register_empty(self):
        eng = MaskEngine()
        with pytest.raises(MaskError):
            eng.register(1, "")

    def test_crack_found(self):
        eng = MaskEngine()
        target = hashlib.md5(b"4242").hexdigest()
        result = eng.crack(target, "?d?d?d?d", algo="md5")
        assert result["found"]
        assert result["plaintext"] == "4242"
        assert result["attempts"] == 4243  # 0000..4242

    def test_crack_sha256(self):
        eng = MaskEngine()
        target = hashlib.sha256(b"ab").hexdigest()
        result = eng.crack(target, "?l?l", algo="sha256")
        assert result["found"] and result["plaintext"] == "ab"

    def test_crack_not_found(self):
        eng = MaskEngine()
        target = hashlib.md5(b"zzzz").hexdigest()
        result = eng.crack(target, "?d?d", algo="md5")
        assert not result["found"]
        assert result["attempts"] == 100

    def test_crack_limit(self):
        eng = MaskEngine()
        target = hashlib.md5(b"9999").hexdigest()
        result = eng.crack(target, "?d?d?d?d", limit=50)
        assert not result["found"]
        assert result["attempts"] == 50

    def test_crack_unknown_algo(self):
        eng = MaskEngine()
        with pytest.raises(MaskError):
            eng.crack("ab" * 16, "?d", algo="bogus")

    def test_crack_progress_callback(self):
        eng = MaskEngine()
        calls = []
        target = hashlib.md5(b"nope").hexdigest()
        eng.crack(target, "?d?d?d", limit=250,
                  progress=lambda n, g: calls.append(n),
                  progress_every=100)
        assert calls == [100, 200]


class TestEstimateTime:
    def test_basic(self):
        est = estimate_mask_time("?d?d?d?d", 1000.0)
        assert est["keyspace_size"] == 10_000
        assert est["seconds"] == 10.0
        assert "second" in est["human"]

    def test_large(self):
        est = estimate_mask_time("?a?a?a?a?a?a?a?a", 1e9)
        assert est["seconds"] > 0
        assert "year" in est["human"] or "day" in est["human"]

    def test_minutes(self):
        est = estimate_mask_time("?d?d?d?d?d", 100.0)  # 100000/100 = 1000s
        assert "minute" in est["human"]

    def test_invalid_rate(self):
        with pytest.raises(ValueError):
            estimate_mask_time("?d", 0)
