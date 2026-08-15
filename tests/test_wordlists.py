"""Tests for hash_auditor.wordlists."""

from __future__ import annotations

import base64
import zlib

import pytest

from hash_auditor.wordlists import (
    EMBEDDED_DATA,
    EMBEDDED_NAMES,
    EMBEDDED_PASSWORDS,
    EMBEDDED_WORDS,
    load_wordlist,
    stream_candidates,
)


class TestEmbeddedData:
    def test_passwords_are_real_and_plentiful(self):
        assert len(EMBEDDED_PASSWORDS) >= 300
        for top in ("password", "123456", "qwerty", "letmein", "iloveyou"):
            assert top in EMBEDDED_PASSWORDS

    def test_words_are_real_and_plentiful(self):
        assert len(EMBEDDED_WORDS) >= 700
        for w in ("time", "water", "castle", "banana", "elephant"):
            assert w in EMBEDDED_WORDS

    def test_names_are_real_and_plentiful(self):
        assert len(EMBEDDED_NAMES) >= 200
        for n in ("james", "mary", "smith", "jessica"):
            assert n in EMBEDDED_NAMES

    def test_total_entries_at_least_one_thousand(self):
        total = len(EMBEDDED_PASSWORDS) + len(EMBEDDED_WORDS)
        assert total >= 1000

    def test_lists_are_deduplicated(self):
        for lst in (EMBEDDED_PASSWORDS, EMBEDDED_WORDS, EMBEDDED_NAMES):
            assert len(lst) == len(set(lst))

    def test_no_empty_entries(self):
        for lst in (EMBEDDED_PASSWORDS, EMBEDDED_WORDS, EMBEDDED_NAMES):
            assert all(entry.strip() for entry in lst)

    def test_embedded_data_blobs_roundtrip(self):
        assert set(EMBEDDED_DATA) == {"passwords", "words", "names"}
        for blob in EMBEDDED_DATA.values():
            raw = zlib.decompress(base64.b64decode(blob))
            text = raw.decode("utf-8")
            assert text.split()  # non-empty token list

    def test_words_include_names(self):
        # EMBEDDED_WORDS is the general fodder list: words + names.
        assert "james" in EMBEDDED_WORDS
        assert "smith" in EMBEDDED_WORDS


class TestLoadWordlist:
    def test_basic_utf8(self, tmp_path):
        p = tmp_path / "wl.txt"
        p.write_text("alpha\nbeta\n\n# comment\ngamma\n", encoding="utf-8")
        assert list(load_wordlist(p)) == ["alpha", "beta", "gamma"]

    def test_strips_whitespace(self, tmp_path):
        p = tmp_path / "wl.txt"
        p.write_text("  alpha  \n\tbeta\t\n", encoding="utf-8")
        assert list(load_wordlist(p)) == ["alpha", "beta"]

    def test_utf8_bom(self, tmp_path):
        p = tmp_path / "wl.txt"
        p.write_bytes(b"\xef\xbb\xbfalpha\nbeta\n")
        assert list(load_wordlist(p)) == ["alpha", "beta"]

    def test_utf16(self, tmp_path):
        p = tmp_path / "wl.txt"
        p.write_text("alpha\nbeta\n", encoding="utf-16")
        assert list(load_wordlist(p)) == ["alpha", "beta"]

    def test_cp1252_fallback(self, tmp_path):
        p = tmp_path / "wl.txt"
        # 0x93/0x94 are CP1252 curly quotes; invalid as UTF-8 start bytes.
        p.write_bytes(b"caf\xe9\n\x93quoted\x94\n")
        words = list(load_wordlist(p))
        assert words[0] == "caf\u00e9"
        assert "quoted" in words[1]

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            list(load_wordlist(tmp_path / "nope.txt"))

    def test_is_a_generator(self, tmp_path):
        p = tmp_path / "wl.txt"
        p.write_text("alpha\n", encoding="utf-8")
        import types
        assert isinstance(load_wordlist(p), types.GeneratorType)


class TestStreamCandidates:
    def test_chains_and_dedupes(self, tmp_path):
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        a.write_text("one\ntwo\nthree\n", encoding="utf-8")
        b.write_text("three\nfour\none\n", encoding="utf-8")
        assert list(stream_candidates([a, b])) == ["one", "two", "three", "four"]

    def test_empty_paths(self):
        assert list(stream_candidates([])) == []

    def test_missing_file_propagates(self, tmp_path):
        a = tmp_path / "a.txt"
        a.write_text("one\n", encoding="utf-8")
        with pytest.raises(FileNotFoundError):
            list(stream_candidates([a, tmp_path / "missing.txt"]))

    def test_lazy_streaming(self, tmp_path):
        a = tmp_path / "a.txt"
        a.write_text("\n".join(f"w{i}" for i in range(50)), encoding="utf-8")
        gen = stream_candidates([a])
        first = next(gen)
        assert first == "w0"
