"""Tests for hash_auditor.checksums."""

from __future__ import annotations

import zlib

import pytest

from hash_auditor.checksums import (
    adler32,
    checksum_report,
    crc16,
    crc32,
    fnv1a_32,
    fnv1a_64,
    internet_checksum,
    luhn_check,
    luhn_generate,
)


class TestCrc32:
    def test_matches_zlib(self):
        for sample in (b"", b"a", b"abc", b"The quick brown fox",
                       bytes(range(256))):
            assert crc32(sample) == zlib.crc32(sample) & 0xFFFFFFFF

    def test_known_value(self):
        assert crc32(b"123456789") == 0xCBF43926

    def test_str_input(self):
        assert crc32("abc") == crc32(b"abc")


class TestCrc16:
    def test_known_value(self):
        # CRC-16/CCITT-FALSE check value for "123456789"
        assert crc16(b"123456789") == 0x29B1

    def test_empty(self):
        assert crc16(b"") == 0xFFFF  # init value, no data

    def test_deterministic(self):
        assert crc16(b"hello") == crc16(b"hello")


class TestAdler32:
    def test_matches_zlib(self):
        for sample in (b"", b"a", b"abc", b"The quick brown fox",
                       bytes(range(256)) * 2):
            assert adler32(sample) == zlib.adler32(sample) & 0xFFFFFFFF

    def test_known_value(self):
        assert adler32(b"Wikipedia") == 0x11E60398


class TestFnv:
    def test_fnv1a_32_known(self):
        # FNV-1a 32-bit of empty is the offset basis
        assert fnv1a_32(b"") == 0x811C9DC5

    def test_fnv1a_64_known(self):
        assert fnv1a_64(b"") == 0xCBF29CE484222325

    def test_fnv1a_32_a(self):
        assert fnv1a_32(b"a") == 0xE40C292C

    def test_fnv1a_64_a(self):
        assert fnv1a_64(b"a") == 0xAF63DC4C8601EC8C

    def test_deterministic(self):
        assert fnv1a_32(b"hello") == fnv1a_32(b"hello")
        assert fnv1a_64(b"hello") == fnv1a_64(b"hello")


class TestInternetChecksum:
    def test_known(self):
        # classic example: 0x0001 + 0xf203 ... use a simple check
        assert internet_checksum(b"\x00\x01\xf2\x03") == \
            (~((0x0001 + 0xF203))) & 0xFFFF

    def test_zero_data(self):
        assert internet_checksum(b"\x00\x00") == 0xFFFF

    def test_odd_length_padded(self):
        # odd length is padded with a zero byte
        assert internet_checksum(b"\x01") == internet_checksum(b"\x01\x00")


class TestLuhn:
    def test_valid_card(self):
        assert luhn_check("4532015112830366")  # valid test Visa

    def test_invalid(self):
        assert not luhn_check("4532015112830367")

    def test_generate_roundtrip(self):
        base = "453201511283036"
        full = luhn_generate(base)
        assert len(full) == len(base) + 1
        assert luhn_check(full)

    def test_non_digit_raises(self):
        with pytest.raises(ValueError):
            luhn_check("12a4")
        with pytest.raises(ValueError):
            luhn_generate("12a")

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            luhn_check("")


class TestChecksumReport:
    def test_shape(self):
        rep = checksum_report(b"hello")
        assert set(rep) == {"crc32", "crc16", "adler32", "fnv1a_32",
                            "fnv1a_64", "internet_checksum"}
        assert len(rep["crc32"]) == 8
        assert len(rep["fnv1a_64"]) == 16

    def test_str_input(self):
        assert checksum_report("abc") == checksum_report(b"abc")
