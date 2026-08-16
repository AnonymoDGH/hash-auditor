"""Tests for hash_auditor.rainbow."""

from __future__ import annotations

import hashlib

import pytest

from hash_auditor.rainbow import (
    RainbowTable,
    build_table,
    index_to_password,
    keyspace,
    keyspace_size,
    password_to_index,
    reduction,
)


class TestKeyspace:
    def test_keyspace_order(self):
        assert list(keyspace("ab", 2)) == ["aa", "ab", "ba", "bb"]

    def test_keyspace_size(self):
        assert keyspace_size("abc", 3) == 27
        assert keyspace_size("aa", 2) == 1  # duplicates removed

    def test_keyspace_invalid_length(self):
        with pytest.raises(ValueError):
            list(keyspace("ab", 0))

    def test_index_roundtrip(self):
        alphabet, length = "abcd", 3
        size = keyspace_size(alphabet, length)
        for index in (0, 1, size // 2, size - 1):
            pw = index_to_password(alphabet, length, index)
            assert password_to_index(alphabet, pw) == index

    def test_index_bounds(self):
        with pytest.raises(ValueError):
            index_to_password("ab", 2, 4)
        with pytest.raises(ValueError):
            index_to_password("ab", 2, -1)

    def test_password_foreign_char(self):
        with pytest.raises(ValueError):
            password_to_index("ab", "ac")

    def test_first_and_last(self):
        assert index_to_password("abc", 2, 0) == "aa"
        assert index_to_password("abc", 2, 8) == "cc"


class TestReduction:
    def test_deterministic(self):
        digest = hashlib.md5(b"test").digest()
        assert reduction(digest, 3, 1000) == reduction(digest, 3, 1000)

    def test_column_dependent(self):
        digest = hashlib.md5(b"test").digest()
        values = {reduction(digest, col, 10 ** 9) for col in range(8)}
        assert len(values) > 1  # different columns give different reductions

    def test_in_range(self):
        digest = hashlib.md5(b"x").digest()
        for col in range(5):
            assert 0 <= reduction(digest, col, 100) < 100

    def test_invalid_size(self):
        with pytest.raises(ValueError):
            reduction(b"\x00" * 16, 0, 0)


class TestRainbowTable:
    def test_build_deterministic(self):
        t1 = build_table("abc", 3, chains=10, chain_length=8, seed=42)
        t2 = build_table("abc", 3, chains=10, chain_length=8, seed=42)
        assert t1.chains == t2.chains

    def test_different_seeds_differ(self):
        t1 = build_table("abc", 3, chains=10, chain_length=8, seed=1)
        t2 = build_table("abc", 3, chains=10, chain_length=8, seed=2)
        assert t1.chains != t2.chains

    def test_lookup_finds_chain_member(self):
        # Tiny keyspace, exhaustive table: every start point chained.
        table = RainbowTable("ab", 3, chain_length=6)
        for start in range(table.size):
            table.add_chain(start)
        # Every password in the keyspace must be recoverable from its hash.
        for pw in keyspace("ab", 3):
            h = hashlib.md5(pw.encode()).hexdigest()
            assert table.lookup(h) == pw, f"failed to crack {pw!r}"

    def test_lookup_miss(self):
        table = build_table("ab", 3, chains=2, chain_length=4, seed=7)
        # A hash of something outside the keyspace (contains 'z').
        h = hashlib.md5(b"zzz").hexdigest()
        assert table.lookup(h) is None

    def test_lookup_non_hex(self):
        table = build_table("ab", 3, chains=2, chain_length=4, seed=7)
        assert table.lookup("not-a-hash!") is None

    def test_lookup_odd_length_hex(self):
        table = build_table("ab", 3, chains=2, chain_length=4, seed=7)
        assert table.lookup("abc") is None

    def test_add_chain_bounds(self):
        table = RainbowTable("ab", 2, chain_length=3)
        with pytest.raises(ValueError):
            table.add_chain(4)

    def test_invalid_chain_length(self):
        with pytest.raises(ValueError):
            RainbowTable("ab", 2, chain_length=0)

    def test_build_invalid_chains(self):
        with pytest.raises(ValueError):
            build_table("ab", 2, chains=0, chain_length=3)

    def test_coverage(self):
        table = RainbowTable("ab", 2, chain_length=3)
        assert table.coverage() == 0.0
        table.add_chain(0)
        table.add_chain(1)
        table.add_chain(0)  # duplicate start
        assert table.coverage() == pytest.approx(2 / 4)

    def test_stats(self):
        table = build_table("abc", 2, chains=5, chain_length=4, seed=3)
        stats = table.stats()
        assert stats["keyspace_size"] == 9
        assert stats["chains"] == 5
        assert stats["chain_length"] == 4
        assert 0.0 <= stats["coverage"] <= 1.0

    def test_save_load_roundtrip(self, tmp_path):
        table = build_table("abc", 3, chains=6, chain_length=5, seed=11)
        path = table.save(tmp_path / "table.json")
        loaded = RainbowTable.load(path)
        assert loaded.chains == table.chains
        assert loaded.alphabet == table.alphabet
        assert loaded.length == table.length
        assert loaded.chain_length == table.chain_length
        # Loaded table cracks the same hashes.
        pw = index_to_password("abc", 3, table.chains[0][1])
        h = hashlib.md5(pw.encode()).hexdigest()
        assert loaded.lookup(h) == pw

    def test_from_dict_rejects_bad_format(self):
        with pytest.raises(ValueError):
            RainbowTable.from_dict({"format": "bogus"})

    def test_from_dict_rejects_bad_hash(self):
        with pytest.raises(ValueError):
            RainbowTable.from_dict({"format": "hash-auditor-rainbow/1",
                                    "hash": "sha1"})

    def test_build_more_chains_than_keyspace(self):
        # With-replacement sampling path.
        table = build_table("ab", 1, chains=10, chain_length=3, seed=5)
        assert len(table.chains) == 10
        assert table.coverage() <= 1.0
