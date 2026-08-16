"""Tests for hash_auditor.brute."""

from __future__ import annotations

import hashlib

import pytest

from hash_auditor.brute import (
    BruteForcer,
    Checkpoint,
    candidate_to_index,
    incremental_index,
    index_to_candidate,
)


class TestIndexing:
    def test_length1(self):
        assert index_to_candidate("ab", 0) == "a"
        assert index_to_candidate("ab", 1) == "b"

    def test_length2(self):
        # after 2 length-1 candidates come length-2
        assert index_to_candidate("ab", 2) == "aa"
        assert index_to_candidate("ab", 3) == "ab"
        assert index_to_candidate("ab", 4) == "ba"
        assert index_to_candidate("ab", 5) == "bb"

    def test_length3(self):
        # 2 + 4 = 6 length<3 candidates, so index 6 is 'aaa'
        assert index_to_candidate("ab", 6) == "aaa"

    def test_roundtrip(self):
        for index in range(0, 40):
            cand = index_to_candidate("abc", index)
            assert candidate_to_index("abc", cand) == index

    def test_incremental_index(self):
        assert incremental_index("ab", 1, 0) == 0
        assert incremental_index("ab", 1, 1) == 1
        assert incremental_index("ab", 2, 0) == 2

    def test_incremental_index_bounds(self):
        with pytest.raises(ValueError):
            incremental_index("ab", 2, 4)  # only 4 length-2 (0..3)
        with pytest.raises(ValueError):
            incremental_index("ab", 0, 0)

    def test_index_negative(self):
        with pytest.raises(ValueError):
            index_to_candidate("ab", -1)

    def test_candidate_foreign_char(self):
        with pytest.raises(ValueError):
            candidate_to_index("ab", "ac")


class TestBruteForcer:
    def test_candidates_order(self):
        bf = BruteForcer("ab")
        out = [c for _, c in bf.candidates(0, max_index=6)]
        assert out == ["a", "b", "aa", "ab", "ba", "bb"]

    def test_crack_found(self):
        bf = BruteForcer("ab")
        target = hashlib.md5(b"ba").hexdigest()
        result = bf.crack(target)
        assert result["found"]
        assert result["plaintext"] == "ba"
        assert result["index"] == 4

    def test_crack_sha256(self):
        bf = BruteForcer("0123456789", algo="sha256")
        target = hashlib.sha256(b"42").hexdigest()
        result = bf.crack(target)
        assert result["found"] and result["plaintext"] == "42"

    def test_crack_not_found_with_limit(self):
        bf = BruteForcer("ab")
        target = hashlib.md5(b"zzzz").hexdigest()
        result = bf.crack(target, max_attempts=6)
        assert not result["found"]
        assert result["attempts"] == 6

    def test_resume_from_index(self):
        bf = BruteForcer("ab")
        target = hashlib.md5(b"bb").hexdigest()
        # start at index 5 ('bb') directly
        result = bf.crack(target, start_index=5)
        assert result["found"] and result["plaintext"] == "bb"
        assert result["attempts"] == 1

    def test_unknown_algo(self):
        with pytest.raises(ValueError):
            BruteForcer("ab", algo="bogus")

    def test_empty_alphabet(self):
        with pytest.raises(ValueError):
            BruteForcer("")

    def test_progress_callback(self):
        bf = BruteForcer("ab")
        calls = []
        target = hashlib.md5(b"nothere").hexdigest()
        bf.crack(target, max_attempts=25,
                 progress=lambda n, c: calls.append(n),
                 progress_every=10)
        assert calls == [10, 20]


class TestCheckpoint:
    def test_roundtrip(self):
        cp = Checkpoint(alphabet="ab", algo="md5", target="x" * 32,
                        next_index=42, attempts=42)
        loaded = Checkpoint.from_json(cp.to_json())
        assert loaded.next_index == 42
        assert loaded.alphabet == "ab"
        assert loaded.target == "x" * 32

    def test_save_load(self, tmp_path):
        cp = Checkpoint(alphabet="01", algo="sha1", target="t", next_index=7)
        path = cp.save(tmp_path / "cp.json")
        loaded = Checkpoint.load(path)
        assert loaded.next_index == 7
        assert loaded.algo == "sha1"

    def test_crack_writes_checkpoint(self, tmp_path):
        bf = BruteForcer("ab")
        target = hashlib.md5(b"nothere").hexdigest()
        cp_path = tmp_path / "cp.json"
        bf.crack(target, max_attempts=10, checkpoint_path=cp_path,
                 checkpoint_every=5)
        assert cp_path.exists()
        cp = Checkpoint.load(cp_path)
        assert cp.next_index == 10
        assert cp.attempts == 10

    def test_resume_after_checkpoint(self, tmp_path):
        bf = BruteForcer("ab")
        target = hashlib.md5(b"ba").hexdigest()  # index 4
        cp_path = tmp_path / "cp.json"
        # run 1: only 2 attempts (a, b), checkpoint at end
        r1 = bf.crack(target, max_attempts=2, checkpoint_path=cp_path,
                      checkpoint_every=1)
        assert not r1["found"]
        cp = Checkpoint.load(cp_path)
        # run 2: resume from checkpoint
        r2 = bf.crack(target, start_index=cp.next_index)
        assert r2["found"] and r2["plaintext"] == "ba"
