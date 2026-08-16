"""Tests for hash_auditor.identify."""

from __future__ import annotations

import hashlib

import pytest

from hash_auditor.hashid import (
    HashCandidate,
    format_candidates,
    identify_best,
    identify_hash,
    identify_many,
)


def md5hex(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def sha1hex(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()


def sha256hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def sha512hex(s: str) -> str:
    return hashlib.sha512(s.encode()).hexdigest()


class TestRawHex:
    def test_md5_length(self):
        cands = identify_hash(md5hex("hello"))
        assert cands[0].name == "md5"
        assert cands[0].confidence > 0.2
        names = {c.name for c in cands}
        assert "ntlm" in names

    def test_sha1(self):
        assert identify_best(sha1hex("hello")).name == "sha1"

    def test_sha256(self):
        assert identify_best(sha256hex("hello")).name == "sha256"

    def test_sha512(self):
        assert identify_best(sha512hex("hello")).name == "sha512"

    def test_crc32(self):
        assert identify_best("deadbeef").name == "crc32"

    def test_uppercase_hex_normalized(self):
        best = identify_best(md5hex("hello").upper())
        assert best is not None and best.name == "md5"

    def test_ranking_is_sorted(self):
        cands = identify_hash(md5hex("x"))
        confs = [c.confidence for c in cands]
        assert confs == sorted(confs, reverse=True)

    def test_unknown_length(self):
        assert identify_hash("abc123") == []

    def test_empty(self):
        assert identify_hash("") == []
        assert identify_hash("   ") == []

    def test_quotes_stripped(self):
        assert identify_best(f"'{md5hex('q')}'").name == "md5"
        assert identify_best(f'"{md5hex("q")}"').name == "md5"


class TestModularCrypt:
    def test_bcrypt(self):
        h = "$2b$12$KIXhcs7anG39TZxKvOqseOaBcJhVbGHQ6qXc1VZ7dK0rF1yWnXW2G"
        best = identify_best(h)
        assert best.name == "bcrypt"
        assert best.confidence >= 0.95
        assert any("cost factor 12" in r for r in best.reasons)

    def test_bcrypt_unusual_cost(self):
        h = "$2a$99$" + "a" * 53
        best = identify_best(h)
        assert best.name == "bcrypt"
        assert best.confidence < 0.95

    def test_md5crypt(self):
        h = "$1$saltstri$YMyguxXMBpd2TEZ.vS/3q1"
        best = identify_best(h)
        assert best.name == "md5crypt"

    def test_apr1(self):
        h = "$apr1$r31.....$HqJZimcKQFAMYayBlzkrA/"
        assert identify_best(h).name == "apr1crypt"

    def test_sha512crypt(self):
        h = "$6$saltsalt$" + "a" * 86
        assert identify_best(h).name == "sha512crypt"

    def test_sha256crypt_rounds(self):
        h = "$5$rounds=5000$salt$" + "b" * 43
        best = identify_best(h)
        assert best.name == "sha256crypt"
        assert any("rounds=5000" in r for r in best.reasons)

    def test_argon2id(self):
        h = ("$argon2id$v=19$m=65536,t=3,p=4$"
             "c2FsdHNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG")
        best = identify_best(h)
        assert best.name == "argon2id"
        assert best.confidence >= 0.97

    def test_argon2i_and_d(self):
        for variant in ("i", "d"):
            h = (f"$argon2{variant}$v=19$m=4096,t=3,p=1$"
                 "c2FsdA$RdescudvJCsgt3ub")
            assert identify_best(h).name == f"argon2{variant}"

    def test_pbkdf2(self):
        h = "$pbkdf2-sha256$29000$salt$hash"
        best = identify_best(h)
        assert best.name == "pbkdf2-sha256"
        assert any("29000 iterations" in r for r in best.reasons)

    def test_django_pbkdf2(self):
        h = "pbkdf2_sha256$260000$saltsalt$abc123def456"
        best = identify_best(h)
        assert best.name == "django-pbkdf2_sha256"
        assert any("260000 iterations" in r for r in best.reasons)

    def test_scrypt_hashcat(self):
        h = "$SCRYPT:16384:8:1:c2FsdA:aGFzaA"
        assert identify_best(h).name == "scrypt"

    def test_scrypt_modular(self):
        h = "$s0$e0801$c2FsdA$aGFzaA"
        assert identify_best(h).name == "scrypt"

    def test_yescrypt(self):
        h = "$y$j9T$salt$hashhashhash"
        assert identify_best(h).name == "yescrypt"

    def test_phpass(self):
        h = "$P$B91234567aaaaaaaaaaaaaaaaaaaaaa"[:34]
        h = "$P$B" + "a" * 8 + "b" * 22
        assert identify_best(h).name == "phpass"

    def test_sunmd5(self):
        h = "$md5$rounds=2006$salt$" + "a" * 22
        assert identify_best(h).name == "sunmd5"

    def test_unknown_dollar(self):
        assert identify_hash("$zz$whatever") == []


class TestOtherFormats:
    def test_mysql5(self):
        h = "*" + "A" * 40
        assert identify_best(h).name == "mysql5"

    def test_ldap_ssha(self):
        h = "{SSHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
        assert identify_best(h).name == "ldap-ssha"

    def test_des_crypt(self):
        h = "abQX.12345678"  # 13 chars, crypt alphabet, not pure hex
        assert identify_best(h).name == "des-crypt"

    def test_base64_sha256(self):
        import base64
        h = base64.b64encode(hashlib.sha256(b"x").digest()).decode()
        assert identify_best(h).name == "sha256-base64"


class TestBatchAndFormat:
    def test_identify_many_skips_comments(self):
        text = "\n".join([
            "# comment",
            "",
            md5hex("a"),
            "junk!!",
        ])
        results = identify_many(text)
        assert len(results) == 2
        assert results[0][1][0].name == "md5"
        assert results[1][1] == []

    def test_identify_many_accepts_list(self):
        results = identify_many([sha1hex("b")])
        assert results[0][1][0].name == "sha1"

    def test_format_candidates_empty(self):
        assert format_candidates([]) == "[!] no matching hash format"

    def test_format_candidates_numbered(self):
        cands = identify_hash(md5hex("z"))
        text = format_candidates(cands)
        assert text.startswith("1. md5")
        assert "2." in text

    def test_candidate_describe(self):
        c = HashCandidate("md5", 0.5, ("reason one", "reason two"))
        assert c.describe() == "md5 (confidence: 0.50) -- reason one; reason two"

    def test_candidate_frozen(self):
        c = HashCandidate("md5", 0.5)
        with pytest.raises(Exception):
            c.name = "sha1"
