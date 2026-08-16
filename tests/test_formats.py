"""Tests for hash_auditor.formats."""

from __future__ import annotations

import hashlib

from hash_auditor.formats import (
    HashRecord,
    detect_delimiter,
    parse_hash_file,
    parse_line,
    split_by_format,
    to_hashcat,
)

MD5 = hashlib.md5(b"x").hexdigest()
SHA1 = hashlib.sha1(b"x").hexdigest()


class TestDetectDelimiter:
    def test_tab(self):
        assert detect_delimiter("a\tb") == "\t"

    def test_colon(self):
        assert detect_delimiter("user:hash") == ":"

    def test_comma(self):
        assert detect_delimiter("a,b,c") == ","

    def test_semicolon(self):
        assert detect_delimiter("a;b") == ";"

    def test_default(self):
        assert detect_delimiter("nothing") == ":"


class TestParseLine:
    def test_bare_hash(self):
        rec = parse_line(MD5, line_no=3)
        assert rec.hash == MD5
        assert rec.format == "md5"
        assert rec.user is None
        assert rec.salt is None
        assert rec.line_no == 3

    def test_blank_and_comment(self):
        assert parse_line("") is None
        assert parse_line("   ") is None
        assert parse_line("# comment") is None

    def test_user_hash(self):
        rec = parse_line(f"alice:{MD5}")
        assert rec.user == "alice"
        assert rec.hash == MD5
        assert rec.format == "md5"

    def test_hash_salt(self):
        rec = parse_line(f"{MD5}:pepper")
        assert rec.hash == MD5
        assert rec.salt == "pepper"
        assert rec.user is None

    def test_user_salt_hash(self):
        rec = parse_line(f"bob:salt123:{SHA1}")
        assert rec.user == "bob"
        assert rec.salt == "salt123"
        assert rec.hash == SHA1
        assert rec.format == "sha1"

    def test_csv(self):
        rec = parse_line(f"carol,{MD5}")
        assert rec.user == "carol"
        assert rec.hash == MD5

    def test_modular_hash(self):
        h = "$2b$12$" + "a" * 53
        rec = parse_line(f"user:{h}")
        assert rec.hash == h
        assert rec.format == "bcrypt"

    def test_ldap_hash(self):
        h = "{SSHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
        rec = parse_line(h)
        assert rec.hash == h
        assert rec.format == "ldap-ssha"

    def test_no_hash_field(self):
        assert parse_line("just some words here") is None

    def test_short_hex_not_hash(self):
        # 4-char hex is too short to be a hash
        assert parse_line("user:abcd") is None

    def test_describe(self):
        rec = parse_line(f"alice:{MD5}")
        text = rec.describe()
        assert "md5" in text
        assert "user=alice" in text


class TestParseHashFile:
    def test_mixed_file(self):
        text = "\n".join([
            "# dump",
            MD5,
            "",
            f"alice:{SHA1}",
            "garbage line",
        ])
        records, skipped = parse_hash_file(text)
        assert len(records) == 2
        assert skipped == 3  # comment + blank + garbage
        assert records[0].line_no == 2
        assert records[1].line_no == 4

    def test_empty(self):
        records, skipped = parse_hash_file("")
        assert records == []
        assert skipped == 0  # no lines at all


class TestSplitAndRender:
    def test_split_by_format(self):
        records = [parse_line(MD5), parse_line(SHA1), parse_line("junk!!")]
        groups = split_by_format([r for r in records if r])
        assert "md5" in groups
        assert "sha1" in groups

    def test_split_unknown(self):
        rec = HashRecord(raw="x", hash="x", format=None)
        groups = split_by_format([rec])
        assert "unknown" in groups

    def test_to_hashcat(self):
        records = [parse_line(MD5), parse_line(f"{SHA1}:salt")]
        out = to_hashcat(records)
        lines = out.splitlines()
        assert lines[0] == MD5
        assert lines[1] == f"{SHA1}:salt"
