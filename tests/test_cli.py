"""Tests for the hashaudit CLI (all subcommands)."""

from __future__ import annotations

import hashlib
import json

import pytest

from hash_auditor.cli import main


def run(capsys, *argv: str) -> str:
    assert main(list(argv)) == 0
    return capsys.readouterr().out


class TestOriginalCommands:
    def test_check(self, capsys):
        out = run(capsys, "check", "password123")
        assert "verdict: weak" in out

    def test_hash(self, capsys):
        out = run(capsys, "hash", "hello", "--algo", "md5")
        assert out.strip() == hashlib.md5(b"hello").hexdigest()

    def test_identify(self, capsys):
        out = run(capsys, "identify", hashlib.md5(b"x").hexdigest())
        assert "md5" in out

    def test_crack(self, capsys, tmp_path):
        wl = tmp_path / "wl.txt"
        wl.write_text("hunter2\n", encoding="utf-8")
        target = hashlib.md5(b"hunter2").hexdigest()
        out = run(capsys, "crack", "--hash", target, "--wordlist", str(wl),
                  "--algo", "md5", "--nomutate")
        assert "FOUND: 'hunter2'" in out


class TestRecognize:
    def test_md5(self, capsys):
        out = run(capsys, "recognize", hashlib.md5(b"x").hexdigest())
        assert "md5" in out
        assert "confidence" in out

    def test_bcrypt(self, capsys):
        h = "$2b$12$" + "a" * 53
        out = run(capsys, "recognize", h)
        assert out.startswith("1. bcrypt")

    def test_unknown(self, capsys):
        out = run(capsys, "recognize", "junk!!")
        assert "no matching hash format" in out


class TestRainbow:
    def test_build_and_lookup(self, capsys, tmp_path):
        table = tmp_path / "t.json"
        out = run(capsys, "rainbow", "--table", str(table),
                  "--alphabet", "ab", "--length", "3",
                  "--chains", "8", "--chain-length", "6", "--seed", "1")
        assert "built 8 chains" in out
        assert table.exists()
        # look up a hash of a keyspace member
        target = hashlib.md5(b"aba").hexdigest()
        out = run(capsys, "rainbow", "--table", str(table),
                  "--lookup", target)
        # full coverage of the 8-password keyspace: must be found
        assert "FOUND" in out

    def test_lookup_miss(self, capsys, tmp_path):
        table = tmp_path / "t.json"
        run(capsys, "rainbow", "--table", str(table), "--alphabet", "ab",
            "--length", "3", "--chains", "2", "--chain-length", "4")
        out = run(capsys, "rainbow", "--table", str(table),
                  "--lookup", hashlib.md5(b"zzz").hexdigest())
        assert "Not covered" in out


class TestPolicy:
    def test_single_password(self, capsys):
        out = run(capsys, "policy", "Tr0ub4dor&3xtra")
        assert "PASS" in out

    def test_failing_password(self, capsys):
        out = run(capsys, "policy", "abc", "--preset", "corporate")
        assert "FAIL" in out
        assert "min_length" in out

    def test_file_mode(self, capsys, tmp_path):
        f = tmp_path / "pw.txt"
        f.write_text("password\nXk9$mQ2vLp7wZr\n", encoding="utf-8")
        out = run(capsys, "policy", "--file", str(f), "--preset", "corporate")
        assert "checked 2 passwords" in out
        assert "pass rate" in out

    def test_missing_args(self, capsys):
        with pytest.raises(SystemExit):
            main(["policy"])


class TestGenerate:
    def test_diceware_seeded(self, capsys):
        out1 = run(capsys, "generate", "--scheme", "diceware", "--seed", "7")
        out2 = run(capsys, "generate", "--scheme", "diceware", "--seed", "7")
        assert out1 == out2

    def test_count(self, capsys):
        out = run(capsys, "generate", "--scheme", "syllable", "--count", "3")
        assert len(out.strip().splitlines()) == 3

    def test_leet(self, capsys):
        out = run(capsys, "generate", "--scheme", "leet", "--base", "dragon")
        assert out.strip()

    def test_pin_with_entropy(self, capsys):
        out = run(capsys, "generate", "--scheme", "pin", "--entropy",
                  "--pin-length", "8")
        assert "bits" in out


class TestBreach:
    def test_exposed(self, capsys):
        out = run(capsys, "breach", "password")
        assert "EXPOSED" in out
        assert "score" in out

    def test_clean(self, capsys):
        out = run(capsys, "breach", "Xk9$mQ2vLp7wZr")
        assert "not found" in out

    def test_file_mode(self, capsys, tmp_path):
        f = tmp_path / "pw.txt"
        f.write_text("password\nqwerty\nXk9$mQ2vLp7wZr\n", encoding="utf-8")
        out = run(capsys, "breach", "--file", str(f), "--top", "5")
        assert "checked 3 passwords" in out
        assert "exposed: 2" in out

    def test_missing_args(self):
        with pytest.raises(SystemExit):
            main(["breach"])


class TestMask:
    def test_info(self, capsys):
        out = run(capsys, "mask", "?d?d?d?d", "--info")
        assert "10,000" in out
        assert "bits" in out
        assert "worst case" in out

    def test_crack(self, capsys):
        target = hashlib.md5(b"1234").hexdigest()
        out = run(capsys, "mask", "?d?d?d?d", "--hash", target)
        assert "FOUND: '1234'" in out

    def test_crack_miss(self, capsys):
        target = hashlib.md5(b"zzzz").hexdigest()
        out = run(capsys, "mask", "?d?d", "--hash", target)
        assert "not found" in out

    def test_missing_hash(self):
        with pytest.raises(SystemExit):
            main(["mask", "?d?d"])


class TestReport:
    def test_text_report(self, capsys, tmp_path):
        f = tmp_path / "pw.txt"
        f.write_text("password\nXk9$mQ2vLp7wZr\n", encoding="utf-8")
        out = run(capsys, "report", "--file", str(f),
                  "--timestamp", "2024-01-01T00:00:00+00:00")
        assert "PASSWORDS (2)" in out
        assert "SUMMARY" in out

    def test_json_report(self, capsys, tmp_path):
        f = tmp_path / "pw.txt"
        f.write_text("hunter2\n", encoding="utf-8")
        out = run(capsys, "report", "--file", str(f), "--json",
                  "--timestamp", "2024-01-01T00:00:00+00:00")
        data = json.loads(out)
        assert data["passwords"][0]["exposed"] is True


class TestStats:
    def test_basic(self, capsys, tmp_path):
        f = tmp_path / "wl.txt"
        f.write_text("password\npassword\n123456\nDragon1\n", encoding="utf-8")
        out = run(capsys, "stats", "--file", str(f))
        assert "total: 4" in out
        assert "unique: 3" in out
        assert "Zipf exponent" in out

    def test_json(self, capsys, tmp_path):
        f = tmp_path / "wl.txt"
        f.write_text("a\nb\n", encoding="utf-8")
        out = run(capsys, "stats", "--file", str(f), "--json")
        # the summary lines come first, then the JSON blob
        data = json.loads(out[out.index("{"):])
        assert data["total"] == 2


class TestSimilarity:
    def test_increment(self, capsys):
        out = run(capsys, "similarity", "hunter2", "hunter3")
        assert "digit_increment" in out

    def test_unrelated(self, capsys):
        out = run(capsys, "similarity", "abc", "totally-different")
        assert "unrelated" in out


class TestAudit:
    def test_single(self, capsys):
        out = run(capsys, "audit", "password")
        assert "risk score" in out
        assert "exposed in breach corpus" in out

    def test_clean(self, capsys):
        out = run(capsys, "audit", "Xk9$mQ2vLp7wZr")
        assert "risk score" in out

    def test_file_mode(self, capsys, tmp_path):
        f = tmp_path / "pw.txt"
        f.write_text("password\nXk9$mQ2vLp7wZr\n", encoding="utf-8")
        out = run(capsys, "audit", "--file", str(f), "--top", "5")
        assert "audited 2 password(s)" in out
        assert "critical" in out or "high" in out

    def test_missing_args(self):
        with pytest.raises(SystemExit):
            main(["audit"])


class TestPcfg:
    def test_generate(self, capsys):
        out = run(capsys, "pcfg", "--count", "10")
        lines = [l for l in out.splitlines() if l.strip()]
        assert len(lines) == 10
        assert "1." in lines[0]
        assert "10." in lines[9]


class TestEntropy:
    def test_random_looking(self, capsys):
        out = run(capsys, "entropy", "Xk9$mQ2vLp7wZr")
        assert "randomness score" in out
        assert "shannon entropy" in out
        assert "effective bits" in out

    def test_pattern(self, capsys):
        out = run(capsys, "entropy", "aaaaaaaaaa")
        assert "pattern" in out


class TestHistory:
    def test_rejected(self, capsys, tmp_path):
        f = tmp_path / "hist.txt"
        f.write_text("Summer2023\nDragon1\n", encoding="utf-8")
        out = run(capsys, "history", "Summer2024", "--file", str(f))
        assert "rejected" in out
        assert "closest match" in out

    def test_allowed(self, capsys, tmp_path):
        f = tmp_path / "hist.txt"
        f.write_text("Summer2023\n", encoding="utf-8")
        out = run(capsys, "history", "Xk9$mQ2vLp7wZr", "--file", str(f))
        assert "allowed" in out


class TestParse:
    def test_parse_dump(self, capsys, tmp_path):
        md5 = hashlib.md5(b"x").hexdigest()
        sha1 = hashlib.sha1(b"x").hexdigest()
        f = tmp_path / "dump.txt"
        f.write_text(f"# dump\n{md5}\nalice:{sha1}\n", encoding="utf-8")
        out = run(capsys, "parse", "--file", str(f))
        assert "parsed 2 hash(es)" in out
        assert "md5: 1" in out
        assert "sha1: 1" in out

    def test_hashcat_output(self, capsys, tmp_path):
        md5 = hashlib.md5(b"x").hexdigest()
        f = tmp_path / "dump.txt"
        f.write_text(md5 + "\n", encoding="utf-8")
        out = run(capsys, "parse", "--file", str(f), "--hashcat")
        assert md5 in out


class TestCombine:
    def test_combinator_crack(self, capsys, tmp_path):
        wl = tmp_path / "wl.txt"
        wl.write_text("sun\nshine\n", encoding="utf-8")
        target = hashlib.md5(b"sunshine").hexdigest()
        out = run(capsys, "combine", "--wordlist", str(wl),
                  "--mode", "combinator", "--hash", target)
        assert "FOUND: 'sunshine'" in out

    def test_hybrid_crack(self, capsys, tmp_path):
        wl = tmp_path / "wl.txt"
        wl.write_text("pass\n", encoding="utf-8")
        target = hashlib.md5(b"pass42").hexdigest()
        out = run(capsys, "combine", "--wordlist", str(wl),
                  "--mode", "hybrid", "--mask", "?d?d", "--hash", target)
        assert "FOUND: 'pass42'" in out

    def test_count_only(self, capsys, tmp_path):
        wl = tmp_path / "wl.txt"
        wl.write_text("a\nb\n", encoding="utf-8")
        out = run(capsys, "combine", "--wordlist", str(wl),
                  "--mode", "combinator")
        assert "generated 4 candidates" in out
