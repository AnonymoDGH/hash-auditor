"""Hash Auditor — measure your passwords, then crack your own hashes.

Check a password against known-bad patterns and weak lists, compute hashes in
common formats, identify a hash by its length, and brute-force your own hashes
with a wordlist. Audit first. Cracking is for what you own.

Pure standard library.
"""

from __future__ import annotations

import hashlib
import re
import string

# The usual suspects — every one of these is a terrible password.
WEAK = {
    "password", "password1", "password123", "123456", "123456789", "12345678",
    "1234567", "1234567890", "qwerty", "qwerty123", "abc123", "111111",
    "iloveyou", "admin", "letmein", "monkey", "dragon", "sunshine", "princess",
    "football", "baseball", "welcome", "trustno1", "shadow", "master", "login",
    "passw0rd", "admin123", "root", "toor", "000000", "696969", "654321",
    "666666", "1q2w3e4r", "qazwsx", "zaq12wsx", "p@ssw0rd", "pass", "test",
    "test123", "secret", "changeme", "hello", "hello123", "letmein1",
}

ALGOS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}

HASH_LENGTHS = {
    32: "md5",
    40: "sha1",
    56: "sha224",
    64: "sha256",
    96: "sha384",
    128: "sha512",
}


def hash_text(password: str, algo: str = "sha256") -> str:
    if algo not in ALGOS:
        raise ValueError(f"Unknown algorithm: {algo} (use {', '.join(ALGOS)})")
    return ALGOS[algo](password.encode("utf-8")).hexdigest()


def identify(hash_hex: str) -> str | None:
    return HASH_LENGTHS.get(len(hash_hex.strip().lower()))


def entropy_bits(password: str) -> float:
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 33
    if pool == 0:
        return 0.0
    # Deduplicate: pool is the per-char alphabet, so entropy = n * log2(pool)
    return len(password) * (pool.bit_length() - 1 if (pool & (pool - 1)) == 0
                            else __import__("math").log2(pool))


def analyze(password: str) -> dict:
    flags: list[str] = []
    lower = password.lower()

    if len(password) < 8:
        flags.append("too short (< 8)")
    if len(password) > 64:
        flags.append("absurdly long")
    if lower in WEAK:
        flags.append("in the known-weak list")
    if len(set(password)) <= len(password) * 0.4:
        flags.append("too few unique characters")
    if re.fullmatch(r"(\d)\1*", password):
        flags.append("all the same digit")
    if re.search(r"(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)",
                  lower):
        flags.append("contains an alphabetical sequence")
    if re.fullmatch(r"\d{4,8}", password):
        flags.append("digits only — a PIN, not a password")
    if re.search(r"(19|20)\d{2}", password):
        flags.append("contains a year")

    classes = sum(bool(c) for c in (
        re.search(r"[a-z]", password),
        re.search(r"[A-Z]", password),
        re.search(r"[0-9]", password),
        re.search(r"[^a-zA-Z0-9]", password),
    ))

    return {
        "length": len(password),
        "character_classes": classes,
        "unique_ratio": round(len(set(password)) / max(len(password), 1), 2),
        "entropy_bits": round(entropy_bits(password), 1),
        "flags": flags,
        "verdict": "weak" if (flags or len(password) < 8) else
                   ("ok" if len(password) >= 12 else "acceptable"),
    }


def crack(hash_hex: str, wordlist: str | list[str], algo: str | None = None,
          mutate: bool = True) -> str | None:
    """Find a password for `hash_hex`. Returns the match or None."""
    algo = algo or identify(hash_hex) or "md5"
    target = hash_hex.strip().lower()
    words = wordlist if isinstance(wordlist, list) else \
        (line.strip() for line in open(wordlist, encoding="utf-8", errors="replace"))

    for word in words:
        candidates = [word]
        if mutate:
            cap = word.capitalize()
            candidates += [cap, word.upper(),
                           word + "1", word + "123", word + "!",
                           cap + "1", cap + "123", cap + "!", "!" + word]
        for cand in candidates:
            if hash_text(cand, algo) == target:
                return cand
    return None


def audit_file(lines: str) -> list[dict]:
    return [analyze(line.strip()) for line in lines.splitlines() if line.strip()]


__all__ = ["WEAK", "ALGOS", "HASH_LENGTHS", "hash_text", "identify",
           "entropy_bits", "analyze", "crack", "audit_file",
           # submodules (imported last: several of them import this package)
           "hashes", "wordlists", "rules", "zxcvbn_lite", "hashid",
           "rainbow", "breach", "policy", "generator", "report", "mask",
           "stats", "similarity", "entropy", "history", "formats",
           "combinator", "pcfg", "brute", "leet", "keyboard", "dates",
           "audit", "wordlist_tools", "fingerprint", "checksums"]

__version__ = "0.2.0"

# Submodule imports come after the core API above because several modules
# (audit, leet, ...) import names from this package at import time.
from . import (  # noqa: E402
    audit,
    breach,
    brute,
    checksums,
    combinator,
    dates,
    entropy,
    fingerprint,
    formats,
    generator,
    hashid,
    hashes,
    history,
    keyboard,
    leet,
    mask,
    pcfg,
    policy,
    rainbow,
    report,
    rules,
    similarity,
    stats,
    wordlist_tools,
    wordlists,
    zxcvbn_lite,
)
