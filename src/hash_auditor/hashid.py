"""Hash type identification for hash-auditor.

Where `Thash_auditor.identify` guesses an algorithm from digest length
alone, this module runs a battery of structural heuristics -- length, charset,
delimiters, parameter blocks -- and returns a *ranked* list of candidates,
each with a confidence score and the reasons it was proposed.

Recognised families
-------------------
* raw hex digests: crc32, md5, ntlm, sha1, sha224, sha256, sha384, sha512,
  sha3 variants, blake2, mysql5 (`*` + uppercase hex), mysql old (16 hex);
* modular crypt formats: bcrypt, md5crypt (`$1$`), apr1, sha256crypt
  (`$5$`), sha512crypt (`$6$`), yescrypt (`$y$`), sunmd5;
* KDF formats: argon2, scrypt (both spellings), pbkdf2 (`$pbkdf2-*$`),
  Django (`pbkdf2_sha256$...`), PHPS (`$P$` / `$H$`);
* directory-server formats: LDAP `{SCHEME}base64`;
* legacy formats: Unix DES crypt (13 chars), Oracle 10g, base64 digests.

Public API
----------
HashCandidate
    dataclass: `name`, `confidence` (0.0-1.0), `reasons` (list[str]).
identify_hash(text) -> list[HashCandidate]
    all plausible candidates, best first.
identify_best(text) -> HashCandidate | None
    the top candidate, or None when nothing matches.
identify_many(lines) -> list[tuple[str, list[HashCandidate]]]
    batch identification, skipping blanks and comments.
format_candidates(candidates) -> str
    a human-readable rendering of a candidate list.

Pure standard library. Deterministic. No network access.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

__all__ = [
    "HashCandidate",
    "identify_hash",
    "identify_best",
    "identify_many",
    "format_candidates",
    "HEX_DIGEST_LENGTHS",
]

#: Raw hex digest length -> candidate names, most common first.
HEX_DIGEST_LENGTHS: dict[int, tuple[str, ...]] = {
    8: ("crc32",),
    16: ("mysql323", "oracle10g"),
    32: ("md5", "ntlm", "md4"),
    40: ("sha1", "ripemd160"),
    56: ("sha224", "sha3-224"),
    64: ("sha256", "sha3-256", "blake2s"),
    96: ("sha384", "sha3-384"),
    128: ("sha512", "sha3-512", "blake2b", "whirlpool"),
}

#: Base64 digest length (with padding) -> candidate names.
_B64_DIGEST_LENGTHS: dict[int, tuple[str, ...]] = {
    24: ("md5-base64",),
    28: ("sha1-base64",),
    44: ("sha256-base64",),
    88: ("sha512-base64",),
}

_HEX_RE = re.compile(r"^[0-9a-f]+$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_CRYPT_B64 = r"[./0-9A-Za-z]"


@dataclass(frozen=True)
class HashCandidate:
    """One identification hypothesis for a hash string.

    Attributes
    ----------
    name:
        Machine-readable format name, e.g. `bcrypt` or `sha256`.
    confidence:
        0.0-1.0. Structural matches (delimiters + parameter blocks) score
        0.9 or higher; length-only matches share a smaller pool.
    reasons:
        Human-readable evidence for the hypothesis.
    """

    name: str
    confidence: float
    reasons: tuple[str, ...] = field(default_factory=tuple)

    def describe(self) -> str:
        """One-line summary: `name (confidence: 0.95) -- reason; reason`."""
        return f"{self.name} (confidence: {self.confidence:.2f}) -- " + \
            "; ".join(self.reasons)


def _is_hex(text: str) -> bool:
    return bool(_HEX_RE.fullmatch(text))


def _is_b64(text: str) -> bool:
    return bool(_B64_RE.fullmatch(text)) and len(text) % 4 == 0


def _hex_candidates(text: str) -> list[HashCandidate]:
    """Candidates for a raw lowercase-hex string, by length."""
    names = HEX_DIGEST_LENGTHS.get(len(text))
    if not names:
        return []
    # The confidence pool shrinks as ambiguity grows: a 32-hex string is
    # most often md5, sometimes ntlm, rarely md4.
    pool = 0.85 if len(names) == 1 else 0.75
    step = pool / len(names)
    out: list[HashCandidate] = []
    for rank, name in enumerate(names):
        confidence = round(pool - rank * step, 3)
        out.append(HashCandidate(
            name, confidence,
            (f"{len(text)} lowercase hex characters",
             f"length matches the {name} digest size"),
        ))
    return out


def _b64_candidates(text: str) -> list[HashCandidate]:
    """Candidates for a raw base64 string whose length matches a digest."""
    names = _B64_DIGEST_LENGTHS.get(len(text))
    if not names:
        return []
    return [HashCandidate(
        names[0], 0.55,
        (f"{len(text)} base64 characters",
         f"decodes to a {len(text) * 3 // 4}-byte digest"),
    )]


def _struct(name: str, confidence: float, *reasons: str) -> HashCandidate:
    return HashCandidate(name, confidence, reasons)


def identify_hash(text: str) -> list[HashCandidate]:
    """Identify a hash string; return all plausible candidates, best first.

    The input is stripped of surrounding whitespace and surrounding single
    or double quotes. An empty input yields an empty list. Candidates are
    sorted by descending confidence, ties broken by name for determinism.
    """
    text = text.strip().strip("'\"")
    if not text:
        return []

    candidates: list[HashCandidate] = []

    # --- modular crypt / KDF formats, recognised by their $-prefix --------
    if text.startswith("$"):
        candidates.extend(_identify_dollar(text))

    # --- Django: pbkdf2_sha256$iterations$salt$hash (no leading $) --------
    m = re.fullmatch(r"(pbkdf2_sha256|md5|sha1|bcrypt|argon2)\$([^$]*)\$"
                     r"([^$]*)\$([A-Za-z0-9+/=]+)", text)
    if m:
        scheme = m.group(1)
        iters = m.group(2)
        reasons = [f"Django '{scheme}' prefix"]
        if iters.isdigit():
            reasons.append(f"{iters} iterations")
        candidates.append(_struct(f"django-{scheme}", 0.96, *reasons))

    # --- LDAP scheme prefix ----------------------------------------------
    m = re.fullmatch(r"\{(MD5|SMD5|SHA|SSHA|SHA256|SHA512|CRYPT)\}"
                     r"([A-Za-z0-9+/=]+)", text)
    if m:
        scheme = m.group(1)
        body = m.group(2)
        candidates.append(_struct(
            f"ldap-{scheme.lower()}", 0.93,
            f"LDAP {{{scheme}}} scheme prefix",
            f"{len(body)} base64 characters of digest data",
        ))

    # --- MySQL 5.x: '*' + 40 uppercase hex (SHA1 of SHA1) -----------------
    if re.fullmatch(r"\*[0-9A-F]{40}", text):
        candidates.append(_struct(
            "mysql5", 0.95,
            "leading '*' with 40 uppercase hex characters",
            "matches MySQL PASSWORD() output",
        ))

    # --- bcrypt ------------------------------------------------------------
    m = re.fullmatch(r"\$2([abxy])\$([0-9]{2})\$(" + _CRYPT_B64 + "{53})", text)
    if m:
        cost = int(m.group(2))
        reasons = [f"bcrypt revision '{m.group(1)}'", f"cost factor {cost}"]
        conf = 0.97 if 4 <= cost <= 31 else 0.80
        if cost > 31:
            reasons.append("cost above 31 is unusual")
        candidates.append(_struct("bcrypt", conf, *reasons))

    # --- raw hex ------------------------------------------------------------
    lower = text.lower()
    if _is_hex(lower):
        candidates.extend(_hex_candidates(lower))
    elif _is_b64(text):
        candidates.extend(_b64_candidates(text))

    # --- Unix DES crypt: exactly 13 chars from the crypt alphabet ----------
    if re.fullmatch(_CRYPT_B64 + "{13}", text) and not _is_hex(lower):
        candidates.append(_struct(
            "des-crypt", 0.6,
            "13 characters from the traditional crypt alphabet",
            "first two characters encode the salt",
        ))

    candidates.sort(key=lambda c: (-c.confidence, c.name))
    return candidates


def _identify_dollar(text: str) -> list[HashCandidate]:
    """Heuristics for strings starting with `$`."""
    out: list[HashCandidate] = []

    m = re.fullmatch(r"\$argon2(id|i|d)\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$"
                     r"([A-Za-z0-9+/=]+)\$([A-Za-z0-9+/=]+)", text)
    if m:
        out.append(_struct(
            f"argon2{m.group(1)}", 0.98,
            f"argon2 variant '{m.group(1)}'",
            f"version {m.group(2)}",
            f"m={m.group(3)}, t={m.group(4)}, p={m.group(5)} parameters",
        ))
        return out

    # scrypt, hashcat spelling: SCRYPT:N:r:p:salt:hash
    m = re.fullmatch(r"SCRYPT:(\d+):(\d+):(\d+):([A-Za-z0-9+/=]+):"
                     r"([A-Za-z0-9+/=]+)", text[1:])
    if m:
        out.append(_struct(
            "scrypt", 0.97,
            f"scrypt parameters N={m.group(1)} r={m.group(2)} p={m.group(3)}",
            "hashcat SCRYPT: format",
        ))
        return out

    # scrypt, modular-crypt spelling: $s0$params$salt$hash
    m = re.fullmatch(r"\$s0\$([0-9a-f]+)\$([A-Za-z0-9+/=]+)\$"
                     r"([A-Za-z0-9+/=]+)", text)
    if m:
        out.append(_struct(
            "scrypt", 0.95,
            "modular-crypt $s0$ prefix",
            f"packed parameter block of {len(m.group(1))} hex digits",
        ))
        return out

    # pbkdf2, hashcat/passlib spelling: $pbkdf2-sha256$iter$salt$hash
    m = re.fullmatch(r"\$pbkdf2-(sha1|sha224|sha256|sha512)\$(\d+)\$"
                     r"([A-Za-z0-9+/=.]+)\$([A-Za-z0-9+/=.]+)", text)
    if m:
        out.append(_struct(
            f"pbkdf2-{m.group(1)}", 0.97,
            f"PBKDF2-HMAC-{m.group(1).upper()}",
            f"{m.group(2)} iterations",
        ))
        return out

    # md5crypt / apr1: $1$salt$22-crypt-chars
    m = re.fullmatch(r"\$(1|apr1)\$([^$]{0,8})\$(" + _CRYPT_B64 + "{22})", text)
    if m:
        name = "md5crypt" if m.group(1) == "1" else "apr1crypt"
        out.append(_struct(
            name, 0.96,
            f"${m.group(1)}$ prefix",
            f"{len(m.group(2))}-character salt",
            "22-character crypt-encoded digest",
        ))
        return out

    # sha256crypt / sha512crypt: $5$ / $6$, optional rounds=
    m = re.fullmatch(r"\$(5|6)\$(rounds=(\d+)\$)?([^$]{0,16})\$(" +
                     _CRYPT_B64 + r"{43,86})", text)
    if m:
        want = 43 if m.group(1) == "5" else 86
        if len(m.group(5)) == want:
            name = "sha256crypt" if m.group(1) == "5" else "sha512crypt"
            reasons = [f"${m.group(1)}$ prefix"]
            if m.group(3):
                reasons.append(f"explicit rounds={m.group(3)}")
            reasons.append(f"{len(m.group(4))}-character salt")
            out.append(_struct(name, 0.96, *reasons))
            return out

    # yescrypt: $y$params$salt$hash
    m = re.fullmatch(r"\$y\$([^$]+)\$([^$]+)\$([./0-9A-Za-z]+)", text)
    if m:
        out.append(_struct(
            "yescrypt", 0.94,
            "$y$ prefix",
            f"parameter block {m.group(1)!r}",
        ))
        return out

    # PHPASS / WordPress: $P$ or $H$ + iteration char + salt + digest
    m = re.fullmatch(r"\$[PH]\$([./0-9A-Za-z])(" + _CRYPT_B64 + "{8})(" +
                     _CRYPT_B64 + "{22})", text)
    if m:
        out.append(_struct(
            "phpass", 0.95,
            f"${text[1]}$ prefix (PHPASS/WordPress)",
            f"iteration character {m.group(1)!r}",
            "8-character salt + 22-character digest",
        ))
        return out

    # sunmd5: $md5$rounds=N$salt$hash
    if re.fullmatch(r"\$md5\$rounds=\d+\$[^$]+\$[./0-9A-Za-z]{22}", text):
        out.append(_struct(
            "sunmd5", 0.93,
            "$md5$rounds= prefix (Sun MD5)",
            "22-character crypt-encoded digest",
        ))
        return out

    return out


def identify_best(text: str) -> HashCandidate | None:
    """Return the highest-confidence candidate, or None."""
    candidates = identify_hash(text)
    return candidates[0] if candidates else None


def identify_many(lines: list[str] | str) -> list[tuple[str, list[HashCandidate]]]:
    """Identify every hash in a batch of lines.

    Blank lines and `#` comments are skipped. Returns `(line, candidates)`
    pairs in input order; lines with no hypothesis get an empty list.
    """
    if isinstance(lines, str):
        lines = lines.splitlines()
    out: list[tuple[str, list[HashCandidate]]] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append((line, identify_hash(line)))
    return out


def format_candidates(candidates: list[HashCandidate]) -> str:
    """Render a candidate list as aligned human-readable lines."""
    if not candidates:
        return "[!] no matching hash format"
    lines = []
    for rank, cand in enumerate(candidates, 1):
        lines.append(f"{rank}. {cand.describe()}")
    return "\n".join(lines)
