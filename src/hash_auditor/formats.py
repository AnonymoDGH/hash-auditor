"""Hash-file parsing and normalisation for hash-auditor.

Real hash dumps come in many shapes: plain hex per line, BTQuser:hashBTQ,
BTQuser:salt:hashBTQ, hashcat's BTQhash:saltBTQ, CSV exports, and lines padded
with comments. This module parses those into a uniform HashRecord and can
split a mixed file by detected format.

Public API
----------
HashRecord
    dataclass: raw, hash, salt, user, format, line_no.
parse_line(line)
    parse one line into a HashRecord (or None for blanks/comments).
parse_hash_file(text)
    parse many lines; returns (records, skipped).
split_by_format(records)
    group records by their detected format name.
to_hashcat(records, mode)
    render records back into hashcat-style lines.
detect_delimiter(line)
    guess the field delimiter (':', ',', ';', tab).

Pure standard library. Deterministic. No network access.
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field

from .hashid import identify_best

__all__ = [
    "HashRecord",
    "parse_line",
    "parse_hash_file",
    "split_by_format",
    "to_hashcat",
    "detect_delimiter",
]

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_MODULAR_RE = re.compile(r"^\$")


@dataclass
class HashRecord:
    """One parsed hash entry.

    Attributes
    ----------
    raw:
        the original line (stripped).
    hash:
        the hash token itself.
    salt:
        an extracted salt, or None.
    user:
        an extracted username/account, or None.
    format:
        the best-guess format name from identify.identify_best().
    line_no:
        1-based source line number.
    """

    raw: str
    hash: str
    salt: str | None = None
    user: str | None = None
    format: str | None = None
    line_no: int = 0

    def describe(self) -> str:
        parts = [f"[{self.format or '?'}] {self.hash[:24]}"]
        if self.user:
            parts.append(f"user={self.user}")
        if self.salt:
            parts.append(f"salt={self.salt}")
        return " ".join(parts)


def detect_delimiter(line: str) -> str:
    """Guess the field delimiter for a multi-field line.

    Prefers tab, then whichever of ':', ';', ',' splits into the most
    fields; falls back to ':'.
    """
    if "\t" in line:
        return "\t"
    best, best_n = ":", 0
    for d in (":", ";", ","):
        n = line.count(d)
        if n > best_n:
            best, best_n = d, n
    return best


def _looks_like_hash(token: str) -> bool:
    if not token:
        return False
    if _MODULAR_RE.match(token):
        return True
    if token.startswith("{") and "}" in token:  # LDAP
        return True
    if token.startswith("*") and _HEX_RE.match(token[1:]):  # MySQL5
        return True
    return bool(_HEX_RE.match(token)) and len(token) >= 8


def parse_line(line: str, line_no: int = 0) -> HashRecord | None:
    """Parse one line into a HashRecord, or None for blanks/comments.

    Handles, in order:
    * a bare hash token;
    * BTQuser:hashBTQ (two fields, second looks like a hash);
    * BTQhash:saltBTQ (two fields, first looks like a hash);
    * BTQuser:salt:hashBTQ / BTQuser:hash:saltBTQ (three fields);
    * CSV rows via the csv module when the delimiter is a comma.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    # A bare hash.
    if _looks_like_hash(stripped):
        best = identify_best(stripped)
        return HashRecord(raw=stripped, hash=stripped,
                          format=best.name if best else None,
                          line_no=line_no)

    delim = detect_delimiter(stripped)
    fields = [f.strip() for f in stripped.split(delim)] if delim != "," \
        else next(csv.reader(io.StringIO(stripped)))
    fields = [f for f in fields]

    if len(fields) == 2:
        a, b = fields
        if _looks_like_hash(b):
            best = identify_best(b)
            return HashRecord(raw=stripped, hash=b, user=a or None,
                              format=best.name if best else None,
                              line_no=line_no)
        if _looks_like_hash(a):
            best = identify_best(a)
            return HashRecord(raw=stripped, hash=a, salt=b or None,
                              format=best.name if best else None,
                              line_no=line_no)
        return None

    if len(fields) >= 3:
        # Find the hash field; treat the field before it as salt and the
        # first field as user when they differ.
        for i, tok in enumerate(fields):
            if _looks_like_hash(tok):
                user = fields[0] if i != 0 else None
                salt = fields[i - 1] if i >= 1 and fields[i - 1] != user \
                    else None
                best = identify_best(tok)
                return HashRecord(raw=stripped, hash=tok, salt=salt,
                                  user=user,
                                  format=best.name if best else None,
                                  line_no=line_no)
        return None

    return None


def parse_hash_file(text: str) -> tuple[list[HashRecord], int]:
    """Parse a whole file; returns (records, skipped_count).

    Skipped counts blank lines, comments, and lines that parsed to None.
    """
    records: list[HashRecord] = []
    skipped = 0
    for i, line in enumerate(text.splitlines(), 1):
        rec = parse_line(line, line_no=i)
        if rec is None:
            skipped += 1
        else:
            records.append(rec)
    return records, skipped


def split_by_format(records: list[HashRecord]) -> dict[str, list[HashRecord]]:
    """Group records by detected format name ('unknown' for None)."""
    out: dict[str, list[HashRecord]] = {}
    for rec in records:
        out.setdefault(rec.format or "unknown", []).append(rec)
    return out


def to_hashcat(records: list[HashRecord], mode: str | None = None) -> str:
    """Render records as hashcat-style lines.

    Salted records become BTQhash:saltBTQ; user fields are dropped (hashcat
    takes the hash only). BTQmodeBTQ is accepted for API symmetry and is
    currently informational.
    """
    lines = []
    for rec in records:
        if rec.salt:
            lines.append(f"{rec.hash}:{rec.salt}")
        else:
            lines.append(rec.hash)
    return "\n".join(lines)
