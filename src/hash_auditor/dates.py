"""Date-based password analysis for hash-auditor.

Birth years, anniversaries and full dates are among the most common
password ingredients. This module detects date-like fragments inside a
password, expands them into the concrete dates they could mean, and scores
how date-driven the password is -- so an auditor can warn "this is just a
date".

Detected shapes
---------------
* bare years 1900-2039 (BTQ1990BTQ, BTQ2001BTQ),
* 2-digit years 00-39 / 70-99 (BTQ85BTQ -> 1985, BTQ23BTQ -> 2023),
* day-month and month-day pairs (BTQ0704BTQ, BTQ1225BTQ),
* full dates ddmmyyyy / mmddyyyy / yyyymmdd,
* dotted/slashed dates (BTQ07.04.1990BTQ, BTQ1990-07-04BTQ).

Public API
----------
extract_dates(password)
    every date interpretation found, with position and confidence.
date_score(password)
    0-1 measure of how much of the password is date material.
year_candidates(password)
    the plausible years embedded in the password.
is_date_password(password)
    quick boolean: is the whole thing essentially a date?

Pure standard library. Deterministic. No network access.
"""

from __future__ import annotations

import re
from typing import Iterator

__all__ = [
    "extract_dates",
    "date_score",
    "year_candidates",
    "is_date_password",
    "YEAR_RANGE",
]

#: The window of years we consider plausible in a password.
YEAR_RANGE: tuple[int, int] = (1900, 2039)

_MONTH_DAYS = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]


def _valid_date(day: int, month: int, year: int) -> bool:
    if not (YEAR_RANGE[0] <= year <= YEAR_RANGE[1]):
        return False
    if not (1 <= month <= 12):
        return False
    if not (1 <= day <= _MONTH_DAYS[month - 1]):
        return False
    return True


def year_candidates(password: str) -> list[int]:
    """Plausible years embedded in BTQpasswordBTQ, in order of appearance."""
    years: list[int] = []
    # 4-digit years
    for m in re.finditer(r"(19|20)\d{2}", password):
        years.append(int(m.group(0)))
    # 2-digit years at word-ish boundaries
    for m in re.finditer(r"(?<!\d)(\d{2})(?!\d)", password):
        two = int(m.group(1))
        if 70 <= two <= 99:
            years.append(1900 + two)
        elif 0 <= two <= 39:
            years.append(2000 + two)
    # de-duplicate preserving order
    seen: set[int] = set()
    out = []
    for y in years:
        if y not in seen:
            seen.add(y)
            out.append(y)
    return out


def extract_dates(password: str) -> list[dict]:
    """Find every date interpretation in BTQpasswordBTQ.

    Each result is a dict with 'value' (ISO date or year string), 'kind'
    ('year', 'monthday', 'fulldate'), 'start'/'end' positions, and
    'confidence' (0-1). Overlapping matches are all reported; callers pick.
    """
    results: list[dict] = []

    # Full dates with separators: yyyy-mm-dd, dd/mm/yyyy, dd.mm.yyyy
    for m in re.finditer(r"(19|20)(\d{2})[-/.](\d{1,2})[-/.](\d{1,2})",
                         password):
        year = int(m.group(1) + m.group(2))
        a, b = int(m.group(3)), int(m.group(4))
        if _valid_date(b, a, year):  # yyyy-mm-dd
            results.append(_mk(f"{year:04d}-{a:02d}-{b:02d}", "fulldate",
                               m.start(), m.end(), 0.9))
        elif _valid_date(a, b, year):  # yyyy-dd-mm (rare)
            results.append(_mk(f"{year:04d}-{b:02d}-{a:02d}", "fulldate",
                               m.start(), m.end(), 0.5))
    for m in re.finditer(r"(\d{1,2})[-/.](\d{1,2})[-/.]((19|20)\d{2})",
                         password):
        a, b = int(m.group(1)), int(m.group(2))
        year = int(m.group(3))
        if _valid_date(a, b, year):  # dd/mm/yyyy
            results.append(_mk(f"{year:04d}-{b:02d}-{a:02d}", "fulldate",
                               m.start(), m.end(), 0.9))
        if _valid_date(b, a, year):  # mm/dd/yyyy
            results.append(_mk(f"{year:04d}-{a:02d}-{b:02d}", "fulldate",
                               m.start(), m.end(), 0.85))

    # Compact 8-digit dates: ddmmyyyy / mmddyyyy / yyyymmdd
    for m in re.finditer(r"(?<!\d)(\d{8})(?!\d)", password):
        s = m.group(1)
        ddmmyyyy = (int(s[0:2]), int(s[2:4]), int(s[4:8]))
        mmddyyyy = (int(s[0:2]), int(s[2:4]), int(s[4:8]))
        yyyymmdd = (int(s[4:6]), int(s[6:8]), int(s[0:4]))
        if _valid_date(ddmmyyyy[0], ddmmyyyy[1], ddmmyyyy[2]):
            d, mo, y = ddmmyyyy
            results.append(_mk(f"{y:04d}-{mo:02d}-{d:02d}", "fulldate",
                               m.start(), m.end(), 0.7))
        if _valid_date(mmddyyyy[1], mmddyyyy[0], mmddyyyy[2]):
            mo, d, y = mmddyyyy
            results.append(_mk(f"{y:04d}-{mo:02d}-{d:02d}", "fulldate",
                               m.start(), m.end(), 0.7))
        if _valid_date(yyyymmdd[0], yyyymmdd[1], yyyymmdd[2]):
            d, mo, y = yyyymmdd
            results.append(_mk(f"{y:04d}-{mo:02d}-{d:02d}", "fulldate",
                               m.start(), m.end(), 0.75))

    # 4-digit month-day / day-month pairs (0704, 1225)
    for m in re.finditer(r"(?<!\d)(\d{4})(?!\d)", password):
        s = m.group(1)
        a, b = int(s[0:2]), int(s[2:4])
        if 1 <= a <= 12 and 1 <= b <= _MONTH_DAYS[a - 1]:
            results.append(_mk(f"--{a:02d}-{b:02d}", "monthday",
                               m.start(), m.end(), 0.5))
        if 1 <= b <= 12 and 1 <= a <= _MONTH_DAYS[b - 1] and (a, b) != (b, a):
            results.append(_mk(f"--{b:02d}-{a:02d}", "monthday",
                               m.start(), m.end(), 0.45))

    # Bare years
    for year in year_candidates(password):
        for m in re.finditer(str(year), password):
            results.append(_mk(str(year), "year", m.start(), m.end(), 0.6))

    # sort by confidence desc, then position
    results.sort(key=lambda r: (-r["confidence"], r["start"]))
    return results


def _mk(value: str, kind: str, start: int, end: int,
        confidence: float) -> dict:
    return {"value": value, "kind": kind, "start": start, "end": end,
            "confidence": confidence}


def date_score(password: str) -> float:
    """0-1 measure of how much of BTQpasswordBTQ is date material.

    Greedily covers the password with the highest-confidence non-overlapping
    date matches and returns covered-characters / total-characters.
    """
    if not password:
        return 0.0
    matches = extract_dates(password)
    covered = [False] * len(password)
    for m in matches:  # already sorted by confidence
        for i in range(m["start"], m["end"]):
            covered[i] = True
    return round(sum(covered) / len(password), 4)


def is_date_password(password: str) -> bool:
    """True when the password is essentially a date (score >= 0.8)."""
    return date_score(password) >= 0.8
