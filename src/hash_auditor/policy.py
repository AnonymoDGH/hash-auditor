"""Password policy engine for hash-auditor.

A configurable, declarative policy checker. A Policy is a bag of named
rules with parameters; check() runs every rule against a password and
returns a structured report of violations. Unlike the heuristic flags in
hash_auditor.analyze(), every rule here is individually tunable, and the
engine can grade whole wordlists against a policy.

Built-in rules
--------------
min_length / max_length
    length bounds.
min_classes
    require N of {lower, upper, digit, symbol}.
require_each
    require every character class present.
banned
    reject exact passwords (case-insensitive) from a ban list.
banned_substrings
    reject passwords containing any banned fragment.
max_repeat
    no run of the same character longer than N.
max_sequence
    no ascending/descending alphabet or digit run longer than N.
max_keyboard_walk
    no QWERTY adjacency walk longer than N.
min_unique_ratio
    distinct characters / length must be at least R.
no_whitespace
    reject spaces/tabs/newlines.

Public API
----------
Policy
    dataclass holding rule parameters; from_dict()/to_dict() round-trip.
Violation
    dataclass: rule, message, severity ('error' | 'warning').
check_password(password, policy) -> PolicyReport
PolicyReport
    violations list, passed bool, score 0-100, grade A-F.
grade_wordlist(words, policy) -> dict
    aggregate pass/fail statistics over many passwords.
PRESETS
    named policies: 'basic', 'corporate', 'nist' (NIST SP 800-63B-flavoured).

Pure standard library. Deterministic. No network access.
"""

from __future__ import annotations

import re
import string
from dataclasses import dataclass, field, asdict
from typing import Iterable

__all__ = [
    "Policy",
    "Violation",
    "PolicyReport",
    "check_password",
    "grade_wordlist",
    "PRESETS",
    "char_classes",
]

_QWERTY_ROWS = [
    "1234567890",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]


def _adjacent(a: str, b: str) -> bool:
    """True when two keys sit next to each other on a QWERTY layout."""
    a, b = a.lower(), b.lower()
    for row in _QWERTY_ROWS:
        ia, ib = row.find(a), row.find(b)
        if ia != -1 and ib != -1 and abs(ia - ib) == 1:
            return True
    # vertical-ish neighbours between staggered rows
    pairs = {
        ("q", "a"), ("w", "a"), ("w", "s"), ("e", "s"), ("e", "d"),
        ("r", "d"), ("r", "f"), ("t", "f"), ("t", "g"), ("y", "g"),
        ("y", "h"), ("u", "h"), ("u", "j"), ("i", "j"), ("i", "k"),
        ("o", "k"), ("o", "l"), ("p", "l"),
        ("a", "z"), ("s", "z"), ("s", "x"), ("d", "x"), ("d", "c"),
        ("f", "c"), ("f", "v"), ("g", "v"), ("g", "b"), ("h", "b"),
        ("h", "n"), ("j", "n"), ("j", "m"), ("k", "m"),
    }
    return (a, b) in pairs or (b, a) in pairs


def char_classes(password: str) -> dict[str, bool]:
    """Which of the four character classes appear in BTQpasswordBTQ."""
    return {
        "lower": any(c.islower() for c in password),
        "upper": any(c.isupper() for c in password),
        "digit": any(c.isdigit() for c in password),
        "symbol": any(not c.isalnum() for c in password),
    }


@dataclass
class Violation:
    """One policy rule failure."""

    rule: str
    message: str
    severity: str = "error"  # 'error' fails the password; 'warning' does not

    def describe(self) -> str:
        mark = "[-]" if self.severity == "error" else "[~]"
        return f"{mark} {self.rule}: {self.message}"


@dataclass
class Policy:
    """Declarative password policy; every field maps to one rule.

    Set a numeric bound to None (or 0 where noted) to disable that rule.
    """

    min_length: int = 8
    max_length: int | None = 64
    min_classes: int = 1
    require_each: bool = False
    banned: tuple[str, ...] = ()
    banned_substrings: tuple[str, ...] = ()
    max_repeat: int | None = 3
    max_sequence: int | None = 4
    max_keyboard_walk: int | None = 4
    min_unique_ratio: float = 0.0
    no_whitespace: bool = True

    def to_dict(self) -> dict:
        """JSON-friendly representation (tuples become lists)."""
        data = asdict(self)
        data["banned"] = list(self.banned)
        data["banned_substrings"] = list(self.banned_substrings)
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        """Build a Policy from a dict; unknown keys raise TypeError."""
        kwargs = dict(data)
        for key in ("banned", "banned_substrings"):
            if key in kwargs:
                kwargs[key] = tuple(kwargs[key])
        return cls(**kwargs)


@dataclass
class PolicyReport:
    """Result of checking one password against a policy."""

    password_length: int
    violations: list[Violation] = field(default_factory=list)

    @property
    def errors(self) -> list[Violation]:
        return [v for v in self.violations if v.severity == "error"]

    @property
    def warnings(self) -> list[Violation]:
        return [v for v in self.violations if v.severity == "warning"]

    @property
    def passed(self) -> bool:
        return not self.errors

    @property
    def score(self) -> int:
        """0-100: start at 100, -20 per error, -5 per warning, floor 0."""
        return max(0, 100 - 20 * len(self.errors) - 5 * len(self.warnings))

    @property
    def grade(self) -> str:
        """Letter grade for the score: A>=90, B>=75, C>=60, D>=40, else F."""
        s = self.score
        for grade, floor in (("A", 90), ("B", 75), ("C", 60), ("D", 40)):
            if s >= floor:
                return grade
        return "F"

    def to_dict(self) -> dict:
        return {
            "password_length": self.password_length,
            "passed": self.passed,
            "score": self.score,
            "grade": self.grade,
            "violations": [
                {"rule": v.rule, "message": v.message, "severity": v.severity}
                for v in self.violations
            ],
        }


def _longest_repeat(password: str) -> int:
    best = run = 0
    prev = None
    for ch in password:
        run = run + 1 if ch == prev else 1
        prev = ch
        best = max(best, run)
    return best


def _longest_sequence(password: str) -> int:
    """Longest ascending/descending run of consecutive codepoints among
    letters (case-insensitive) or digits."""
    lower = password.lower()
    best = run_up = run_down = 0
    for i in range(1, len(lower)):
        a, b = lower[i - 1], lower[i]
        if a.isalnum() and b.isalnum() and ord(b) - ord(a) == 1:
            run_up += 1
        else:
            run_up = 0
        if a.isalnum() and b.isalnum() and ord(a) - ord(b) == 1:
            run_down += 1
        else:
            run_down = 0
        best = max(best, run_up + 1, run_down + 1)
    return best if len(lower) else 0


def _longest_keyboard_walk(password: str) -> int:
    best = run = 0
    for i in range(1, len(password)):
        if _adjacent(password[i - 1], password[i]):
            run += 1
        else:
            run = 0
        best = max(best, run + 1)
    return best if len(password) else 0


def check_password(password: str, policy: Policy | None = None) -> PolicyReport:
    """Check one password; returns a PolicyReport with every violation."""
    policy = policy or Policy()
    report = PolicyReport(password_length=len(password))
    v = report.violations

    if len(password) < policy.min_length:
        v.append(Violation("min_length",
                           f"shorter than {policy.min_length} characters"))
    if policy.max_length is not None and len(password) > policy.max_length:
        v.append(Violation("max_length",
                           f"longer than {policy.max_length} characters"))

    classes = char_classes(password)
    present = sum(classes.values())
    if present < policy.min_classes:
        v.append(Violation("min_classes",
                           f"uses {present} character class(es), "
                           f"needs {policy.min_classes}"))
    if policy.require_each:
        missing = [name for name, ok in classes.items() if not ok]
        if missing:
            v.append(Violation("require_each",
                               "missing class(es): " + ", ".join(missing)))

    if password.lower() in {b.lower() for b in policy.banned}:
        v.append(Violation("banned", "password is on the ban list"))
    lowered = password.lower()
    for frag in policy.banned_substrings:
        if frag and frag.lower() in lowered:
            v.append(Violation("banned_substrings",
                               f"contains banned fragment {frag!r}"))

    if policy.max_repeat is not None:
        run = _longest_repeat(password)
        if run > policy.max_repeat:
            v.append(Violation("max_repeat",
                               f"repeats one character {run} times "
                               f"(max {policy.max_repeat})"))

    if policy.max_sequence is not None:
        seq = _longest_sequence(password)
        if seq > policy.max_sequence:
            v.append(Violation("max_sequence",
                               f"contains a {seq}-step sequence "
                               f"(max {policy.max_sequence})"))

    if policy.max_keyboard_walk is not None:
        walk = _longest_keyboard_walk(password)
        if walk > policy.max_keyboard_walk:
            v.append(Violation("max_keyboard_walk",
                               f"keyboard walk of {walk} keys "
                               f"(max {policy.max_keyboard_walk})"))

    if policy.min_unique_ratio > 0 and password:
        ratio = len(set(password)) / len(password)
        if ratio < policy.min_unique_ratio:
            v.append(Violation("min_unique_ratio",
                               f"unique ratio {ratio:.2f} below "
                               f"{policy.min_unique_ratio:.2f}"))

    if policy.no_whitespace and re.search(r"\s", password):
        v.append(Violation("no_whitespace", "contains whitespace"))

    return report


def grade_wordlist(words: Iterable[str], policy: Policy | None = None) -> dict:
    """Grade many passwords against a policy.

    Returns aggregate statistics: total, passed, failed, pass_rate,
    average score, grade histogram, and the worst offenders (lowest scores,
    ties broken alphabetically, capped at 10).
    """
    policy = policy or Policy()
    total = passed = 0
    total_score = 0
    grades = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
    rows: list[tuple[int, str]] = []

    for word in words:
        rep = check_password(word, policy)
        total += 1
        total_score += rep.score
        grades[rep.grade] += 1
        if rep.passed:
            passed += 1
        rows.append((rep.score, word))

    rows.sort(key=lambda r: (r[0], r[1]))
    return {
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "pass_rate": round(passed / total, 4) if total else 0.0,
        "average_score": round(total_score / total, 2) if total else 0.0,
        "grades": grades,
        "worst": [w for _, w in rows[:10]],
    }


#: Named preset policies.
PRESETS: dict[str, Policy] = {
    "basic": Policy(),
    "corporate": Policy(
        min_length=10,
        min_classes=3,
        require_each=False,
        banned=("password", "password1", "welcome1", "changeme",
                "letmein", "admin123", "qwerty123"),
        banned_substrings=("password", "company", "admin"),
        max_repeat=2,
        max_sequence=3,
        max_keyboard_walk=3,
        min_unique_ratio=0.5,
    ),
    "nist": Policy(
        # NIST SP 800-63B: length over composition; check against ban lists.
        min_length=8,
        max_length=None,
        min_classes=1,
        require_each=False,
        banned=("password", "123456", "12345678", "qwerty", "letmein"),
        max_repeat=None,
        max_sequence=None,
        max_keyboard_walk=None,
        min_unique_ratio=0.0,
        no_whitespace=False,
    ),
}
