"""Hashcat-style mutation rule engine for hash-auditor.

Implements a compact, well-tested subset of the hashcat rule language. A rule
is a string of single-character (or two-character) operations applied left to
right to a word. Supported operations:

=====  =====================================================
Op     Meaning
=====  =====================================================
'':'   identity -- emit the word unchanged
'l'    lowercase the whole word
'u'    uppercase the whole word
'c'    capitalize first letter, lowercase the rest
'C'    uppercase first letter, lowercase the rest (alias of c)
't'    toggle the case of every letter
'T' N  toggle the case of the character at position N
'd'    duplicate the word (abc -> abcabc)
'r'    reverse the word
'$' X  append character X
'^' X  prepend character X
'x' N  keep only the first N characters (truncate)
'o' N  drop the first N characters
'z' N  repeat the first character N times, prepended
'y' N  repeat the last character N times, appended
=====  =====================================================

Positions are 0-based. Out-of-range positions are clamped to the word length
rather than raising, matching hashcat's tolerant behaviour on short words.

Public API
----------
apply_rule(word, rule)
    apply one rule string to a word.
apply_rules(word, rules)
    apply many rules to one word, returning a list of candidates.
parse_rule_file(text)
    parse a hashcat-style rule file into a list of rule strings.
RULE_SETS
    dict of named preset rule lists ('basic', 'append-years', 'l33t', 'full').
mutate_stream(words, rules)
    generator yielding every (word x rule) candidate, de-duplicated.
rule_stats(candidates)
    summary statistics over a candidate iterable.

Pure standard library. Deterministic.
"""

from __future__ import annotations

from typing import Iterable, Iterator

__all__ = [
    "apply_rule",
    "apply_rules",
    "parse_rule_file",
    "RULE_SETS",
    "mutate_stream",
    "rule_stats",
    "RuleError",
]


class RuleError(ValueError):
    """Raised when a rule string is malformed."""


# ---------------------------------------------------------------------------
# Core operation helpers.
# ---------------------------------------------------------------------------


def _toggle_char(ch: str) -> str:
    """Swap the case of a single character; non-letters pass through."""
    if ch.islower():
        return ch.upper()
    if ch.isupper():
        return ch.lower()
    return ch


def _toggle_at(word: str, pos: int) -> str:
    """Toggle the case of the character at pos (clamped to word bounds)."""
    if not word:
        return word
    pos = max(0, min(pos, len(word) - 1))
    return word[:pos] + _toggle_char(word[pos]) + word[pos + 1:]


def _clamp_pos(word: str, pos: int) -> int:
    """Clamp a position into [0, len(word)]."""
    return max(0, min(pos, len(word)))


# ---------------------------------------------------------------------------
# Rule application.
# ---------------------------------------------------------------------------


def apply_rule(word: str, rule: str) -> str:
    """Apply a single rule string to word and return the mutated word.

    Operations are applied left to right. Unknown operations raise
    RuleError. Operations that take an argument ('T', '$', '^', 'x', 'o',
    'z', 'y') consume the next character of the rule as their argument.

    Examples
    --------
    >>> apply_rule("abc", ":")
    'abc'
    >>> apply_rule("abc", "u$1")
    'ABC1'
    >>> apply_rule("Password", "l")
    'password'
    """
    out = word
    i = 0
    n = len(rule)
    while i < n:
        op = rule[i]
        if op == ":":
            pass
        elif op == "l":
            out = out.lower()
        elif op == "u":
            out = out.upper()
        elif op in ("c", "C"):
            out = out[:1].upper() + out[1:].lower() if out else out
        elif op == "t":
            out = "".join(_toggle_char(ch) for ch in out)
        elif op == "T":
            i += 1
            if i >= n:
                raise RuleError(f"rule {rule!r}: 'T' needs a position argument")
            out = _toggle_at(out, _digit(rule[i], rule))
        elif op == "d":
            out = out + out
        elif op == "r":
            out = out[::-1]
        elif op == "$":
            i += 1
            if i >= n:
                raise RuleError(f"rule {rule!r}: '$' needs a character argument")
            out = out + rule[i]
        elif op == "^":
            i += 1
            if i >= n:
                raise RuleError(f"rule {rule!r}: '^' needs a character argument")
            out = rule[i] + out
        elif op == "x":
            i += 1
            if i >= n:
                raise RuleError(f"rule {rule!r}: 'x' needs a length argument")
            out = out[: _clamp_pos(out, _digit(rule[i], rule))]
        elif op == "o":
            i += 1
            if i >= n:
                raise RuleError(f"rule {rule!r}: 'o' needs a count argument")
            out = out[_clamp_pos(out, _digit(rule[i], rule)):]
        elif op == "z":
            i += 1
            if i >= n:
                raise RuleError(f"rule {rule!r}: 'z' needs a count argument")
            count = _digit(rule[i], rule)
            out = (out[:1] * count) + out if out else out
        elif op == "y":
            i += 1
            if i >= n:
                raise RuleError(f"rule {rule!r}: 'y' needs a count argument")
            count = _digit(rule[i], rule)
            out = out + (out[-1:] * count) if out else out
        elif op == " ":
            # Whitespace inside a rule is ignored (hashcat tolerates it).
            pass
        else:
            raise RuleError(f"rule {rule!r}: unknown operation {op!r}")
        i += 1
    return out


def _digit(ch: str, rule: str) -> int:
    """Parse a single decimal digit argument, raising RuleError otherwise."""
    if not ch.isdigit():
        raise RuleError(f"rule {rule!r}: expected a digit, got {ch!r}")
    return int(ch)


def apply_rules(word: str, rules: Iterable[str]) -> list[str]:
    """Apply every rule to word, returning the list of candidates in order.

    Duplicates are preserved here (callers that want de-duplication should
    use mutate_stream()).
    """
    return [apply_rule(word, rule) for rule in rules]


# ---------------------------------------------------------------------------
# Rule file parsing.
# ---------------------------------------------------------------------------


def parse_rule_file(text: str) -> list[str]:
    """Parse a hashcat-style rule file into a list of rule strings.

    * Blank lines are skipped.
    * Lines starting with '#' are comments and are skipped.
    * Inline comments (' #' and everything after) are stripped.
    * Leading/trailing whitespace on each rule is stripped.
    * The special hashcat no-op rule ':\r' / bare ':' is kept as ':'.

    Returns rules in file order, without de-duplication.
    """
    rules: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip("\r\n")
        # Strip inline comments: a '#' preceded by whitespace.
        hash_pos = line.find(" #")
        if hash_pos != -1:
            line = line[:hash_pos]
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rules.append(line)
    return rules


# ---------------------------------------------------------------------------
# Preset rule sets.
# ---------------------------------------------------------------------------

#: Named preset rule lists. 'full' is the union of the other three.
RULE_SETS: dict[str, list[str]] = {
    # Identity + case + simple duplication/reversal.
    "basic": [
        ":",        # identity
        "l",        # lowercase
        "u",        # UPPERCASE
        "c",        # Capitalized
        "t",        # tOGGLE
        "d",        # duplicated
        "r",        # reversed
        "T0",       # toggle first char
    ],
    # Append digits that dominate breach lists: single digits and years.
    # ('$' takes exactly one character, so multi-char suffixes chain ops.)
    "append-years": [
        "$1", "$2", "$3", "$7", "$9",
        "$0", "$5", "$8",
        "$1$!",
        "$1$2$3",
        "$1$9$7$0", "$1$9$8$0", "$1$9$9$0", "$2$0$0$0", "$2$0$1$0", "$2$0$2$0",
        "$1$9$8$5", "$1$9$9$5", "$2$0$0$5", "$2$0$2$4",
    ],
    # l33t-speak substitutions built from the supported op set.
    "l33t": [
        ":", "$!", "$@", "$#",
        "c$!", "u$!",
        "^!", "^@",
        "x4$!",     # first 4 chars + '!'
        "o1",       # drop first char
        "z2",       # repeat first char twice, prepended
        "y2",       # repeat last char twice, appended
    ],
}

RULE_SETS["full"] = (
    RULE_SETS["basic"] + RULE_SETS["append-years"] + RULE_SETS["l33t"]
)


# ---------------------------------------------------------------------------
# Streaming mutation and statistics.
# ---------------------------------------------------------------------------


def mutate_stream(words: Iterable[str], rules: Iterable[str]) -> Iterator[str]:
    """Yield every rule-mutated candidate for every word, de-duplicated.

    The rule list is materialised once; words are consumed lazily. A
    candidate is yielded only on its first occurrence across the whole
    stream, so downstream hash comparisons never repeat work.
    """
    rule_list = list(rules)
    seen: set[str] = set()
    for word in words:
        for rule in rule_list:
            cand = apply_rule(word, rule)
            if cand not in seen:
                seen.add(cand)
                yield cand


def rule_stats(candidates: Iterable[str]) -> dict:
    """Compute summary statistics over a candidate iterable.

    Returns a dict with:

    * 'count' -- total number of candidates consumed,
    * 'unique' -- number of distinct candidates,
    * 'empty' -- number of empty-string candidates,
    * 'min_length' / 'max_length' / 'avg_length' -- length stats
      (avg_length is 0.0 for an empty input),
    * 'digit_suffix' -- how many candidates end in a digit,
    * 'upper' / 'lower' / 'mixed' -- case-class counts.
    """
    count = 0
    unique: set[str] = set()
    empty = 0
    total_len = 0
    min_len: int | None = None
    max_len = 0
    digit_suffix = 0
    upper = lower = mixed = 0

    for cand in candidates:
        count += 1
        unique.add(cand)
        n = len(cand)
        if n == 0:
            empty += 1
        total_len += n
        if min_len is None or n < min_len:
            min_len = n
        if n > max_len:
            max_len = n
        if cand and cand[-1].isdigit():
            digit_suffix += 1
        letters = [ch for ch in cand if ch.isalpha()]
        if letters:
            if all(ch.isupper() for ch in letters):
                upper += 1
            elif all(ch.islower() for ch in letters):
                lower += 1
            else:
                mixed += 1

    return {
        "count": count,
        "unique": len(unique),
        "empty": empty,
        "min_length": min_len if min_len is not None else 0,
        "max_length": max_len,
        "avg_length": round(total_len / count, 2) if count else 0.0,
        "digit_suffix": digit_suffix,
        "upper": upper,
        "lower": lower,
        "mixed": mixed,
    }
