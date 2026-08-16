"""Password and passphrase generation for hash-auditor.

Four deterministic, seeded generation schemes plus entropy accounting for
each:

diceware
    N words drawn from the embedded wordlist with a seeded RNG, joined by a
    separator. Entropy is N * log2(wordlist size) -- the gold standard for
    human-memorable passphrases.
syllable
    pronounceable pseudo-words built from consonant/vowel syllable templates
    with optional digit/symbol tails. Entropy is estimated from the syllable
    inventory.
leet
    takes a base word and applies deterministic l33t substitutions plus a
    seeded choice of case flips and affixes. Entropy is estimated from the
    number of reachable variants.
pin
    numeric PINs: random, pattern-avoiding (no repeats, no sequences), or
    word-mapped (letters -> phone keypad).

Every function takes an explicit BTQrngBTQ (or builds one from a seed) so all
output is reproducible in tests.

Public API
----------
generate_diceware(words, count, separator, rng)
generate_syllable(syllables, count, rng)
generate_leet(base, rng)
generate_pin(length, mode, rng)
generate(scheme, **kwargs)
    dispatcher used by the CLI.
entropy_report(password, scheme)
    bits of entropy attributed to a generated secret, per scheme.

Pure standard library. Deterministic given a seed. No network access.
"""

from __future__ import annotations

import math
import random
import string

from .wordlists import EMBEDDED_WORDS

__all__ = [
    "generate_diceware",
    "generate_syllable",
    "generate_leet",
    "generate_pin",
    "generate",
    "entropy_report",
    "SYLLABLES",
    "LEET_MAP",
    "KEYPAD_MAP",
]

#: Consonant-vowel syllable inventory for the pronounceable scheme.
SYLLABLES: tuple[str, ...] = (
    "ba", "be", "bi", "bo", "bu",
    "da", "de", "di", "do", "du",
    "fa", "fe", "fi", "fo", "fu",
    "ga", "ge", "gi", "go", "gu",
    "ka", "ke", "ki", "ko", "ku",
    "la", "le", "li", "lo", "lu",
    "ma", "me", "mi", "mo", "mu",
    "na", "ne", "ni", "no", "nu",
    "pa", "pe", "pi", "po", "pu",
    "ra", "re", "ri", "ro", "ru",
    "sa", "se", "si", "so", "su",
    "ta", "te", "ti", "to", "tu",
    "va", "ve", "vi", "vo", "vu",
    "za", "ze", "zi", "zo", "zu",
    "sha", "she", "shi", "cho", "chu",
    "tra", "tre", "kri", "gro", "bru",
)

#: Deterministic l33t substitutions, applied in this order.
LEET_MAP: dict[str, str] = {
    "a": "4", "e": "3", "i": "1", "o": "0",
    "s": "5", "t": "7", "b": "8", "g": "9",
}

#: Phone-keypad mapping for word-to-PIN generation.
KEYPAD_MAP: dict[str, str] = {
    **dict.fromkeys("abc", "2"), **dict.fromkeys("def", "3"),
    **dict.fromkeys("ghi", "4"), **dict.fromkeys("jkl", "5"),
    **dict.fromkeys("mno", "6"), **dict.fromkeys("pqrs", "7"),
    **dict.fromkeys("tuv", "8"), **dict.fromkeys("wxyz", "9"),
}

_DIGIT_TAILS = ("!", "?", "#", "2", "4", "6", "8", "0")


def _rng(rng: random.Random | None, seed: int | None) -> random.Random:
    if rng is not None:
        return rng
    return random.Random(seed)


def generate_diceware(count: int = 5, separator: str = "-",
                      words: list[str] | None = None,
                      rng: random.Random | None = None,
                      seed: int | None = None) -> str:
    """Pick BTQcountBTQ words from the wordlist and join them.

    Words are sampled with replacement; the default wordlist is the embedded
    common-English list. Raises ValueError for count < 1 or an empty list.
    """
    if count < 1:
        raise ValueError("count must be >= 1")
    pool = words if words is not None else EMBEDDED_WORDS
    if not pool:
        raise ValueError("word list is empty")
    r = _rng(rng, seed)
    return separator.join(r.choice(pool) for _ in range(count))


def generate_syllable(count: int = 4, capitalize: bool = True,
                      tail: bool = True,
                      rng: random.Random | None = None,
                      seed: int | None = None) -> str:
    """Build a pronounceable passphrase from BTQcountBTQ random syllables.

    With BTQtailBTQ a two-character digit/symbol tail is appended to raise the
    character-class count. Capitalisation marks word boundaries for
    readability.
    """
    if count < 1:
        raise ValueError("count must be >= 1")
    r = _rng(rng, seed)
    parts = [r.choice(SYLLABLES) for _ in range(count)]
    word = "".join(parts)
    if capitalize:
        word = word.capitalize()
    if tail:
        word += r.choice(_DIGIT_TAILS) + str(r.randrange(10))
    return word


def generate_leet(base: str, strength: int = 2,
                  rng: random.Random | None = None,
                  seed: int | None = None) -> str:
    """Mutate BTQbaseBTQ into a l33t-style password.

    strength 1 substitutes roughly half the eligible letters, strength 2
    substitutes all of them, strength 3 also flips the case of two random
    letters and appends a symbol+digit tail. The same base, strength and
    seed always produce the same output.
    """
    if not base:
        raise ValueError("base must be non-empty")
    if strength not in (1, 2, 3):
        raise ValueError("strength must be 1, 2 or 3")
    r = _rng(rng, seed)

    letters = [i for i, ch in enumerate(base) if ch.lower() in LEET_MAP]
    if strength == 1 and letters:
        letters = sorted(r.sample(letters, max(1, len(letters) // 2)))

    chars = list(base)
    for i in letters:
        chars[i] = LEET_MAP[chars[i].lower()]

    if strength >= 3:
        alpha_idx = [i for i, ch in enumerate(chars) if ch.isalpha()]
        for i in r.sample(alpha_idx, min(2, len(alpha_idx))) if alpha_idx else []:
            chars[i] = chars[i].swapcase()
        out = "".join(chars) + r.choice(("!", "?", "#", "$")) + str(r.randrange(100))
        return out
    return "".join(chars)


def generate_pin(length: int = 6, mode: str = "random",
                 word: str | None = None,
                 rng: random.Random | None = None,
                 seed: int | None = None) -> str:
    """Generate a numeric PIN.

    Modes:
    * random   -- uniform digits from the seeded RNG.
    * strong   -- random but rejects runs of one digit and ascending or
                  descending sequences (re-draws, bounded attempts).
    * word     -- map BTQwordBTQ through the phone keypad; length is ignored.
    """
    if length < 1:
        raise ValueError("length must be >= 1")
    r = _rng(rng, seed)
    if mode == "word":
        if not word:
            raise ValueError("mode 'word' needs a word")
        digits = "".join(KEYPAD_MAP.get(ch, "") for ch in word.lower())
        if not digits:
            raise ValueError(f"word {word!r} maps to no keypad digits")
        return digits
    if mode == "random":
        return "".join(r.choice(string.digits) for _ in range(length))
    if mode == "strong":
        for _ in range(100):
            pin = "".join(r.choice(string.digits) for _ in range(length))
            if _pin_ok(pin):
                return pin
        # Astronomically unlikely fallback: construct a valid PIN directly.
        digits = r.sample(string.digits, min(length, 10))
        while len(digits) < length:
            digits.append(str(r.randrange(10)))
        return "".join(digits)
    raise ValueError(f"unknown PIN mode: {mode}")


def _pin_ok(pin: str) -> bool:
    if len(set(pin)) < max(2, len(pin) // 2):
        return False
    for i in range(len(pin) - 1):
        if pin[i] == pin[i + 1]:
            return False
    ascending = all(ord(pin[i + 1]) - ord(pin[i]) == 1
                    for i in range(len(pin) - 1))
    descending = all(ord(pin[i]) - ord(pin[i + 1]) == 1
                     for i in range(len(pin) - 1))
    return not (ascending or descending)


def generate(scheme: str, seed: int | None = None, **kwargs) -> str:
    """Dispatch to a scheme generator: diceware/syllable/leet/pin."""
    rng = random.Random(seed)
    if scheme == "diceware":
        return generate_diceware(rng=rng, **kwargs)
    if scheme == "syllable":
        return generate_syllable(rng=rng, **kwargs)
    if scheme == "leet":
        return generate_leet(rng=rng, **kwargs)
    if scheme == "pin":
        return generate_pin(rng=rng, **kwargs)
    raise ValueError(f"unknown scheme: {scheme} "
                     "(use diceware, syllable, leet, pin)")


def entropy_report(password: str, scheme: str,
                   words: list[str] | None = None,
                   count: int | None = None) -> dict:
    """Estimate the entropy of a generated secret, per scheme.

    Returns a dict with BTQschemeBTQ, BTQbitsBTQ (rounded to 1 decimal) and a
    human BTQexplanationBTQ. For diceware the count defaults to the number of
    separator-delimited parts in the password.
    """
    pool = words if words is not None else EMBEDDED_WORDS
    if scheme == "diceware":
        n = count if count is not None else max(1, len(password.split("-")))
        bits = n * math.log2(max(len(pool), 2))
        explanation = (f"{n} words from a {len(pool)}-word list: "
                       f"{n} x log2({len(pool)})")
    elif scheme == "syllable":
        n = count if count is not None else 4
        bits = n * math.log2(len(SYLLABLES)) + math.log2(len(_DIGIT_TAILS) * 10)
        explanation = (f"{n} syllables from a {len(SYLLABLES)}-syllable "
                       f"inventory plus a 2-char tail")
    elif scheme == "leet":
        variants = 2 ** sum(1 for ch in password if ch in LEET_MAP.values())
        bits = math.log2(max(variants, 2)) * 2
        explanation = ("leet substitutions over the base word; "
                       "case/affix choices double the space")
    elif scheme == "pin":
        bits = len(password) * math.log2(10)
        explanation = f"{len(password)} digits: log2(10) each"
    else:
        raise ValueError(f"unknown scheme: {scheme}")
    return {"scheme": scheme, "bits": round(bits, 1),
            "explanation": explanation}
