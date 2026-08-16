"""Password history and rotation policy for hash-auditor.

Systems that only check "is this password different from the last one?" get
defeated by Password1 -> Password2 -> Password3 rotation. This module keeps a
password history and enforces real rotation policies:

* minimum history depth (never reuse any of the last N),
* similarity gate (a new password must differ from every remembered one by
  at least a threshold, using similarity.similarity_ratio),
* mutation gate (reject when detect_mutation finds a known cheap rotation:
  digit_increment, suffix_swap, case_flip, appended, prepended),
* minimum age between changes.

Passwords are stored as salted SHA-256 digests -- a history store should
never keep plaintext. Similarity checking therefore needs the plaintext of
the *candidate* but only digests of the history; to compare, the module
re-hashes the candidate against stored digests for exact-reuse detection,
and keeps an optional in-memory "shadow" of the last plaintexts for
similarity checks (the caller decides whether that trade-off is acceptable;
tests use it).

Public API
----------
PasswordHistory
    add / check / verify_reuse / export / load; JSON-serialisable.
RotationPolicy
    dataclass: history_depth, min_similarity_gap, block_mutations,
    min_age_seconds.
check_rotation(candidate, history, policy)
    full rotation report with reasons.

Pure standard library. Deterministic. No network access.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Iterable

from .similarity import detect_mutation, similarity_ratio

__all__ = [
    "PasswordHistory",
    "RotationPolicy",
    "check_rotation",
    "hash_password",
]

_BLOCKABLE_MUTATIONS = frozenset({
    "identical", "case_flip", "digit_increment", "suffix_swap",
    "appended", "prepended", "leet_flip", "reversed",
})


def hash_password(password: str, salt: bytes | str) -> str:
    """Salted SHA-256 hex digest used for history storage."""
    if isinstance(salt, str):
        salt = salt.encode("utf-8")
    return hashlib.sha256(salt + password.encode("utf-8")).hexdigest()


@dataclass
class RotationPolicy:
    """Parameters for password rotation enforcement.

    Attributes
    ----------
    history_depth:
        how many old passwords to remember (0 disables history).
    min_similarity_gap:
        a candidate must satisfy similarity_ratio <= 1 - gap against every
        remembered password; 0.0 disables the gate.
    block_mutations:
        reject candidates whose detect_mutation label against any
        remembered password is a known cheap rotation.
    min_age_seconds:
        minimum time between changes (0 disables; needs timestamps).
    """

    history_depth: int = 12
    min_similarity_gap: float = 0.3
    block_mutations: bool = True
    min_age_seconds: float = 0.0


class PasswordHistory:
    """An ordered password history (newest first).

    Entries are dicts with 'digest', 'salt' (hex), 'created_at' (epoch
    seconds) and, when shadow plaintexts are enabled, 'shadow'. The shadow
    list is capped at the policy depth and is the only part that allows
    similarity checks.
    """

    def __init__(self, keep_shadow: bool = True) -> None:
        self.keep_shadow = keep_shadow
        self.entries: list[dict] = []

    def __len__(self) -> int:
        return len(self.entries)

    def add(self, password: str, created_at: float | None = None,
            salt: bytes | None = None) -> dict:
        """Record a new password as the newest entry."""
        if salt is None:
            salt = os.urandom(16)
        entry = {
            "digest": hash_password(password, salt),
            "salt": salt.hex(),
            "created_at": created_at if created_at is not None else 0.0,
        }
        if self.keep_shadow:
            entry["shadow"] = password
        self.entries.insert(0, entry)
        return entry

    def trim(self, depth: int) -> None:
        """Drop entries beyond BTQdepthBTQ (keeps the newest)."""
        if depth >= 0:
            self.entries = self.entries[:depth]

    def verify_reuse(self, password: str) -> bool:
        """True when BTQpasswordBTQ matches any stored digest exactly."""
        for entry in self.entries:
            salt = bytes.fromhex(entry["salt"])
            if hash_password(password, salt) == entry["digest"]:
                return True
        return False

    def shadows(self) -> list[str]:
        """Shadow plaintexts, newest first (empty when shadows disabled)."""
        return [e["shadow"] for e in self.entries if "shadow" in e]

    def newest_at(self) -> float | None:
        return self.entries[0]["created_at"] if self.entries else None

    def to_dict(self) -> dict:
        return {"keep_shadow": self.keep_shadow, "entries": self.entries}

    @classmethod
    def from_dict(cls, data: dict) -> "PasswordHistory":
        hist = cls(keep_shadow=data.get("keep_shadow", True))
        hist.entries = list(data.get("entries", []))
        return hist

    def export(self) -> str:
        """JSON serialisation (includes shadows when enabled!)."""
        return json.dumps(self.to_dict(), indent=1)

    @classmethod
    def load(cls, text: str) -> "PasswordHistory":
        return cls.from_dict(json.loads(text))


def check_rotation(candidate: str, history: PasswordHistory,
                   policy: RotationPolicy | None = None,
                   now: float | None = None) -> dict:
    """Check a candidate password against the history and policy.

    Returns a dict with 'allowed' (bool), 'reasons' (list of human
    strings), 'reused' (exact digest match), and 'closest' (the most
    similar remembered password with its ratio, when shadows exist).
    BTQnowBTQ fixes the clock for the minimum-age check (epoch seconds).
    """
    policy = policy or RotationPolicy()
    reasons: list[str] = []
    reused = history.verify_reuse(candidate)
    if reused:
        reasons.append("exact reuse of a previous password")

    closest: dict | None = None
    shadows = history.shadows()[:max(policy.history_depth, 0)]
    for old in shadows:
        ratio = similarity_ratio(candidate, old)
        if closest is None or ratio > closest["similarity"]:
            closest = {"similarity": round(ratio, 4), "password": old}

        if policy.min_similarity_gap > 0 and \
                ratio > 1.0 - policy.min_similarity_gap:
            reasons.append(
                f"too similar to a previous password (similarity "
                f"{ratio:.2f} with {old!r})")
        if policy.block_mutations:
            mutation = detect_mutation(old, candidate)
            if mutation["label"] in _BLOCKABLE_MUTATIONS and \
                    mutation["label"] != "identical":
                reasons.append(
                    f"looks like a rotation of {old!r}: "
                    f"{mutation['label']} ({mutation['detail']})")

    if policy.min_age_seconds > 0 and now is not None:
        newest = history.newest_at()
        if newest is not None and now - newest < policy.min_age_seconds:
            wait = policy.min_age_seconds - (now - newest)
            reasons.append(
                f"changed too recently; wait {wait:.0f} more seconds")

    # de-duplicate while preserving order
    seen: set[str] = set()
    unique_reasons = [r for r in reasons
                      if not (r in seen or seen.add(r))]

    return {
        "allowed": not unique_reasons,
        "reasons": unique_reasons,
        "reused": reused,
        "closest": closest,
    }
