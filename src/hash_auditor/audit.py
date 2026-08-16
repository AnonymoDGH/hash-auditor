"""Integrated password audit orchestrator for hash-auditor.

The individual modules each answer one question: is it weak? is it leaked?
is it a date? is it a keyboard walk? This module runs them all against a
password (or a batch) and folds the answers into a single, prioritised
verdict with an overall risk score.

The orchestrator is deliberately dependency-light: it imports the sibling
modules and composes their reports. It never hashes or cracks -- it is a
*read-only* risk assessment.

Public API
----------
audit_password(password)
    full single-password audit: strength, exposure, structure, dates,
    walks, leet, and a combined risk score + verdict.
audit_batch(passwords)
    run audit_password over many, aggregate, rank worst-first.
risk_score(findings)
    fold one audit's sub-findings into a 0-100 risk score.
verdict_for(score)
    map a risk score to a label.

Pure standard library. Deterministic. No network access.
"""

from __future__ import annotations

from typing import Iterable

from . import analyze
from .breach import exposure_score
from .dates import date_score, extract_dates
from .entropy import randomness_report
from .keyboard import walk_score
from .leet import leet_dictionary_match
from .wordlists import EMBEDDED_PASSWORDS

__all__ = [
    "audit_password",
    "audit_batch",
    "risk_score",
    "verdict_for",
]

#: Risk bands -> verdict labels.
_VERDICT_BANDS = (
    (80, "critical"),
    (60, "high"),
    (40, "medium"),
    (20, "low"),
    (0, "minimal"),
)


def verdict_for(score: int) -> str:
    """Map a 0-100 risk score to critical/high/medium/low/minimal."""
    for floor, label in _VERDICT_BANDS:
        if score >= floor:
            return label
    return "minimal"


def audit_password(password: str) -> dict:
    """Run the full battery of checks on one password.

    Returns a dict with every sub-report plus a combined 'risk_score'
    (0-100), a 'verdict', and a prioritised 'issues' list of human strings.
    """
    strength = analyze(password)
    exposure = exposure_score(password)
    randomness = randomness_report(password)
    dates = extract_dates(password)
    dscore = date_score(password)
    wscore = walk_score(password)
    leet_matches = leet_dictionary_match(password, EMBEDDED_PASSWORDS)

    findings = {
        "password_length": len(password),
        "strength": strength,
        "exposure": exposure,
        "randomness": randomness,
        "date_score": dscore,
        "dates": dates[:5],
        "walk_score": wscore,
        "leet_matches": leet_matches[:5],
    }
    findings["risk_score"] = risk_score(findings)
    findings["verdict"] = verdict_for(findings["risk_score"])
    findings["issues"] = _collect_issues(findings)
    return findings


def _collect_issues(f: dict) -> list[str]:
    """Build a prioritised, human-readable issue list from sub-findings."""
    issues: list[str] = []
    if f["exposure"]["found"]:
        issues.append(
            f"found in breach corpus (matched "
            f"{f['exposure']['matched_variant']!r}, "
            f"score {f['exposure']['score']})")
    if f["strength"]["verdict"] == "weak":
        issues.append("strength estimator rates it weak")
    for flag in f["strength"]["flags"]:
        issues.append(f"strength flag: {flag}")
    if f["leet_matches"]:
        issues.append(
            "leet-mutation of a common password: "
            + ", ".join(f["leet_matches"][:3]))
    if f["date_score"] >= 0.8:
        issues.append("essentially a date")
    elif f["date_score"] >= 0.4:
        issues.append("contains a prominent date fragment")
    if f["walk_score"] >= 0.8:
        issues.append("a keyboard walk")
    if f["randomness"]["verdict"] == "pattern":
        issues.append("very low randomness (pattern-like)")
    return issues


def risk_score(findings: dict) -> int:
    """Fold the sub-findings into a single 0-100 risk score.

    Weighted blend: breach exposure dominates (40), then strength weakness
    (25), structure (leet/date/walk, 20), and low randomness (15). Each
    component is itself 0-100 before weighting.
    """
    exposure_component = float(findings["exposure"]["score"])

    strength = findings["strength"]
    if strength["verdict"] == "weak":
        strength_component = 90.0
    elif strength["verdict"] == "acceptable":
        strength_component = 45.0
    else:
        strength_component = 15.0
    # extra penalty for many flags
    strength_component = min(100.0,
                             strength_component + 5 * len(strength["flags"]))

    structure = 0.0
    if findings["leet_matches"]:
        structure += 50.0
    structure += 30.0 * findings["date_score"]
    structure += 30.0 * findings["walk_score"]
    structure_component = min(100.0, structure)

    rand = findings["randomness"]
    randomness_component = max(0.0, 100.0 - rand["score"])

    score = (0.40 * exposure_component +
             0.25 * strength_component +
             0.20 * structure_component +
             0.15 * randomness_component)
    return int(round(max(0.0, min(100.0, score))))


def audit_batch(passwords: Iterable[str]) -> dict:
    """Audit many passwords and aggregate the results.

    Returns totals, a verdict histogram, the average risk score, and the
    per-password audits ranked worst-first (by descending risk score, ties
    broken by the password string).
    """
    audits: list[tuple[str, dict]] = []
    histogram = {"critical": 0, "high": 0, "medium": 0, "low": 0,
                 "minimal": 0}
    total_risk = 0
    for pw in passwords:
        audit = audit_password(pw)
        audits.append((pw, audit))
        histogram[audit["verdict"]] += 1
        total_risk += audit["risk_score"]

    audits.sort(key=lambda pa: (-pa[1]["risk_score"], pa[0]))
    total = len(audits)
    return {
        "total": total,
        "average_risk": round(total_risk / total, 2) if total else 0.0,
        "histogram": histogram,
        "ranked": [
            {"password": pw, "risk_score": a["risk_score"],
             "verdict": a["verdict"], "issues": a["issues"]}
            for pw, a in audits
        ],
    }
