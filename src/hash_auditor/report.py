"""Audit report building for hash-auditor.

Aggregates findings from the other modules -- strength estimates, policy
checks, breach exposure, hash identification -- into one structured audit
report that can be rendered as JSON or as a human-readable text report with
ASCII tables.

A report is built incrementally: create an AuditReport, add findings of the
various kinds, then render. Every finding is a plain dict so the JSON output
is trivially serialisable.

Public API
----------
AuditReport
    add_password_finding / add_hash_finding / add_policy_summary /
    add_exposure_summary / to_dict / to_json / to_text.
ascii_table(headers, rows)
    a small dependency-free ASCII table renderer.
severity_of(score)
    map a 0-100 exposure score to a severity label.
summarize_findings(report)
    roll up counts by verdict/severity.

Pure standard library. Deterministic. No network access.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterable

__all__ = [
    "AuditReport",
    "ascii_table",
    "severity_of",
    "summarize_findings",
]

_SEVERITY_BANDS = (
    (80, "critical"),
    (60, "high"),
    (40, "medium"),
    (1, "low"),
    (0, "none"),
)


def severity_of(score: int) -> str:
    """Map a 0-100 exposure score to critical/high/medium/low/none."""
    for floor, label in _SEVERITY_BANDS:
        if score >= floor:
            return label
    return "none"


def ascii_table(headers: Iterable[str], rows: Iterable[Iterable[object]],
                min_width: int = 4) -> str:
    """Render an ASCII table with a header row and a rule line.

    Columns are sized to their widest cell (at least BTQmin_widthBTQ). Cells
    are stringified with str(). Example::

        name | score
        -----+------
        pw   |    42
    """
    headers = [str(h) for h in headers]
    str_rows = [[str(cell) for cell in row] for row in rows]
    n_cols = len(headers)
    widths = [max(min_width, len(h)) for h in headers]
    for row in str_rows:
        for i in range(min(n_cols, len(row))):
            widths[i] = max(widths[i], len(row[i]))

    def fmt_row(cells: list[str]) -> str:
        padded = []
        for i in range(n_cols):
            cell = cells[i] if i < len(cells) else ""
            # right-align numbers, left-align text
            if cell.replace(".", "", 1).replace("-", "", 1).isdigit():
                padded.append(cell.rjust(widths[i]))
            else:
                padded.append(cell.ljust(widths[i]))
        return " | ".join(padded).rstrip()

    lines = [fmt_row(headers)]
    lines.append("-+-".join("-" * w for w in widths))
    for row in str_rows:
        lines.append(fmt_row(row))
    return "\n".join(lines)


class AuditReport:
    """An incrementally-built audit report.

    Parameters
    ----------
    title:
        report heading.
    timestamp:
        ISO timestamp; defaults to the current UTC time. Pass an explicit
        value in tests for determinism.
    """

    def __init__(self, title: str = "Hash Auditor Report",
                 timestamp: str | None = None) -> None:
        self.title = title
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat(
            timespec="seconds")
        self.password_findings: list[dict] = []
        self.hash_findings: list[dict] = []
        self.policy_summary: dict | None = None
        self.exposure_summary: dict | None = None
        self.notes: list[str] = []

    # -- findings ------------------------------------------------------------

    def add_password_finding(self, password_label: str, analysis: dict,
                             exposure: dict | None = None) -> dict:
        """Record one audited password.

        BTQanalysisBTQ is a hash_auditor.analyze() report; BTQexposureBTQ an
        optional breach.exposure_score() report. The combined finding gets a
        unified verdict: 'fail' when the password is weak or exposed with
        score >= 60, 'warn' for exposed < 60 or flagged, else 'pass'.
        """
        finding: dict = {
            "label": password_label,
            "length": analysis.get("length"),
            "entropy_bits": analysis.get("entropy_bits"),
            "verdict": analysis.get("verdict"),
            "flags": list(analysis.get("flags", [])),
        }
        if exposure is not None:
            finding["exposed"] = exposure.get("found", False)
            finding["exposure_score"] = exposure.get("score", 0)
            finding["exposure_severity"] = severity_of(
                exposure.get("score", 0))
            finding["matched_variant"] = exposure.get("matched_variant")
        else:
            finding["exposed"] = False
            finding["exposure_score"] = 0
            finding["exposure_severity"] = "none"
            finding["matched_variant"] = None

        weak = finding["verdict"] == "weak"
        if weak or finding["exposure_score"] >= 60:
            finding["status"] = "fail"
        elif finding["exposed"] or finding["flags"]:
            finding["status"] = "warn"
        else:
            finding["status"] = "pass"
        self.password_findings.append(finding)
        return finding

    def add_hash_finding(self, hash_text: str, candidates: list,
                         cracked: bool = False,
                         plaintext_label: str | None = None) -> dict:
        """Record one identified (and possibly cracked) hash.

        BTQcandidatesBTQ is a list of identify.HashCandidate (or dicts with
        'name' and 'confidence').
        """
        norm = []
        for c in candidates:
            if isinstance(c, dict):
                norm.append({"name": c.get("name"),
                             "confidence": c.get("confidence")})
            else:
                norm.append({"name": c.name, "confidence": c.confidence})
        finding = {
            "hash": hash_text,
            "candidates": norm,
            "best_guess": norm[0]["name"] if norm else None,
            "cracked": cracked,
            "plaintext_label": plaintext_label,
        }
        self.hash_findings.append(finding)
        return finding

    def add_policy_summary(self, summary: dict) -> None:
        """Attach a policy.grade_wordlist() summary."""
        self.policy_summary = dict(summary)

    def add_exposure_summary(self, summary: dict) -> None:
        """Attach a breach.cross_reference() summary (rows elided)."""
        slim = {k: v for k, v in summary.items() if k != "rows"}
        self.exposure_summary = slim

    def add_note(self, note: str) -> None:
        self.notes.append(note)

    # -- rendering -------------------------------------------------------------

    def to_dict(self) -> dict:
        """The full report as a JSON-serialisable dict."""
        return {
            "title": self.title,
            "timestamp": self.timestamp,
            "passwords": self.password_findings,
            "hashes": self.hash_findings,
            "policy": self.policy_summary,
            "exposure": self.exposure_summary,
            "summary": summarize_findings(self),
            "notes": self.notes,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)

    def to_text(self) -> str:
        """Human-readable report with ASCII tables."""
        out: list[str] = []
        bar = "=" * 60
        out.append(bar)
        out.append(self.title.center(60))
        out.append(f"generated: {self.timestamp}".center(60))
        out.append(bar)

        if self.password_findings:
            out.append("")
            out.append(f"PASSWORDS ({len(self.password_findings)})")
            out.append("-" * 60)
            rows = [
                (f["label"], f["length"], f["entropy_bits"],
                 f["verdict"], f["exposure_score"], f["status"])
                for f in self.password_findings
            ]
            out.append(ascii_table(
                ("label", "len", "bits", "verdict", "exposure", "status"),
                rows))

        if self.hash_findings:
            out.append("")
            out.append(f"HASHES ({len(self.hash_findings)})")
            out.append("-" * 60)
            rows = []
            for f in self.hash_findings:
                shown = f["hash"][:16] + "..." if len(f["hash"]) > 16 \
                    else f["hash"]
                rows.append((shown, f["best_guess"] or "?",
                             "yes" if f["cracked"] else "no"))
            out.append(ascii_table(("hash", "best guess", "cracked"), rows))

        if self.policy_summary:
            out.append("")
            out.append("POLICY")
            out.append("-" * 60)
            p = self.policy_summary
            out.append(f"checked: {p.get('total', 0)}   "
                       f"passed: {p.get('passed', 0)}   "
                       f"failed: {p.get('failed', 0)}   "
                       f"pass rate: {p.get('pass_rate', 0):.1%}")
            grades = p.get("grades", {})
            if grades:
                out.append(ascii_table(
                    ("grade", "count"),
                    [(g, grades[g]) for g in "ABCDF" if g in grades]))

        if self.exposure_summary:
            out.append("")
            out.append("BREACH EXPOSURE")
            out.append("-" * 60)
            e = self.exposure_summary
            out.append(f"checked: {e.get('total', 0)}   "
                       f"exposed: {e.get('exposed', 0)}   "
                       f"fraction: {e.get('exposed_fraction', 0):.1%}")

        summary = summarize_findings(self)
        out.append("")
        out.append("SUMMARY")
        out.append("-" * 60)
        out.append(f"passwords: {summary['passwords_total']} total, "
                   f"{summary['passwords_failed']} failed, "
                   f"{summary['passwords_warned']} warned")
        out.append(f"hashes:    {summary['hashes_total']} identified, "
                   f"{summary['hashes_cracked']} cracked")
        if summary["weak_algorithms"]:
            out.append("weak algorithms seen: " +
                       ", ".join(sorted(summary["weak_algorithms"])))

        if self.notes:
            out.append("")
            out.append("NOTES")
            out.append("-" * 60)
            out.extend(f"* {note}" for note in self.notes)

        out.append(bar)
        return "\n".join(out)


_WEAK_ALGORITHM_NAMES = {
    "md5", "ntlm", "md4", "crc32", "mysql323", "oracle10g", "sha1",
    "des-crypt", "md5crypt", "apr1crypt", "phpass", "ldap-md5",
    "ldap-sha", "django-md5", "django-sha1",
}


def summarize_findings(report: AuditReport) -> dict:
    """Roll up an AuditReport into headline numbers."""
    failed = sum(1 for f in report.password_findings
                 if f["status"] == "fail")
    warned = sum(1 for f in report.password_findings
                 if f["status"] == "warn")
    cracked = sum(1 for f in report.hash_findings if f["cracked"])
    weak_algos = {
        f["best_guess"] for f in report.hash_findings
        if f["best_guess"] in _WEAK_ALGORITHM_NAMES
    }
    return {
        "passwords_total": len(report.password_findings),
        "passwords_failed": failed,
        "passwords_warned": warned,
        "passwords_passed": len(report.password_findings) - failed - warned,
        "hashes_total": len(report.hash_findings),
        "hashes_cracked": cracked,
        "weak_algorithms": sorted(weak_algos),
    }
