"""Tests for hash_auditor.dates."""

from __future__ import annotations

import pytest

from hash_auditor.dates import (
    YEAR_RANGE,
    date_score,
    extract_dates,
    is_date_password,
    year_candidates,
)


class TestYearCandidates:
    def test_four_digit(self):
        assert year_candidates("born1990") == [1990]

    def test_two_digit_high(self):
        assert year_candidates("x85") == [1985]

    def test_two_digit_low(self):
        assert year_candidates("x23") == [2023]

    def test_multiple(self):
        years = year_candidates("1990and2001")
        assert 1990 in years and 2001 in years

    def test_none(self):
        assert year_candidates("password") == []

    def test_dedup(self):
        assert year_candidates("19901990") == [1990]


class TestExtractDates:
    def test_iso_date(self):
        dates = extract_dates("1990-07-04")
        assert any(d["kind"] == "fulldate" and d["value"] == "1990-07-04"
                   for d in dates)

    def test_dmy_slash(self):
        dates = extract_dates("04/07/1990")
        assert any(d["kind"] == "fulldate" for d in dates)

    def test_compact_yyyymmdd(self):
        dates = extract_dates("19900704")
        assert any(d["kind"] == "fulldate" for d in dates)

    def test_monthday(self):
        dates = extract_dates("0704")
        assert any(d["kind"] == "monthday" for d in dates)

    def test_bare_year(self):
        dates = extract_dates("summer1990")
        assert any(d["kind"] == "year" and d["value"] == "1990"
                   for d in dates)

    def test_invalid_month_rejected(self):
        dates = extract_dates("1313")  # month 13 invalid
        assert not any(d["kind"] == "monthday" for d in dates)

    def test_sorted_by_confidence(self):
        dates = extract_dates("1990-07-04")
        confs = [d["confidence"] for d in dates]
        assert confs == sorted(confs, reverse=True)

    def test_empty(self):
        assert extract_dates("") == []


class TestDateScore:
    def test_pure_date(self):
        assert date_score("1990-07-04") == pytest.approx(1.0)

    def test_no_date(self):
        assert date_score("password") == 0.0

    def test_partial(self):
        score = date_score("summer1990")
        assert 0.0 < score < 1.0

    def test_empty(self):
        assert date_score("") == 0.0

    def test_range(self):
        assert 0.0 <= date_score("07041990x") <= 1.0


class TestIsDatePassword:
    def test_pure_date(self):
        assert is_date_password("1990-07-04")

    def test_word(self):
        assert not is_date_password("password")

    def test_year_range(self):
        assert YEAR_RANGE == (1900, 2039)
