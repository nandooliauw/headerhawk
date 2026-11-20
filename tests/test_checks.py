"""Offline tests. No network access: responses are constructed by hand."""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from headerhawk.checks import (  # noqa: E402
    EXPOSURE_SIGNATURES,
    cookie_checks,
    header_checks,
    tls_checks,
)
from headerhawk.models import Check, Response  # noqa: E402
from headerhawk.report import to_html, to_json, to_markdown, to_text  # noqa: E402
from headerhawk.scoring import score  # noqa: E402


def make_response(headers: dict[str, list[str]] | None = None, url: str = "https://example.test/") -> Response:
    response = Response(requested_url=url, final_url=url, status=200)
    response.headers = {k.lower(): v for k, v in (headers or {}).items()}
    response.raw_headers = [(k, v[0]) for k, v in (headers or {}).items()]
    return response


def by_id(checks: list[Check], check_id: str) -> Check:
    return next(c for c in checks if c.id == check_id)


class TestHsts(unittest.TestCase):
    def test_missing_is_fail(self):
        check = by_id(header_checks(make_response()), "HDR-01")
        self.assertEqual(check.status, "fail")

    def test_short_max_age_is_warn(self):
        check = by_id(header_checks(make_response({"Strict-Transport-Security": ["max-age=600"]})), "HDR-01")
        self.assertEqual(check.status, "warn")

    def test_full_hsts_passes_and_reports_flags(self):
        check = by_id(
            header_checks(
                make_response({"Strict-Transport-Security": ["max-age=31536000; includeSubDomains; preload"]})
            ),
            "HDR-01",
        )
        self.assertEqual(check.status, "pass")
        self.assertIn("includeSubDomains", check.evidence)

    def test_plain_http_skips(self):
        check = by_id(header_checks(make_response(url="http://example.test/")), "HDR-01")
        self.assertEqual(check.status, "skip")


class TestCsp(unittest.TestCase):
    def test_absent_fails(self):
        self.assertEqual(by_id(header_checks(make_response()), "HDR-02").status, "fail")

    def test_unsafe_inline_warns(self):
        check = by_id(header_checks(make_response({"Content-Security-Policy": ["default-src 'self' 'unsafe-inline'"]})), "HDR-02")
        self.assertEqual(check.status, "warn")
        self.assertIn("unsafe-inline", check.evidence)

    def test_strict_policy_passes(self):
        policy = "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        self.assertEqual(by_id(header_checks(make_response({"Content-Security-Policy": [policy]})), "HDR-02").status, "pass")

    def test_frame_ancestors_counts_as_clickjacking_protection(self):
        policy = "default-src 'self'; frame-ancestors 'none'"
        self.assertEqual(by_id(header_checks(make_response({"Content-Security-Policy": [policy]})), "HDR-03").status, "pass")


class TestReferrer(unittest.TestCase):
    def test_fallback_list_passes(self):
        value = "origin-when-cross-origin, strict-origin-when-cross-origin"
        self.assertEqual(by_id(header_checks(make_response({"Referrer-Policy": [value]})), "HDR-05").status, "pass")

    def test_unsafe_url_fails(self):
        self.assertEqual(by_id(header_checks(make_response({"Referrer-Policy": ["unsafe-url"]})), "HDR-05").status, "fail")


class TestCookies(unittest.TestCase):
    def test_no_cookie_skips(self):
        self.assertEqual(cookie_checks(make_response())[0].status, "skip")

    def test_hardened_cookie_passes(self):
        value = "sid=abc; Secure; HttpOnly; SameSite=Lax"
        self.assertEqual(cookie_checks(make_response({"Set-Cookie": [value]}))[0].status, "pass")

    def test_missing_secure_fails(self):
        check = cookie_checks(make_response({"Set-Cookie": ["sid=abc; HttpOnly; SameSite=Lax"]}))[0]
        self.assertEqual(check.status, "fail")
        self.assertIn("missing Secure", check.evidence)

    def test_samesite_none_without_secure_fails(self):
        check = cookie_checks(make_response({"Set-Cookie": ["sid=abc; HttpOnly; SameSite=None"]}))[0]
        self.assertEqual(check.status, "fail")
        self.assertIn("SameSite=None without Secure", check.evidence)

    def test_missing_httponly_only_warns(self):
        check = cookie_checks(make_response({"Set-Cookie": ["sid=abc; Secure; SameSite=Lax"]}))[0]
        self.assertEqual(check.status, "warn")


class TestTls(unittest.TestCase):
    def test_legacy_protocol_fails(self):
        response = make_response()
        response.tls = {"version": "TLSv1", "cipher": "AES128-SHA", "cipher_bits": 128}
        self.assertEqual(by_id(tls_checks(response), "TLS-01").status, "fail")

    def test_weak_cipher_fails(self):
        response = make_response()
        response.tls = {"version": "TLSv1.2", "cipher": "DES-CBC3-SHA", "cipher_bits": 112, "weak_cipher": True}
        self.assertEqual(by_id(tls_checks(response), "TLS-02").status, "fail")

    def test_expired_certificate_fails(self):
        response = make_response()
        response.tls = {"version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "days_until_expiry": -3}
        self.assertEqual(by_id(tls_checks(response), "TLS-03").status, "fail")

    def test_expiring_soon_warns(self):
        response = make_response()
        response.tls = {"version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "days_until_expiry": 5}
        self.assertEqual(by_id(tls_checks(response), "TLS-03").status, "warn")


class TestScoring(unittest.TestCase):
    def test_all_pass_is_100(self):
        checks = [Check("A", "a", "headers", "low", 10, status="pass"), Check("B", "b", "tls", "low", 10, status="pass")]
        self.assertEqual(score(checks)[:2], (100, "A"))

    def test_warn_earns_half_credit(self):
        checks = [Check("A", "a", "headers", "low", 10, status="warn"), Check("B", "b", "tls", "low", 10, status="pass")]
        self.assertEqual(score(checks)[0], 75)

    def test_skipped_checks_are_ignored(self):
        checks = [Check("A", "a", "headers", "low", 10, status="pass"), Check("B", "b", "tls", "low", 90, status="skip")]
        self.assertEqual(score(checks)[:2], (100, "A"))

    def test_grade_bands(self):
        cases = [
            (100, 0, "A"),
            (90, 10, "A"),
            (80, 20, "B"),
            (70, 30, "C"),
            (60, 40, "D"),
            (50, 50, "F"),
        ]
        for passing, failing, expected in cases:
            checks = [
                Check("A", "a", "headers", "low", passing, status="pass"),
                Check("B", "b", "tls", "low", failing, status="fail"),
            ]
            self.assertEqual(score(checks)[1], expected, f"{passing}/{passing + failing} should be {expected}")


class TestExposureSignatures(unittest.TestCase):
    def test_git_head(self):
        self.assertTrue(EXPOSURE_SIGNATURES["git_repo"]("ref: refs/heads/main\n", "text/plain"))

    def test_git_head_rejects_html(self):
        self.assertFalse(EXPOSURE_SIGNATURES["git_repo"]("<!DOCTYPE html><html>", "text/html"))

    def test_dotenv(self):
        self.assertTrue(EXPOSURE_SIGNATURES["dotenv"]("APP_KEY=base64:xxx\nDB_HOST=localhost", "text/plain"))

    def test_ds_store(self):
        self.assertTrue(EXPOSURE_SIGNATURES["ds_store"]("\x00\x00\x00\x01Bud1xxxx", "application/octet-stream"))


class TestReports(unittest.TestCase):
    def build(self):
        response = make_response({"Server": ["nginx/1.18.0"]})
        response.final_url = "https://example.test/"
        checks = header_checks(response) + cookie_checks(response) + tls_checks(response)
        value, grade, _ = score(checks)
        from headerhawk.models import Report

        return Report(
            target="https://example.test/",
            final_url=response.final_url,
            generated_at="2026-01-01 00:00:00 UTC",
            score=value,
            grade=grade,
            checks=checks,
            response=response,
        )

    def test_markdown_has_score_and_table(self):
        text = to_markdown(self.build())
        self.assertIn("## Score:", text)
        self.assertIn("| HDR-01 |", text)

    def test_json_is_valid(self):
        import json

        data = json.loads(to_json(self.build()))
        self.assertEqual(data["tool"], "headerhawk")
        self.assertIn("checks", data)

    def test_html_is_self_contained(self):
        markup = to_html(self.build())
        self.assertTrue(markup.startswith("<!DOCTYPE html>"))
        self.assertNotIn("http://cdn", markup)
        self.assertIn("Grade", markup)

    def test_text_mentions_grade(self):
        self.assertIn("grade", to_text(self.build(), colour=False))


if __name__ == "__main__":
    unittest.main(verbosity=2)
