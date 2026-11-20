"""Command line interface for headerhawk."""

from __future__ import annotations

import argparse
import os
import sys
import urllib.parse

from . import __version__
from .checks import cookie_checks, exposure_checks, header_checks, tls_checks
from .fetch import DEFAULT_USER_AGENT, fetch, utc_now
from .models import Report
from .report import render
from .scoring import score

FORMATS = ("text", "md", "html", "json")
EXTENSIONS = {"text": "txt", "md": "md", "html": "html", "json": "json"}


def normalise_target(target: str) -> str:
    if "://" not in target:
        target = "https://" + target
    parsed = urllib.parse.urlsplit(target)
    if parsed.scheme not in ("http", "https"):
        raise SystemExit(f"error: only http/https targets are supported (got {parsed.scheme!r})")
    if not parsed.hostname:
        raise SystemExit(f"error: could not parse a hostname from {target!r}")
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, "")
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="headerhawk",
        description=(
            "Audit HTTP security headers, cookies, TLS and accidental file exposure "
            "for a single URL. Passive, read-only, standard library only."
        ),
        epilog=(
            "examples:\n"
            "  headerhawk https://example.com\n"
            "  headerhawk example.com --probe --format html --out reports\n"
            "  headerhawk https://example.com --format json --out reports --quiet\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="URL or hostname to audit")
    parser.add_argument("--probe", action="store_true", help="enable sensitive-path probes (adds requests)")
    parser.add_argument("--timeout", type=float, default=10.0, help="per-request timeout in seconds (default: 10)")
    parser.add_argument("--format", choices=FORMATS, default="text", help="stdout format (default: text)")
    parser.add_argument(
        "--out",
        metavar="DIR",
        help="also write the report to DIR as report.{md,html,json} (all formats)",
    )
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="override the User-Agent header")
    parser.add_argument("--cacert", metavar="PATH", help="CA bundle to trust (default: auto-detect)")
    parser.add_argument("--insecure", action="store_true", help="do not verify TLS certificates (audit only)")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour in text output")
    parser.add_argument("--quiet", action="store_true", help="suppress stdout, only write files")
    parser.add_argument("--version", action="version", version=f"headerhawk {__version__}")
    return parser


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    target = normalise_target(args.target)

    response = fetch(
        target,
        timeout=args.timeout,
        user_agent=args.user_agent,
        verify_tls=not args.insecure,
        cafile=args.cacert,
    )

    checks = []
    checks.extend(header_checks(response))
    checks.extend(cookie_checks(response))
    checks.extend(tls_checks(response))
    probed = []
    if args.probe:
        exposure, probed = exposure_checks(
            response,
            timeout=args.timeout,
            user_agent=args.user_agent,
            verify_tls=not args.insecure,
            cafile=args.cacert,
        )
        checks.extend(exposure)

    value, grade, _label = score(checks)
    report = Report(
        target=target,
        final_url=response.final_url,
        generated_at=utc_now(),
        score=value,
        grade=grade,
        checks=checks,
        response=response,
        probed=probed,
    )

    if not args.quiet:
        sys.stdout.write(render(report, args.format, colour=not args.no_color) + "\n")

    if args.out:
        os.makedirs(args.out, exist_ok=True)
        for fmt in ("md", "html", "json"):
            path = os.path.join(args.out, f"report.{EXTENSIONS[fmt]}")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(render(report, fmt))
            if not args.quiet:
                sys.stderr.write(f"wrote {path}\n")

    if response.error and response.status == 0:
        return 2
    return 1 if any(c.status == "fail" for c in checks) else 0


def main() -> None:
    raise SystemExit(run())
