"""Command-line interface."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from . import __version__
from .config import Settings
from .domains import registrable


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="domainfinder",
        description="Find more domains owned by the company behind a seed domain, each backed by evidence.",
    )
    p.add_argument("domain", nargs="?", help="seed root domain, e.g. adp.com")
    p.add_argument("-o", "--output", type=Path, help="also write results to this file (.csv or .json)")
    p.add_argument("--json", action="store_true", help="print JSON instead of a table")
    p.add_argument("--min-score", type=int, default=None, help="only list owned domains at or above this score")
    p.add_argument("--high-threshold", type=int, help="score needed for the main list (default 70)")
    p.add_argument("--review-threshold", type=int, help="score needed for needs-review (default 40)")
    p.add_argument("--include-review", action="store_true", default=True,
                   help="show the needs-review section (default on)")
    p.add_argument("--no-review", dest="include_review", action="store_false", help="hide the needs-review section")
    p.add_argument("-v", "--verbose", action="store_true", help="also show rejected domains, sources and notes")
    p.add_argument("--org", action="append", default=[],
                   help="the seed's legal organization name (repeatable); otherwise derived from TLS/CT/RDAP")
    p.add_argument("--brand", action="append", default=[], help="extra brand label for ccTLD permutations (repeatable)")
    p.add_argument("--candidate", action="append", default=[], help="also verify this domain (repeatable)")
    p.add_argument("--sources", help="comma-separated list of sources to use (see --list-sources)")
    p.add_argument("--skip", default="", help="comma-separated list of sources to skip")
    p.add_argument("--no-hackertarget", action="store_true", help="do not use HackerTarget's free quota")
    p.add_argument("--max-candidates", type=int, default=1000, help="verify at most this many candidates")
    p.add_argument("--concurrency", type=int, help="candidates fingerprinted in parallel")
    p.add_argument("--dns", choices=["auto", "system", "doh"], help="DNS mode (default auto)")
    p.add_argument("--no-tls", action="store_true", help="skip live TLS certificate checks")
    p.add_argument("--no-whois", action="store_true", help="skip the port-43 WHOIS fallback (.edu)")
    p.add_argument("--no-cache", action="store_true", help="ignore and do not write the on-disk cache")
    p.add_argument("--cache-ttl", type=int, help="cache lifetime in hours (default 24)")
    p.add_argument("--idn", choices=["unicode", "punycode"],
                   help="write internationalized domains readably (unicode, default) or in ASCII/Punycode; "
                        "CSV and JSON always carry both in domain_unicode / domain_ascii")
    p.add_argument("--list-sources", action="store_true", help="list candidate sources and whether they are on")
    p.add_argument("--debug", action="store_true", help="debug logging to stderr")
    p.add_argument("--version", action="version", version=f"domainfinder {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    # httpx logs every request URL at INFO; keep it quiet (URLs can carry keys).
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    settings = Settings.from_env()
    if args.high_threshold is not None:
        settings.high_threshold = args.high_threshold
    if args.review_threshold is not None:
        settings.review_threshold = args.review_threshold
    if args.no_hackertarget:
        settings.hackertarget = False
    if args.concurrency:
        settings.concurrency = args.concurrency
    if args.dns:
        settings.dns_mode = args.dns
    if args.no_tls:
        settings.tls_check = False
    if args.no_whois:
        settings.whois = False
    if args.no_cache:
        settings.use_cache = False
    if args.cache_ttl is not None:
        settings.cache_ttl_hours = args.cache_ttl
    if args.idn:
        settings.idn = args.idn

    from rich.console import Console

    out = Console(soft_wrap=False)
    if not out.is_terminal:
        out = Console(soft_wrap=False, width=180)  # files and pipes: room for evidence
    err = Console(stderr=True)

    if args.list_sources:
        from .sources import ALL_SOURCES

        for cls in ALL_SOURCES:
            s = cls(settings)
            state = "on" if s.enabled() else f"off ({s.disabled_reason()})"
            print(f"{s.name:15} {'paid' if s.paid else 'free':5} {s.description}\n{'':21} {state}")
        return 0

    if not args.domain:
        build_parser().print_usage(sys.stderr)
        return 2
    seed = registrable(args.domain)
    if not seed:
        err.print(f"[red]Not a registrable domain: {args.domain}[/red]")
        return 2

    from .pipeline import run
    from .report import print_table, to_csv, to_json

    only = [s.strip() for s in args.sources.split(",")] if args.sources else None
    skip = [s.strip() for s in args.skip.split(",") if s.strip()]

    status = err.status(f"fingerprinting {seed}…") if err.is_terminal else None

    def progress(stage: str, done: int, total: int):
        msg = f"{stage} {done}/{total}" if total else stage
        if status:
            status.update(msg)
        elif args.debug:
            err.print(msg)

    try:
        if status:
            status.start()
        rep = asyncio.run(run(
            seed, settings, user_orgs=args.org, extra_brands=args.brand, only_sources=only,
            skip_sources=skip, extra_candidates=args.candidate, max_candidates=args.max_candidates,
            progress=progress,
        ))
    except KeyboardInterrupt:
        err.print("[red]interrupted[/red]")
        return 130
    finally:
        if status:
            status.stop()

    if args.min_score is not None:
        from .models import Classification

        rep.results = [r for r in rep.results
                       if r.classification is not Classification.OWNED or r.score >= args.min_score]

    if args.json:
        sys.stdout.write(to_json(rep, include_rejected=args.verbose, idn=settings.idn) + "\n")
    else:
        print_table(rep, out, include_review=args.include_review, verbose=args.verbose, idn=settings.idn)

    if args.output:
        suffix = args.output.suffix.lower()
        if suffix == ".json":
            args.output.write_text(to_json(rep, include_rejected=True, include_fingerprints=True, idn=settings.idn),
                                   encoding="utf-8")
        else:
            # UTF-8 with a byte-order mark, so Excel shows 信息 instead of mojibake.
            args.output.write_text(to_csv(rep, include_rejected=args.verbose, idn=settings.idn), encoding="utf-8-sig")
        err.print(f"wrote {args.output}")
    return 0
