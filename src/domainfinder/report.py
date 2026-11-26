"""[4] Output: table, CSV and JSON."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

from . import BANNER
from .domains import display, humanize, to_ascii, to_unicode
from .models import Classification, Result
from .pipeline import RunReport


def to_json(rep: RunReport, include_rejected: bool = True, include_fingerprints: bool = False,
            idn: str = "unicode") -> str:
    def section(cls):
        return [r.to_dict(include_fingerprints, idn) for r in rep.by_class(cls)]

    fp = rep.seed_fingerprint
    doc = {
        "tool": BANNER,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "seed": display(rep.seed, idn),
        "seed_ascii": to_ascii(rep.seed),
        "idn_format": idn,
        "seed_fingerprint": {
            "org_names": rep.org_names,
            "brand_labels": rep.brand_labels,
            "registrar": fp.rdap.registrar,
            "registrant_region": fp.rdap.region_key(),
            "nameservers": fp.ns,
            "mx": fp.mx,
            "mail_tenants": fp.mail_tenants,
            "netblocks": [nb.label() for nb in fp.netblocks],
            "spf_includes": fp.spf_includes,
            "verification_tokens": fp.verification_tokens,
            "analytics_ids": fp.web.analytics_ids,
            "cert_org": fp.cert.subject_org,
        },
        "sources_used": rep.sources_used,
        "sources_disabled": rep.sources_disabled,
        "notes": [humanize(n, idn) for n in rep.notes],
        "candidates_total": rep.candidates_total,
        "candidates_verified": rep.candidates_verified,
        "owned": section(Classification.OWNED),
        "needs_review": section(Classification.REVIEW),
    }
    if include_rejected:
        doc["rejected"] = section(Classification.REJECTED)
    return json.dumps(doc, indent=2, ensure_ascii=False)


CSV_FIELDS = ["domain", "classification", "score", "status", "sources", "evidence", "domain_ascii", "domain_unicode"]


def to_csv(rep: RunReport, include_rejected: bool = False, idn: str = "unicode") -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_FIELDS)
    classes = [Classification.OWNED, Classification.REVIEW] + ([Classification.REJECTED] if include_rejected else [])
    for cls in classes:
        for r in rep.by_class(cls):
            w.writerow([
                display(r.domain, idn), r.classification.value, r.score, humanize(r.status, idn),
                "; ".join(r.sources),
                humanize(" | ".join(f"{e.detail} ({e.points:+d})" for e in r.evidence if e.points), idn),
                to_ascii(r.domain), to_unicode(r.domain),
            ])
    return buf.getvalue()


def _rows(results: list[Result], verbose: bool, idn: str):
    for r in results:
        yield (display(r.domain, idn), str(r.score), humanize(r.status, idn),
               humanize(r.summary(6 if verbose else 3), idn), ", ".join(r.sources))


def print_table(rep: RunReport, console, *, include_review: bool = True, verbose: bool = False, min_score: int = 0,
                idn: str = "unicode") -> None:
    from rich.table import Table

    fp = rep.seed_fingerprint
    console.print(f"[bold]Seed[/bold] {display(rep.seed, idn)}")
    console.print(f"  organization: {', '.join(rep.org_names) or '[yellow]unknown (pass --org)[/yellow]'}")
    if fp.rdap.registrar:
        console.print(f"  registrar: {fp.rdap.registrar}  registrant region: {fp.rdap.region_key() or '-'}")
    console.print(f"  nameservers: {', '.join(fp.ns) or '-'}")
    if fp.mail_tenants:
        console.print(f"  mail tenant: {', '.join(fp.mail_tenants)}")
    for nb in fp.netblocks:
        console.print(f"  netblock: {nb.label()}")
    console.print(
        f"  candidates: {rep.candidates_total} found, {rep.candidates_verified} verified; "
        f"sources: {', '.join(rep.sources_used)}"
    )
    sections = [(Classification.OWNED, "High-confidence domains", "green")]
    if include_review:
        sections.append((Classification.REVIEW, "Needs review (never counted as owned)", "yellow"))
    if verbose:
        sections.append((Classification.REJECTED, "Rejected", "red"))
    for cls, title, colour in sections:
        res = [r for r in rep.by_class(cls) if cls is not Classification.OWNED or r.score >= min_score]
        t = Table(title=f"{title} ({len(res)})", title_style=f"bold {colour}", show_lines=False, expand=True)
        t.add_column("domain", style="bold", no_wrap=True)
        t.add_column("score", justify="right", no_wrap=True)
        t.add_column("status", overflow="fold", max_width=26)
        t.add_column("evidence", overflow="fold", min_width=40, ratio=1)
        if verbose:
            t.add_column("found by", overflow="fold", max_width=20)
        for row in _rows(res, verbose, idn):
            t.add_row(*(row if verbose else row[:4]))
        console.print(t)
    if verbose and rep.notes:
        console.print("[bold]Notes[/bold]")
        for n in rep.notes:
            console.print(f"  - {humanize(n, idn)}")
    off = {k: v for k, v in rep.sources_disabled.items() if v != "not selected"}
    if off:
        console.print("[dim]Disabled sources: " + "; ".join(f"{k} ({v})" for k, v in off.items()) + "[/dim]")
