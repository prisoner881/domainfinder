"""Orchestration: fingerprint the seed → gather candidates → verify → classify."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Callable

from .cache import Cache
from .collectors.rdap import RdapClient
from .config import Settings
from .dns import Resolver
from .domains import label, registrable
from .fingerprint import Collectors, fingerprint
from .http import Http
from .models import Candidate, Classification, Fingerprint, Result
from .orgnames import is_meaningful, same_org
from .rootcheck import RootCheck, check_root
from .sources import ALL_SOURCES, Source, SourceContext
from .sources.crtsh import seed_org_from_ct
from .verify import Scorer, SeedProfile, plausible_org_for_label, score_all

log = logging.getLogger(__name__)

# When there are more candidates than --max-candidates, verify these first.
SOURCE_PRIORITY = ["root-check", "manual", "import", "whoisxml", "crtsh-org", "seed-links", "cctld", "gtld", "crtsh-san", "hackertarget", "viewdns", "edgar"]


@dataclass
class RunReport:
    seed: str
    seed_fingerprint: Fingerprint
    org_names: list[str]
    brand_labels: list[str]
    sources_used: list[str]
    sources_disabled: dict[str, str]
    notes: list[str]
    results: list[Result]
    candidates_total: int
    candidates_verified: int
    http_stats: dict[str, int] = field(default_factory=dict)
    root_check: RootCheck | None = None

    def by_class(self, cls: Classification) -> list[Result]:
        return sorted(
            (r for r in self.results if r.classification is cls), key=lambda r: (-r.score, r.domain)
        )


def _priority(c: Candidate) -> tuple:
    ranks = [SOURCE_PRIORITY.index(s) if s in SOURCE_PRIORITY else 99 for s in c.sources]
    return (min(ranks) if ranks else 99, -len(c.sources), c.domain)


def derive_org_names(seed_fp: Fingerprint, ct_orgs: list[str], user_orgs: list[str], brand: str) -> list[str]:
    from .data import load as load_data

    data = load_data()
    names: list[str] = []

    def add(n: str):
        if n and is_meaningful(n) and n.strip() not in names:
            names.append(n.strip())

    for n in user_orgs:
        add(n)
    if seed_fp.cert.subject_org and not data.is_shared_hosting_org(seed_fp.cert.subject_org) \
            and not data.is_brand_registrar(seed_fp.cert.subject_org):
        add(seed_fp.cert.subject_org)
    for n in ct_orgs:
        if not data.is_brand_registrar(n):
            add(n)
    r = seed_fp.rdap.registrant_org
    if r and not data.is_proxy_registrant(r, seed_fp.rdap.registrar):
        add(r)
    # A netblock registered to something that looks like the seed's name.
    for nb in seed_fp.netblocks:
        if nb.org and not data.is_shared_hosting_org(nb.org) and plausible_org_for_label(nb.org, brand):
            add(nb.org)
    return names


async def run(
    seed: str,
    settings: Settings,
    *,
    user_orgs: list[str] | None = None,
    extra_brands: list[str] | None = None,
    only_sources: list[str] | None = None,
    skip_sources: list[str] | None = None,
    extra_candidates: list[str] | None = None,
    imported_candidates: list[tuple[str, str]] | None = None,
    import_notes: list[str] | None = None,
    max_candidates: int = 1000,
    progress: Callable[[str, int, int], None] | None = None,
) -> RunReport:
    supplied = seed
    seed = registrable(seed) or seed
    cache = Cache(settings.cache_dir / "cache.sqlite", settings.cache_ttl_hours * 3600, enabled=settings.use_cache)
    http = Http(cache=cache, timeout=settings.http_timeout)
    resolver = Resolver(http, cache=cache, mode=settings.dns_mode)
    collectors = Collectors(http=http, resolver=resolver, rdap=RdapClient(http), tls_check=settings.tls_check,
                            whois=settings.whois)
    try:
        return await _run(seed, supplied, settings, collectors, user_orgs or [], extra_brands or [], only_sources,
                          skip_sources or [], extra_candidates or [], imported_candidates or [],
                          import_notes or [], max_candidates, progress)
    finally:
        await http.aclose()
        cache.close()


async def _run(seed, supplied, settings, collectors, user_orgs, extra_brands, only_sources, skip_sources,
               extra_candidates, imported_candidates, import_notes, max_candidates, progress) -> RunReport:
    def tick(stage: str, done: int = 0, total: int = 0):
        if progress:
            progress(stage, done, total)

    tick("fingerprinting seed")
    seed_fp = await fingerprint(seed, collectors)
    tls_note = ""
    if seed_fp.cert.fetched and not seed_fp.cert.has_scts:
        tls_note = ("tls: the seed's live certificate carries no Certificate Transparency timestamps "
                    "(TLS interception on this network?); live-certificate comparisons are skipped")
    brand = label(seed)
    brand_labels = [brand] + [b.lower() for b in extra_brands if b and b.lower() != brand]
    if "-" in brand:
        first = brand.split("-", 1)[0]
        if len(first) >= 3 and first not in brand_labels:
            brand_labels.append(first)

    ct_orgs: list[str] = []
    if not user_orgs and not seed_fp.cert.subject_org:
        tick("looking up the seed's organization in CT logs")
        ct_orgs = await seed_org_from_ct(collectors.http, seed, settings.crtsh_timeout)
    org_names = derive_org_names(seed_fp, ct_orgs, user_orgs, brand)
    seed_fp.org_names = org_names

    ctx = SourceContext(seed=seed_fp, settings=settings, collectors=collectors,
                        org_names=org_names, brand_labels=brand_labels)
    if tls_note:
        ctx.notes.append(tls_note)
    root = check_root(supplied, seed_fp)
    if root.flagged:
        ctx.notes.insert(0, "root check: " + root.headline())
    elif root.normalized:
        ctx.notes.insert(0, "root check: " + root.normalized)
    sources: list[Source] = [cls(settings) for cls in ALL_SOURCES]
    used, disabled = [], {}
    active = []
    for s in sources:
        if only_sources and s.name not in only_sources:
            disabled[s.name] = "not selected"
        elif s.name in skip_sources:
            disabled[s.name] = "skipped on the command line"
        elif not s.enabled():
            disabled[s.name] = s.disabled_reason()
        else:
            active.append(s)
            used.append(s.name)

    tick("gathering candidates")

    async def safe(s: Source):
        try:
            return await s.candidates(ctx)
        except Exception as e:  # a broken source must not sink the run
            log.exception("source %s failed", s.name)
            ctx.notes.append(f"{s.name}: failed ({type(e).__name__}: {e})")
            return []

    # Reverse-NS providers can tell us when the seed's NS set is mass-used.
    ns_shared = False
    for s in active:
        for h in seed_fp.ns[:2]:
            n = await s.ns_usage(h)
            if n is not None and n > settings.shared_ns_threshold:
                ns_shared = True
                ctx.notes.append(f"{s.name}: {h} serves {n} domains → NS set treated as shared")

    merged: dict[str, Candidate] = {}
    for found in await asyncio.gather(*(safe(s) for s in active)):
        for c in found:
            m = merged.setdefault(c.domain, Candidate(domain=c.domain))
            for k, v in c.sources.items():
                m.add_source(k, v)
            m.hints.extend(c.hints)
    if root.suggested and root.suggested != seed:
        merged.setdefault(root.suggested, Candidate(domain=root.suggested)).add_source(
            "root-check", "suggested real root of the supplied domain")
    for d in extra_candidates:
        rd = registrable(d)
        if rd and rd != seed:
            merged.setdefault(rd, Candidate(domain=rd)).add_source("manual", "given with --candidate")
    # Domains found by other processes: verified exactly like discovered ones.
    for d, origin in imported_candidates:
        rd = registrable(d)
        if rd and rd != seed:
            merged.setdefault(rd, Candidate(domain=rd)).add_source("import", f"imported from {origin}")
    ctx.notes[:0] = import_notes
    merged.pop(seed, None)

    cands = sorted(merged.values(), key=_priority)
    total = len(cands)
    if len(cands) > max_candidates:
        given = [c for c in cands if {"manual", "import", "root-check"} & set(c.sources)]
        found = [c for c in cands if not {"manual", "import", "root-check"} & set(c.sources)]
        keep = max(0, max_candidates - len(given))
        ctx.notes.append(f"verifying {len(given)} given/imported + the first {keep} of {len(found)} discovered "
                         f"candidates (--max-candidates)")
        cands = given + found[:keep]

    sem = asyncio.Semaphore(max(1, settings.concurrency))
    done = 0

    async def fp_one(c: Candidate) -> tuple[Fingerprint, Candidate]:
        nonlocal done
        async with sem:
            try:
                fp = await fingerprint(c.domain, collectors)
            except Exception as e:
                log.exception("fingerprint %s failed", c.domain)
                fp = Fingerprint(domain=c.domain, errors=[f"{type(e).__name__}: {e}"])
        done += 1
        tick(stage, done, stage_total)
        return fp, c

    stage, stage_total = "verifying candidates", len(cands)
    items = list(await asyncio.gather(*(fp_one(c) for c in cands)))
    profile = SeedProfile.build(seed_fp, org_names, brand_labels)
    profile.ns_shared_override = ns_shared
    scorer = Scorer(profile, settings.high_threshold, settings.review_threshold,
                    ctx.ct_org_domains, ctx.subsidiary_names)
    results = score_all(scorer, items)
    verified_count = len(cands)

    # One hop out: domains named in the Content-Security-Policy of owned and
    # needs-review domains become candidates, verified like any other.
    use_csp = settings.csp_discovery and "csp" not in skip_sources and (not only_sources or "csp" in only_sources)
    if use_csp:
        new = csp_candidates(results, {c.domain for c in cands} | {seed}, seed)
        budget = max(0, max_candidates - len(cands))
        if new:
            picked = new[:budget]
            ctx.notes.append(f"csp: {len(new)} new candidate(s) named in the Content-Security-Policy of owned or "
                             f"needs-review domains" + (f"; verifying {len(picked)} (--max-candidates)"
                                                         if len(picked) < len(new) else ""))
            if picked:
                done, stage, stage_total = 0, "verifying CSP candidates", len(picked)
                items += list(await asyncio.gather(*(fp_one(c) for c in picked)))
                results = score_all(scorer, items)
                total += len(new)
                verified_count += len(picked)
                used.append("csp")
    elif not settings.csp_discovery:
        disabled["csp"] = "turned off (--no-csp)"
    return RunReport(
        seed=seed, seed_fingerprint=seed_fp, org_names=org_names, brand_labels=brand_labels,
        sources_used=used, sources_disabled=disabled, notes=ctx.notes, results=results,
        candidates_total=total, candidates_verified=verified_count, http_stats=dict(collectors.http.stats),
        root_check=root,
    )


def csp_candidates(results: list[Result], known: set[str], seed: str) -> list[Candidate]:
    """Candidates from the CSP headers of owned and needs-review results (one hop)."""
    from .sources.base import make_candidates

    found: dict[str, Candidate] = {}
    for r in sorted(results, key=lambda r: (r.classification is not Classification.OWNED, r.domain)):
        if r.classification not in (Classification.OWNED, Classification.REVIEW) or r.fingerprint is None:
            continue
        for c in make_candidates(r.fingerprint.web.csp_domains, "csp", seed, f"named in the CSP of {r.domain}"):
            if c.domain not in known and c.domain not in found:
                found[c.domain] = c
    return list(found.values())
