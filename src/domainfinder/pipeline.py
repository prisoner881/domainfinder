"""Orchestration: fingerprint the seed → gather candidates → verify → classify."""

from __future__ import annotations

import asyncio
from collections import Counter
import logging
import time
from dataclasses import dataclass, field
from typing import Callable

from .cache import CACHE_FILE, Cache
from .collectors.gleif import seed_family
from .collectors.rdap import RdapClient
from .config import Settings
from .dns import Resolver
from .domains import label, registrable
from .collectors.web import chain_domains, own_page
from .fingerprint import Collectors, fingerprint
from .http import Http
from .models import Candidate, Classification, Fingerprint, Result
from .orgnames import any_match as any_match_name
from .orgnames import is_meaningful, same_org
from .rootcheck import RootCheck, check_root
from .sources import ALL_SOURCES, Source, SourceContext
from .sources.crtsh import collect_org_hits, crtsh_json, seed_org_from_ct
from .verify import Scorer, SeedProfile, channel_of, infra_channels, plausible_org_for_label, score_all

log = logging.getLogger(__name__)

# When there are more candidates than --max-candidates, verify these first.
SOURCE_PRIORITY = ["root-check", "manual", "import", "whoisxml", "crtsh-org", "wikidata", "seed-links", "cctld", "gtld", "crtsh-san", "hackertarget", "viewdns", "edgar"]


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
    gleif: dict | None = None  # the seed's legal entity, subsidiaries count, parents (GLEIF)

    def parent_warning(self) -> str:
        """Set when GLEIF says the seed's organization is itself a subsidiary."""
        g = self.gleif or {}
        p = g.get("ultimate_parent") or g.get("direct_parent")
        if not p:
            return ""
        e = g["entity"]
        direct = g.get("direct_parent")
        via = (f" (directly owned by {direct['legal_name']})"
               if direct and g.get("ultimate_parent") and direct["lei"] != g["ultimate_parent"]["lei"] else "")
        return (f"{e['legal_name']}, the organization behind {self.seed}, is a subsidiary of {p['legal_name']} "
                f"({p['country'] or 'country unknown'}, LEI {p['lei']}){via} according to GLEIF. These results cover "
                f"{e['legal_name']} and its own subsidiaries only, not the parent or the parent's other subsidiaries.")

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
    max_candidates: int = 3000,
    progress: Callable[[str, int, int], None] | None = None,
    attested: list[tuple[str, str]] | None = None,
) -> RunReport:
    supplied = seed
    seed = registrable(seed) or seed
    cache = Cache(settings.cache_dir / CACHE_FILE, settings.cache_ttl_hours * 3600, enabled=settings.use_cache,
                  max_stale=max(0, settings.cache_max_stale_days) * 86400)
    http = Http(cache=cache, timeout=settings.http_timeout)
    resolver = Resolver(http, cache=cache, mode=settings.dns_mode)
    collectors = Collectors(http=http, resolver=resolver, rdap=RdapClient(http), tls_check=settings.tls_check,
                            whois=settings.whois)
    from .sources.crtsh_db import CURRENT, CrtshDb

    db = (CrtshDb(limit=settings.crtsh_db_limit, search_timeout=settings.crtsh_db_timeout)
          if settings.crtsh_db else None)
    token = CURRENT.set(db)
    try:
        return await _run(seed, supplied, settings, collectors, user_orgs or [], extra_brands or [], only_sources,
                          skip_sources or [], extra_candidates or [], imported_candidates or [],
                          import_notes or [], max_candidates, progress, attested or [])
    finally:
        CURRENT.reset(token)
        if db is not None:
            await db.aclose()
        await http.aclose()
        cache.close()


async def _run(seed, supplied, settings, collectors, user_orgs, extra_brands, only_sources, skip_sources,
               extra_candidates, imported_candidates, import_notes, max_candidates, progress,
               attested=()) -> RunReport:
    def tick(stage: str, done: int = 0, total: int = 0):
        if progress:
            progress(stage, done, total)

    tick("fingerprinting seed")
    seed_fp = await fingerprint(seed, collectors)
    # From here on, registrar RDAP lookups wait until scoring shows which
    # domains they could change (registrars rate limit, some for a day).
    collectors.rdap.defer_registrar = True
    collectors.rdap.whois_fallback = settings.whois
    ns_stats = {"checked": 0, "changed": 0}
    if seed_fp.ns:  # the seed's own set is what every candidate is compared with
        await refresh_ns(seed_fp, collectors.resolver, ns_stats)
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
    fam, gleif_note = None, ""
    if settings.gleif and org_names:
        tick("looking up the organization in GLEIF")
        cc = seed_fp.rdap.registrant_country.strip()
        try:
            fam, why = await seed_family(collectors.http, org_names, cc if len(cc) == 2 else "")
        except Exception as e:  # noqa: BLE001 - GLEIF is enrichment; it must never sink the run
            log.debug("gleif lookup failed", exc_info=True)
            fam, why = None, f"lookup failed: {type(e).__name__}"
        if fam:
            gleif_note = (f"gleif: {fam.entity.legal_name} (LEI {fam.entity.lei}); {len(fam.children)} consolidated "
                          f"subsidiar{'y' if len(fam.children) == 1 else 'ies'} listed, whose names count as the "
                          f"organization's")
            if fam.parent():
                gleif_note += f"; IT IS ITSELF A SUBSIDIARY OF {fam.parent().legal_name} (LEI {fam.parent().lei})"
        else:
            gleif_note = f"gleif: not used ({why})"

    ctx = SourceContext(seed=seed_fp, settings=settings, collectors=collectors,
                        org_names=org_names, brand_labels=brand_labels)
    if tls_note:
        ctx.notes.append(tls_note)
    if gleif_note:
        ctx.notes.append(gleif_note)
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
    # Domains the organization attests it owns: owned on its word, never cut
    # by --max-candidates, and reference points for the others.
    attested_set: set[str] = set()
    for d, origin in attested:
        rd = registrable(d)
        if rd and rd != seed:
            attested_set.add(rd)
            merged.setdefault(rd, Candidate(domain=rd)).add_source("attested", f"attested by the organization ({origin})")
    ctx.notes[:0] = import_notes
    merged.pop(seed, None)

    cands = sorted(merged.values(), key=_priority)
    total = len(cands)
    if len(cands) > max_candidates:
        given = [c for c in cands if {"manual", "import", "root-check", "attested"} & set(c.sources)]
        found = [c for c in cands if not {"manual", "import", "root-check", "attested"} & set(c.sources)]
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
                # A long attested list gets a light fingerprint (no website or
                # TLS): the comparisons that use it are DNS, mail and network.
                light = c.domain in attested_set and len(attested_set) > ATTESTED_FULL_LIMIT
                fp = await fingerprint(c.domain, collectors, web=not light)
                if ns_partial(fp.ns, seed_fp.ns):
                    await refresh_ns(fp, collectors.resolver, ns_stats)
            except Exception as e:
                log.exception("fingerprint %s failed", c.domain)
                fp = Fingerprint(domain=c.domain, errors=[f"{type(e).__name__}: {e}"])
        done += 1
        tick(stage, done, stage_total)
        return fp, c

    stage, stage_total = "verifying candidates", len(cands)
    items = list(await asyncio.gather(*(fp_one(c) for c in cands)))
    scoring_orgs = list(org_names)
    if fam:
        from .orgnames import any_match

        for n in fam.names():
            if not any_match(n, scoring_orgs):
                scoring_orgs.append(n)
    if attested_set:
        scoring_orgs += await attested_names(collectors, items, attested_set, org_names, ctx)
    profile = SeedProfile.build(seed_fp, scoring_orgs, brand_labels)
    profile.ns_shared_override = ns_shared
    scorer = Scorer(profile, settings.high_threshold, settings.review_threshold,
                    ctx.ct_org_domains, ctx.subsidiary_names, ctx.shared_ns_domains, ctx.ct_cocerts)
    scorer.attested = attested_set
    scorer.anchors = [fp for fp, _ in items if fp.domain in attested_set and fp.registered is not False]
    results = score_all(scorer, items)
    results = await complete_registrars(collectors, scorer, items, results, tick)
    verified_count = len(cands)

    # Second pass, one hop out, all verified like any other candidate:
    #  * domains named in the CSP or on the TLS certificate of owned/review domains;
    #  * domains with certificates in the name of an acquired company, a name
    #    learned from an owned domain proven by two infrastructure matches.
    def pseudo_on(name: str) -> bool:
        return name not in skip_sources and (not only_sources or name in only_sources)

    known = {c.domain for c in cands} | {seed}
    second: dict[str, Candidate] = {}
    # No discovery from domains that are owned only on the organization's
    # word: hundreds of attested domains would multiply the run.
    hop_from = [r for r in results if not (r.domain in attested_set and set(r.sources) == {"attested"})]
    if settings.acquisitions and pseudo_on("acq-ct"):
        names = acquisition_names(hop_from, org_names)
        for name, origin in names:
            hits: dict = {}
            for extra in ({"exclude": "expired"}, {}):
                rows = await crtsh_json(collectors.http, {"O": name, **extra}, settings.crtsh_timeout)
                if rows:
                    collect_org_hits(rows, [name], hits)
            hits.pop(seed, None)
            # A name GLEIF lists in the organization's family is the
            # organization's own: its certificates count in full. GLEIF lags on
            # acquisitions, so a name it does not confirm is not rejected,
            # only weighed as an acquired company's.
            confirmed = bool(fam) and any_match_name(name, fam.names())
            for dom, hit in hits.items():
                if not confirmed:
                    hit.acquired = origin
                scorer.ct.setdefault(dom, hit)  # evidence in the seed's own name wins
                if dom not in known and dom not in second:
                    second[dom] = Candidate(domain=dom, sources={"acq-ct": f"certificate O={name} (name from {origin})"})
            ctx.notes.append(f"acquisitions: CT search for {name!r} (named by owned {origin}"
                             f"{'; a subsidiary according to GLEIF' if confirmed else ''}): {len(hits)} domain(s)")
        if names:
            used.append("acq-ct")
    elif not settings.acquisitions:
        disabled["acq-ct"] = "turned off (DOMAINFINDER_ACQUISITIONS=0)"
    use_csp = settings.csp_discovery and pseudo_on("csp")
    if not settings.csp_discovery:
        disabled["csp"] = "turned off (--no-csp)"
    for c in hop_candidates(hop_from, known, seed, use_csp=use_csp, use_certs=pseudo_on("cert-san"),
                            use_redirects=pseudo_on("redirect-target")):
        if c.domain in second:
            for k, v in c.sources.items():
                second[c.domain].add_source(k, v)
        else:
            second[c.domain] = c
    if second:
        new = sorted(second.values(), key=lambda c: c.domain)
        by_src = Counter(k for c in new for k in c.sources)
        budget = max(0, max_candidates - len(cands))
        picked = new[:budget]
        ctx.notes.append("second pass: " + ", ".join(f"{n} from {k}" for k, n in sorted(by_src.items()))
                         + (f"; verifying {len(picked)} of {len(new)} (--max-candidates)" if len(picked) < len(new) else ""))
        for k in ("csp", "cert-san", "redirect-target"):
            if by_src.get(k) and k not in used:
                used.append(k)
        if picked:
            done, stage, stage_total = 0, "verifying second-pass candidates", len(picked)
            items += list(await asyncio.gather(*(fp_one(c) for c in picked)))
            total += len(new)
            verified_count += len(picked)
    if second or scorer.ct:
        results = score_all(scorer, items)
        results = await complete_registrars(collectors, scorer, items, results, tick)
    if ns_stats["checked"]:
        ctx.notes.append(f"dns: {ns_stats['checked']} nameserver set(s) only partly matching the seed's re-read from "
                         f"the domains' own nameservers; {ns_stats['changed']} changed")
    note = registrar_note(collectors.rdap)
    if note:
        ctx.notes.append(note)
    ctx.notes.append(cache_note(collectors.http))
    from .sources.crtsh_db import CURRENT

    db = CURRENT.get()
    if db is not None and (db.queries or db.fallbacks or db.disabled_reason):
        ctx.notes.append(db.summary())
    return RunReport(
        seed=seed, seed_fingerprint=seed_fp, org_names=org_names, brand_labels=brand_labels,
        sources_used=used, sources_disabled=disabled, notes=ctx.notes, results=results,
        candidates_total=total, candidates_verified=verified_count, http_stats=dict(collectors.http.stats),
        root_check=root,
        gleif=({"entity": fam.entity.to_dict(), "subsidiaries": len(fam.children),
                "direct_parent": fam.direct_parent.to_dict() if fam.direct_parent else None,
                "ultimate_parent": fam.ultimate_parent.to_dict() if fam.ultimate_parent else None}
               if fam else None),
    )


def ns_partial(ns: list[str], seed_ns: list[str]) -> bool:
    """Shares some but not all nameservers with the seed: possibly a partial
    answer (a registry's delegation) rather than the domain's real set."""
    a, b = set(ns), set(seed_ns)
    return bool(a & b) and a != b


async def refresh_ns(fp: Fingerprint, resolver, stats: dict[str, int] | None = None) -> None:
    """Replace a resolver's NS answer with the set the domain's own
    nameservers publish, when one of them answers authoritatively."""
    ask = getattr(resolver, "authoritative_ns", None)
    if ask is None:
        return
    try:
        ans = await ask(fp.domain, fp.ns)
    except Exception as e:  # never let a second opinion break the fingerprint
        log.debug("authoritative NS for %s failed: %s", fp.domain, e)
        return
    if stats is not None:
        stats["checked"] = stats.get("checked", 0) + 1
    if ans.status == "ok" and ans.records and sorted(set(ans.records)) != sorted(set(fp.ns)):
        log.debug("NS of %s: resolver said %s, its nameservers say %s", fp.domain, fp.ns, ans.records)
        fp.ns = sorted(set(ans.records))
        if stats is not None:
            stats["changed"] = stats.get("changed", 0) + 1


ATTESTED_FULL_LIMIT = 200  # above this many attested domains: light fingerprints, no registrar lookups


async def attested_names(collectors, items, attested_set, org_names, ctx) -> list[str]:
    """Registrant organization names on attested domains: names the
    organization uses (a subsidiary, an acquisition's legal name). Taken from
    registrations only: an attested site on a vendor's platform carries the
    vendor's certificate, and its name must not become the organization's."""
    from .data import load as load_data
    from .orgnames import any_match

    data = load_data()
    if len(attested_set) <= ATTESTED_FULL_LIMIT:
        await collectors.rdap.fetch_deferred(attested_set)
    names: list[str] = []
    for fp, _ in items:
        n = fp.rdap.registrant_org if fp.domain in attested_set else ""
        if (n and is_meaningful(n) and not data.is_proxy_registrant(n, fp.rdap.registrar)
                and not data.is_brand_registrar(n) and not any_match(n, org_names + names)):
            names.append(n)
    note = f"attested: {len(attested_set)} domain(s) owned by the organization's word"
    if len(attested_set) > ATTESTED_FULL_LIMIT:
        note += (f"; more than {ATTESTED_FULL_LIMIT}, so fingerprinted without website/TLS and without "
                 f"registrar lookups")
    if names:
        note += f"; organization name(s) from their registrations: {', '.join(names[:8])}"
    ctx.notes.append(note)
    return names[:20]


def needs_registrar(r: Result) -> bool:
    """Could the registrar's record (registrant, contacts) change this result?

    Not for a domain already owned through two independent infrastructure
    matches: registrant details cannot change that, and even another
    organization's name is overridden there. Not for a domain whose only
    evidence is its name: a registrant match could lift it to needs review at
    most. Held domains always: their classification rests on the registrant
    region."""
    if r.classification is Classification.OWNED and len(infra_channels(r.evidence)) >= 2:
        return False
    if r.status == "held/inactive":
        return True
    return any(e.points > 0 and channel_of(e.kind) not in ("name", "corroboration") for e in r.evidence)


async def complete_registrars(collectors, scorer, items, results, tick=None):
    """Make the deferred registrar lookups that could matter, retry failures
    slowly (then WHOIS), and score again if anything arrived."""
    rdap = collectors.rdap
    need = {r.domain for r in results if needs_registrar(r)} & rdap.deferred()
    if not need and not rdap._retry:
        return results
    if tick:
        tick("registrar lookups", 0, len(need))
    await rdap.fetch_deferred(need)
    if rdap._retry:
        await rdap.retry_failed()
    return score_all(scorer, items)


def registrar_note(rdap) -> str:
    """Registrar lookups made, skipped and failed (with why), back-offs."""
    if not (rdap.registrar_lookups or rdap.deferred()):
        return ""
    note = (f"rdap: {rdap.registrar_lookups} registrar lookup(s) made, {len(rdap.deferred())} not needed "
            f"(result already settled, or name evidence only)")
    reasons: dict[str, list[str]] = {}
    for (host, why), n in rdap.failure_reasons.most_common():
        reasons.setdefault(host, []).append(f"{why} ×{n}")
    if reasons:
        note += "; failed: " + "; ".join(f"{h} ({', '.join(r)})" for h, r in list(reasons.items())[:6])
    cool = rdap.cooldowns()
    if cool:
        note += "; backing off: " + ", ".join(
            f"{h} until {time.strftime('%Y-%m-%d %H:%M', time.localtime(u))}" for h, u in sorted(cool.items()))
    if rdap.registrar_failures:
        note += f"; still without registrar data: {sum(rdap.registrar_failures.values())}"
    if rdap.whois_recovered:
        note += f"; {rdap.whois_recovered} completed from the registrar's WHOIS"
    return note


def cache_note(http) -> str:
    """Where the cache is, how big, how much it answered, and any expired
    answers used because a fresh lookup failed."""
    c = http.cache
    if not c.enabled:
        return "cache: off (--no-cache)"
    s = c.stats
    note = (f"cache: {c.path} ({c.size_bytes() / 1e6:.1f} MB); {s['hit']} answer(s) from cache, "
            f"{s['stored']} stored")
    if s["pruned"]:
        note += f", {s['pruned']} expired entr{'y' if s['pruned'] == 1 else 'ies'} removed"
    if s["write_skipped"]:
        note += f", {s['write_skipped']} write(s) skipped (file busy)"
    if http.stale_hosts:
        note += "; fresh lookups failed, older cached answers used: " + ", ".join(
            f"{host} {n}" for host, n in http.stale_hosts.most_common(6))
    return note


def hop_candidates(results: list[Result], known: set[str], seed: str, *, use_csp: bool = True,
                   use_certs: bool = True, use_redirects: bool = True) -> list[Candidate]:
    """Candidates named in the CSP header (own page only) or on the TLS
    certificate of owned and needs-review results, and the redirect targets
    of owned results."""
    from .collectors.tls import covers
    from .sources.base import make_candidates

    found: dict[str, Candidate] = {}
    known = set(known) | {r.domain for r in results}
    # Only proven domains vouch for a certificate: two needs-review domains on
    # one vendor certificate (athletics sites on the vendor's shared
    # certificate) would otherwise make it look like ours.
    ours = {seed} | {r.domain for r in results if r.classification is Classification.OWNED}

    def add(cands: list[Candidate]):
        for c in cands:
            if c.domain in known:
                continue
            if c.domain in found:
                for k, v in c.sources.items():
                    found[c.domain].add_source(k, v)
            else:
                found[c.domain] = c

    for r in sorted(results, key=lambda r: (r.classification is not Classification.OWNED, r.domain)):
        if r.classification not in (Classification.OWNED, Classification.REVIEW) or r.fingerprint is None:
            continue
        f = r.fingerprint
        if use_redirects and r.classification is Classification.OWNED:
            # Where an owned domain sends its visitors: often a new brand of the
            # same organization. Verified like any other candidate.
            later = [h for h in chain_domains(f.web) if h != r.domain]
            if later:
                add(make_candidates(later[-1:], "redirect-target", seed, f"{r.domain} redirects to it"))
        if use_csp and own_page(f.web, r.domain):  # a redirecting domain's CSP is its target's
            add(make_candidates(f.web.csp_domains, "csp", seed, f"named in the CSP of {r.domain}"))
        cert = f.cert
        if (use_certs and cert.fetched and cert.has_scts
                and (covers(cert.sans, r.domain) or covers(cert.sans, "www." + r.domain))):
            # A certificate naming several other domains, none of them known
            # to be ours, is a shared one (a CDN, or a vendor hosting the
            # site): its names are the vendor's customers, not sister domains.
            others = {registrable(x) for x in cert.sans} - {None, r.domain}
            shared = len(others) > 50 or (len(others) > 3 and not others & ours)
            if not shared:
                add(make_candidates(cert.sans, "cert-san", seed, f"on the TLS certificate of {r.domain}"))
    return list(found.values())


def csp_candidates(results: list[Result], known: set[str], seed: str) -> list[Candidate]:
    """Candidates from the CSP headers of owned and needs-review results (one hop)."""
    return hop_candidates(results, known, seed, use_csp=True, use_certs=False, use_redirects=False)


def acquisition_names(results: list[Result], org_names: list[str], limit: int = 5) -> list[tuple[str, str]]:
    """(name, owned domain) for acquired companies: names on the certificate or
    registration of owned domains proven by two or more infrastructure matches,
    when they are not the seed's own names. Learned from evidence, not guessed."""
    from .data import load as load_data
    from .orgnames import any_match, normalize
    from .verify import infra_channels

    data = load_data()
    out: list[tuple[str, str]] = []
    ranked = sorted((r for r in results if r.classification is Classification.OWNED and r.fingerprint),
                    key=lambda r: (-r.score, r.domain))
    for r in ranked:
        if len(infra_channels(r.evidence)) < 2:
            continue
        f = r.fingerprint
        names = []
        if f.cert.subject_org and f.cert.has_scts:
            names.append(f.cert.subject_org)
        if f.rdap.registrant_org and not data.is_proxy_registrant(f.rdap.registrant_org, f.rdap.registrar):
            names.append(f.rdap.registrant_org)
        for n in names:
            norm = normalize(n)
            if (not is_meaningful(n) or any_match(n, org_names) or data.is_shared_hosting_org(n)
                    or data.is_brand_registrar(n) or (len(norm.split()) < 2 and len(norm) < 8)):
                continue  # the seed's own name, a provider, or too short to search safely
            if any(same_org(n, x) for x, _ in out):
                continue
            out.append((n, r.domain))
            if len(out) >= limit:
                return out
    return out
