"""Certificate Transparency via crt.sh: by organization name and by seed domain."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

from ..domains import registrable
from ..http import Http
from ..models import Candidate
from ..orgnames import same_org
from .base import CtOrgHit, Source, SourceContext, make_candidates

log = logging.getLogger(__name__)

CRTSH = "https://crt.sh/"
CT_TTL = 3 * 86400
# Issuers that only do domain validation never carry O=; skip them when
# looking for the seed's organization name.
DV_ISSUERS = re.compile(r"let's encrypt|letsencrypt|zerossl|\bR3\b|\bE[1-9]\b|\bR1[0-4]\b|domain validat|\bDV\b|"
                        r"cpanel|amazon|google trust|gts ca|cloudflare", re.I)


def _variants(params: dict[str, str]) -> list[tuple[str, dict[str, str]]]:
    """URL forms to try, in order. crt.sh intermittently answers one form of a
    large query with 404/502/504 while another form of the same query works."""
    out = [(CRTSH, {**params, "output": "json"}), (CRTSH + "json", dict(params))]
    if "exclude" in params:  # last resort: include expired certs (filtered later)
        bare = {k: v for k, v in params.items() if k != "exclude"}
        out += [(CRTSH + "json", bare), (CRTSH, {**bare, "output": "json"})]
    return out


WEB_CAP = 10_000  # crt.sh's web API stops every search at 10,000 identities


class CtRows(list):
    """crt.sh rows, with where they came from and whether the row limit cut them off."""

    def __init__(self, rows=(), backend: str = "web", cap: int = WEB_CAP):
        super().__init__(rows)
        self.backend = backend
        self.cap = cap

    @property
    def truncated(self) -> bool:
        if self.backend == "database":  # exact: identities fetched vs the LIMIT
            return sum(int(r.get("result_count") or 1) for r in self) >= self.cap
        return len(self) >= self.cap - 10


async def crtsh_json(http: Http, params: dict[str, str], timeout: float) -> CtRows | None:
    """A crt.sh search: the public database first, the web API if that fails."""
    from .crtsh_db import CURRENT

    db = CURRENT.get()
    if db is not None and not db.disabled_reason:
        key = f"CTDB {db.limit} " + json.dumps(params, sort_keys=True)
        cached = http.cache.get(key, CT_TTL)
        if isinstance(cached, list):
            return CtRows(cached, "database", db.limit)
        rows = await db.search(params, timeout)
        if rows is not None:
            http.cache.set(key, rows)
            return CtRows(rows, "database", db.limit)
    rows = await _crtsh_web(http, params, timeout)
    return None if rows is None else CtRows(rows, "web", WEB_CAP)


async def _crtsh_web(http: Http, params: dict[str, str], timeout: float) -> list[dict] | None:
    last = ""
    for url, p in _variants(params):
        # Failures are never cached: crt.sh's 404s are transient, not "no data".
        r = await http.get(url, params=p, ttl=CT_TTL, timeout=timeout, retries=2, cache_404=False)
        ctype = r.headers.get("content-type", "")
        if not r.ok or ("json" not in ctype and not r.text.lstrip().startswith(("[", "{"))):
            last = f"HTTP {r.status or r.error}"
            log.debug("crt.sh %s %s failed: %s", url, p, last)
            continue
        try:
            data = json.loads(r.text) if r.text.strip() else []
        except ValueError:
            last = "non-JSON answer"
            continue
        if isinstance(data, list):
            return data
    log.info("crt.sh %s failed in every URL form (%s)", params, last)
    return None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(s: str) -> datetime | None:
    try:
        return datetime.fromisoformat(s.replace("Z", "")).replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None


def collect_org_hits(rows: list[dict], org_names: list[str], hits: dict[str, CtOrgHit], current_window_days: int = 400) -> None:
    cutoff = _now() - timedelta(days=current_window_days)
    for row in rows:
        o = str(row.get("name_value") or "")
        if org_names and not any(same_org(o, n) for n in org_names):
            continue  # crt.sh's O= search is fuzzy; keep only real matches
        cn = str(row.get("common_name") or "")
        rd = registrable(cn)
        if not rd:
            continue
        h = hits.setdefault(rd, CtOrgHit(org=o.strip()))
        h.count += 1
        na = str(row.get("not_after") or "")
        if na > h.latest_not_after:
            h.latest_not_after = na
        dt = _parse_dt(na)
        if dt and dt >= cutoff:
            h.current = True


class CrtshOrgSource(Source):
    name = "crtsh-org"
    description = "crt.sh: certificates whose Subject O= is the seed's organization"

    async def candidates(self, ctx: SourceContext) -> list[Candidate]:
        if not ctx.org_names:
            ctx.notes.append("crtsh-org: no organization name known for the seed (use --org)")
            return []
        hits: dict[str, CtOrgHit] = {}
        for org in ctx.org_names[:3]:
            for extra in ({"exclude": "expired"}, {}):
                rows = await crtsh_json(ctx.http, {"O": org, **extra}, self.settings.crtsh_timeout)
                if rows is None:
                    ctx.notes.append(f"crtsh-org: query O={org!r} {extra or ''} failed")
                    continue
                if rows.truncated:
                    ctx.notes.append(f"crtsh-org: O={org!r} hit the {rows.cap:,}-row limit of crt.sh's "
                                     f"{rows.backend}; results truncated")
                collect_org_hits(rows, ctx.org_names, hits)
        hits.pop(ctx.seed.domain, None)
        ctx.ct_org_domains.update(hits)
        out = make_candidates(hits.keys(), self.name, ctx.seed.domain)
        for c in out:
            h = hits[c.domain]
            c.sources[self.name] = f"{h.count} cert(s) O={h.org}, latest expiry {h.latest_not_after[:10]}"
        return out


class CrtshDomainSource(Source):
    name = "crtsh-san"
    description = "crt.sh: other registrable domains in the SANs of the seed's certificates"

    async def candidates(self, ctx: SourceContext) -> list[Candidate]:
        seed = ctx.seed.domain
        names: Counter[str] = Counter()
        now = _now()
        seen_certs: set = set()
        for q in (seed, f"%.{seed}"):
            rows = await crtsh_json(ctx.http, {"q": q, "exclude": "expired"}, self.settings.crtsh_timeout)
            if rows is None:
                ctx.notes.append(f"crtsh-san: query {q!r} failed")
                continue
            for row in rows:
                regs = sorted({rd for rd in (registrable(n) for n in str(row.get("name_value") or "").split("\n")) if rd})
                for rd in regs:
                    if rd != seed:
                        names[rd] += 1
                # Current certificates covering the seed and other domains: one
                # party proved control of all of them to the CA (scorer evidence).
                na = _parse_dt(str(row.get("not_after") or ""))
                key = tuple(regs)
                if seed in regs and len(regs) > 1 and na and na >= now and key not in seen_certs:
                    seen_certs.add(key)
                    for rd in regs:
                        if rd != seed:
                            lst = ctx.ct_cocerts.setdefault(rd, [])
                            if len(lst) < 5:
                                lst.append(list(regs))
        out = make_candidates(names.keys(), self.name, seed)
        for c in out:
            c.sources[self.name] = f"in SANs of {names[c.domain]} current cert(s) naming {seed}"
        return out


async def seed_org_from_ct(http: Http, seed: str, timeout: float = 120.0, max_certs: int = 4) -> list[str]:
    """The seed's legal name from Subject O= of its recent OV/EV certificates."""
    rows = await crtsh_json(http, {"q": seed, "exclude": "expired"}, timeout)
    if not rows:
        return []
    picks = []
    for row in sorted(rows, key=lambda r: str(r.get("not_before") or ""), reverse=True):
        cn = str(row.get("common_name") or "").lower()
        if registrable(cn) != seed:
            continue
        if DV_ISSUERS.search(str(row.get("issuer_name") or "")):
            continue
        picks.append(row.get("id"))
        if len(picks) >= max_certs:
            break
    orgs: Counter[str] = Counter()

    from .crtsh_db import CURRENT

    db = CURRENT.get()

    async def one(cid):
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        cert = None
        if db is not None and not db.disabled_reason:
            der = await db.certificate_der(int(cid))
            if der:
                try:
                    cert = x509.load_der_x509_certificate(der)
                except ValueError:
                    cert = None
        if cert is None:
            r = await http.get(CRTSH, params={"d": str(cid)}, ttl=30 * 86400, timeout=60, retries=2, cache_404=False)
            if not r.ok or "BEGIN CERTIFICATE" not in r.text:
                return None
            try:
                cert = x509.load_pem_x509_certificate(r.text.encode())
            except ValueError:
                return None
        try:
            o = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
            return str(o[0].value).strip() if o else None
        except (ValueError, IndexError):
            return None

    for o in await asyncio.gather(*(one(c) for c in picks if c)):
        if o:
            orgs[o] += 1
    return [o for o, _ in orgs.most_common()]
