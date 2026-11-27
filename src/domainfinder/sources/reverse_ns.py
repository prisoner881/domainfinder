"""Free reverse-NS lookups: HackerTarget (no key, tiny quota) and ViewDNS (free key)."""

from __future__ import annotations

import logging

from ..data import load as load_data
from ..domains import registrable
from ..models import Candidate
from .base import Source, SourceContext, make_candidates

log = logging.getLogger(__name__)
TTL = 7 * 86400
# A nameserver host serving at least this many domains is shared DNS
# infrastructure (a DNS provider, possibly the seed's own DNS service).
SHARED_NS_COUNT = 200


def pivot_hosts(ns: list[str], seed: str, limit: int = 3) -> tuple[list[str], str]:
    """NS hosts worth a reverse lookup, and how to combine their results.

    Hosts under the seed's own domain (or any non-shared domain) → union.
    Hosts from selectable managed-DNS pools (Akamai, NS1, ...) → intersection
    of several hosts, which approximates "same NS set". Mass providers → none.
    """
    data = load_data()
    own = [h for h in ns if not data.is_shared_dns(h) and not data.is_selectable_dns(h)]
    if own:
        # One host per nameserver domain: n2-a1.aka-ns.net and
        # ns1.p201.dns.oraclecloud.net, not three hosts of the same pool.
        picked, seen = [], set()
        for h in own:
            rd = registrable(h)
            if rd not in seen:
                seen.add(rd)
                picked.append(h)
        return picked[:limit], "union"
    sel = [h for h in ns if data.is_selectable_dns(h)]
    if len(sel) >= 2:
        return sel[:limit], "intersection"
    return [], ""


def combine(results: list[set[str]], how: str) -> set[str]:
    if not results:
        return set()
    if how == "intersection":
        out = set(results[0])
        for r in results[1:]:
            out &= r
        return out
    out = set()
    for r in results:
        out |= r
    return out


class HackerTargetSource(Source):
    name = "hackertarget"
    description = "HackerTarget free reverse-NS (findshareddns); small daily quota"

    def enabled(self) -> bool:
        return self.settings.hackertarget

    def disabled_reason(self) -> str:
        return "turned off (DOMAINFINDER_HACKERTARGET=0 or --no-hackertarget)"

    async def candidates(self, ctx: SourceContext) -> list[Candidate]:
        hosts, how = pivot_hosts(ctx.seed.ns, ctx.seed.domain)
        if not hosts:
            ctx.notes.append("hackertarget: seed NS is shared hosting; reverse NS skipped")
            return []
        results = []
        for h in hosts:
            r = await ctx.http.get("https://api.hackertarget.com/findshareddns/", params={"q": h}, ttl=TTL, retries=1)
            body = r.text.strip()
            if not r.ok or body.lower().startswith(("error", "api count")) or "quota" in body.lower():
                ctx.notes.append(f"hackertarget: {h}: {body[:80] or r.status}")
                break
            found = {d for d in (registrable(x) for x in body.splitlines()) if d}
            if how == "union" and len(found) >= SHARED_NS_COUNT:
                # Not the seed's own nameserver: a DNS service shared by many
                # unrelated domains. Don't pull them in; tell the scorer.
                ctx.shared_ns_domains.add(registrable(h) or h)
                ctx.notes.append(f"hackertarget: {h} serves {len(found)}+ domains: treated as shared DNS "
                                 f"infrastructure ({registrable(h)}), its domains not used as candidates")
                continue
            results.append(found)
        doms = combine(results, how)
        ctx.notes.append(f"hackertarget: {len(doms)} domains share NS ({how} of {len(results)} host(s))")
        return make_candidates(sorted(doms), self.name, ctx.seed.domain, f"shares NS ({how})")


class ViewDnsSource(Source):
    name = "viewdns"
    description = "ViewDNS reverse NS / reverse MX (free API key)"

    def enabled(self) -> bool:
        return bool(self.settings.viewdns_key)

    def disabled_reason(self) -> str:
        return "set VIEWDNS_API_KEY"

    async def _query(self, ctx: SourceContext, endpoint: str, param: str, value: str) -> set[str] | None:
        r = await ctx.http.get(
            f"https://api.viewdns.info/{endpoint}/",
            params={param: value, "apikey": self.settings.viewdns_key, "output": "json"},
            ttl=TTL,
            retries=1,
        )
        if not r.ok:
            return None
        try:
            resp = r.json().get("response", {})
        except (ValueError, AttributeError):
            return None
        rows = resp.get("domains") or []
        out = set()
        for row in rows:
            name = row.get("domain") if isinstance(row, dict) else row
            rd = registrable(str(name or ""))
            if rd:
                out.add(rd)
        return out

    async def candidates(self, ctx: SourceContext) -> list[Candidate]:
        found: dict[str, Candidate] = {}
        hosts, how = pivot_hosts(ctx.seed.ns, ctx.seed.domain)
        res = [r for r in [await self._query(ctx, "reversens", "ns", h) for h in hosts] if r is not None]
        for c in make_candidates(sorted(combine(res, how)), self.name, ctx.seed.domain, f"shares NS ({how})"):
            found[c.domain] = c
        data = load_data()
        mx = [h for h in ctx.seed.mx if not data.is_shared_mail(h) or ctx.seed.mail_tenants]
        for h in mx[:2]:
            r = await self._query(ctx, "reversemx", "mx", h)
            for c in make_candidates(sorted(r or ()), self.name, ctx.seed.domain, f"shares MX {h}"):
                found.setdefault(c.domain, c)
        return list(found.values())
