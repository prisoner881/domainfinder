"""WhoisXML API Reverse WHOIS: domains whose registrant organization is the seed's.

https://reverse-whois.whoisxmlapi.com/api/documentation/making-requests

Credit use is kept small on purpose (a free account has 500 credits):
* every search first runs in `preview` mode, which only returns a count and
  costs nothing; the 1-credit `purchase` (the domain list, up to 10,000 per
  page) only happens when the count is above zero;
* answers are cached for a week, so re-running a seed spends nothing;
* only `whoisxml_max_pages` pages (default 1) are bought per search.

Searches use exact matches on RegistrantContact.Organization with the seed's
known organization names (plus small punctuation variants). Current-WHOIS
hits are strong evidence (like an RDAP registrant match); historic-only hits
are weak (the domain may have been sold since). Every candidate still goes
through full verification.
"""

from __future__ import annotations

import logging

from ..domains import registrable
from ..models import Candidate, Evidence, Strength
from ..orgnames import normalize
from .base import Source, SourceContext
from ..http import json_answer

log = logging.getLogger(__name__)

ENDPOINT = "https://reverse-whois.whoisxmlapi.com/api/v2"
TTL = 7 * 86400
MAX_VARIANTS = 4


def org_variants(name: str) -> list[str]:
    """'Zyntara Data Processing, Inc.' → itself, '…, Inc', '… Inc.', '… Inc'."""
    name = " ".join(name.split())
    out = [name]
    stripped = name.rstrip(".")
    nocomma = name.replace(", ", " ").replace(",", " ")
    for v in (stripped, nocomma, nocomma.rstrip(".")):
        v = " ".join(v.split())
        if v and v not in out:
            out.append(v)
    return out[:MAX_VARIANTS]


class WhoisXmlSource(Source):
    name = "whoisxml"
    description = "WhoisXML API reverse WHOIS on the registrant organization (500 free credits at sign-up)"
    paid = True

    def enabled(self) -> bool:
        return bool(self.settings.whoisxml_key)

    def disabled_reason(self) -> str:
        return "no API key (set WHOISXML_API_KEY)"

    def _scrub(self, text: str) -> str:
        key = self.settings.whoisxml_key
        return text.replace(key, "<key>") if key else text

    async def _search(self, ctx: SourceContext, org: str, search_type: str, mode: str,
                      search_after: str | None = None) -> tuple[dict | None, bool]:
        query = {
            "searchType": search_type,
            "mode": mode,
            "punycode": True,
            "advancedSearchTerms": [
                {"field": "RegistrantContact.Organization", "term": org, "exactMatch": True},
            ],
        }
        if search_after:
            query["searchAfter"] = search_after
        r = await ctx.http.post_json(
            ENDPOINT, {**query, "apiKey": self.settings.whoisxml_key},
            cache_payload=query, ttl=TTL, timeout=60, retries=1,
            valid=lambda resp: json_answer(resp, "domainsCount"),  # errors come with HTTP 200 too
        )
        try:
            data = r.json() if r.text else {}
        except ValueError:
            data = {}
        if not r.ok or not isinstance(data, dict) or "domainsCount" not in data:
            msg = ""
            if isinstance(data, dict):
                msg = str(data.get("messages") or data.get("ErrorMessage") or data.get("error") or data)[:200]
            ctx.notes.append(self._scrub(
                f"whoisxml: {search_type} {mode} for {org!r} failed (HTTP {r.status or r.error}) {msg}".rstrip()))
            return None, r.cached
        return data, r.cached

    async def candidates(self, ctx: SourceContext) -> list[Candidate]:
        if not ctx.org_names:
            ctx.notes.append("whoisxml: no organization name known for the seed (use --org)")
            return []
        kinds = {"both": ["current", "historic"], "current": ["current"], "historic": ["historic"]}
        search_types = kinds.get(self.settings.whoisxml_search, ["current", "historic"])
        found: dict[str, dict[str, str]] = {}  # domain → {search_type: org}
        seen_norm: set[str] = set()
        credits = 0
        for org in ctx.org_names[:2]:
            if normalize(org) in seen_norm:
                continue
            seen_norm.add(normalize(org))
            for variant in org_variants(org):
                for st in search_types:
                    preview, _ = await self._search(ctx, variant, st, "preview")
                    if preview is None:
                        # Bad key, no credits, service down: stop rather than
                        # repeat the failure for every remaining search.
                        return self._to_candidates(found, ctx, credits)
                    count = int(preview.get("domainsCount") or 0)
                    if count == 0:
                        continue
                    after = None
                    for page in range(max(1, self.settings.whoisxml_max_pages)):
                        data, cached = await self._search(ctx, variant, st, "purchase", after)
                        if data is None:
                            return self._to_candidates(found, ctx, credits)
                        credits += 0 if cached else 1
                        for item in data.get("domainsList") or []:
                            name = item.get("domainName") if isinstance(item, dict) else item
                            rd = registrable(str(name or ""))
                            if rd and rd != ctx.seed.domain:
                                found.setdefault(rd, {}).setdefault(st, variant)
                        after = data.get("nextPageSearchAfter")
                        if not after:
                            break
                    else:
                        if after:
                            ctx.notes.append(f"whoisxml: {st} results for {variant!r} exceed "
                                             f"{self.settings.whoisxml_max_pages} page(s) of 10,000; truncated")
                    ctx.notes.append(f"whoisxml: {count} domain(s) with registrant organization "
                                     f"exactly {variant!r} in {st} WHOIS")
        return self._to_candidates(found, ctx, credits)

    def _to_candidates(self, found: dict[str, dict[str, str]], ctx: SourceContext, credits: int) -> list[Candidate]:
        ctx.notes.append(f"whoisxml: {len(found)} candidate domain(s); {credits} credit(s) spent this run "
                         f"(previews are free; cached answers cost nothing)")
        out = []
        for d, hits in sorted(found.items()):
            if "current" in hits:
                ev = Evidence("whois_org", Strength.STRONG, 60,
                              f"WhoisXML: registrant organization is {hits['current']!r} (current WHOIS)")
                note = f"registrant organization {hits['current']!r} (current WHOIS)"
            else:
                ev = Evidence("whois_org_historic", Strength.WEAK, 15,
                              f"WhoisXML: registrant organization was {hits['historic']!r} (historic WHOIS only)")
                note = f"registrant organization {hits['historic']!r} (historic WHOIS)"
            out.append(Candidate(domain=d, sources={self.name: note}, hints=[ev]))
        return out
