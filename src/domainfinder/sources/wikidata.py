"""Wikidata: subsidiaries of the organization whose official website is the seed.

Wikidata (the structured database behind Wikipedia) records parent/subsidiary
relationships and each organization's official website (property P856). The
organization is found by an *exact* website match (http/https, with or
without www, with or without a trailing slash), never by name. Its
subsidiaries ("has subsidiary" P355, or "parent organization" P749 / "owned
by" P127 pointing at it) contribute their official websites as candidates,
verified like any other. One level deep.
"""

from __future__ import annotations

from ..domains import registrable, to_ascii
from ..models import Candidate
from .base import Source, SourceContext

ENDPOINT = "https://query.wikidata.org/sparql"
TTL = 7 * 86400


def website_variants(domain: str) -> list[str]:
    return [f"{scheme}://{www}{domain}{slash}" for scheme in ("https", "http") for www in ("www.", "")
            for slash in ("/", "")]


def build_query(domain: str) -> str:
    values = " ".join(f"<{v}>" for v in website_variants(to_ascii(domain)))
    return f"""SELECT DISTINCT ?sub ?subLabel ?site WHERE {{
  VALUES ?w {{ {values} }}
  ?org wdt:P856 ?w .
  {{ ?org wdt:P355 ?sub }} UNION {{ ?sub wdt:P749 ?org }} UNION {{ ?sub wdt:P127 ?org }}
  ?sub wdt:P856 ?site .
  SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en". }}
}} LIMIT 1000"""


class WikidataSource(Source):
    name = "wikidata"
    description = "Wikidata: official websites of the seed organization's subsidiaries"

    def enabled(self) -> bool:
        return self.settings.wikidata

    def disabled_reason(self) -> str:
        return "turned off (DOMAINFINDER_WIKIDATA=0)"

    async def candidates(self, ctx: SourceContext) -> list[Candidate]:
        seed = ctx.seed.domain
        r = await ctx.http.get(ENDPOINT, params={"query": build_query(seed), "format": "json"},
                               headers={"Accept": "application/sparql-results+json"}, ttl=TTL, timeout=60, retries=2)
        if not r.ok:
            ctx.notes.append(f"wikidata: query failed (HTTP {r.status or r.error})")
            return []
        try:
            rows = r.json()["results"]["bindings"]
        except (ValueError, KeyError, TypeError):
            ctx.notes.append("wikidata: unexpected answer")
            return []
        out: dict[str, Candidate] = {}
        for b in rows:
            rd = registrable(b.get("site", {}).get("value", ""))
            label = b.get("subLabel", {}).get("value", "")
            if rd and rd != seed and rd not in out:
                out[rd] = Candidate(domain=rd, sources={self.name: f"Wikidata: official website of {label}"})
        ctx.notes.append(f"wikidata: {len(out)} subsidiary website(s) for the organization at {seed}")
        return list(out.values())
