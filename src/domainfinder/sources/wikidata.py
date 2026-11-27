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

import html as htmllib
import re

from .. import USER_AGENT
from ..domains import registrable, to_ascii
from ..models import Candidate
from .base import Source, SourceContext
from ..http import json_answer

ENDPOINT = "https://query.wikidata.org/sparql"
TTL = 7 * 86400


def user_agent(contact: str) -> str:
    """Wikimedia's robot policy asks automated clients for contact details and
    may refuse (HTTP 403) a client without them. Added only when the user has
    set DOMAINFINDER_CONTACT themselves."""
    contact = " ".join(contact.split())
    return f"{USER_AGENT[:-1]}; contact: {contact})" if contact else USER_AGENT


def refusal_reason(text: str) -> str:
    """A short reason from an error page (HTML or plain text)."""
    text = re.sub(r"(?is)<(script|style|title)[^>]*>.*?</\1>", " ", text or "")
    text = " ".join(htmllib.unescape(re.sub(r"<[^>]+>", " ", text)).split())
    return text[:160]


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
        hdr = {"Accept": "application/sparql-results+json", "User-Agent": user_agent(self.settings.contact)}
        r = await ctx.http.get(ENDPOINT, params={"query": build_query(seed), "format": "json"},
                               headers=hdr, ttl=TTL, timeout=60, retries=2, cache_404=False,
                               valid=lambda resp: json_answer(resp, "results"))
        if not r.ok:
            why = f"HTTP {r.status}" if r.status else r.error
            if r.status == 403:
                hint = "" if self.settings.contact else "; Wikimedia may refuse clients without contact details: set DOMAINFINDER_CONTACT"
                reason = refusal_reason(r.text)
                ctx.notes.append(f"wikidata: refused ({why}{': ' + reason if reason else ''}){hint}")
            else:
                ctx.notes.append(f"wikidata: query failed ({why})")
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
