"""Registrable domains the seed itself points at: homepage links, CSP, cert SANs."""

from __future__ import annotations

from ..models import Candidate
from .base import Source, SourceContext, make_candidates


class SeedLinkSource(Source):
    name = "seed-links"
    description = "domains linked from the seed homepage, its CSP header and its live cert SANs"

    async def candidates(self, ctx: SourceContext) -> list[Candidate]:
        seed = ctx.seed
        found: dict[str, Candidate] = {}
        for doms, note in (
            (seed.web.linked_domains, "linked from seed homepage"),
            (seed.web.csp_domains, "named in seed's Content-Security-Policy"),
            (seed.cert.sans, "in seed's live certificate SANs"),
        ):
            for c in make_candidates(doms, self.name, seed.domain, note):
                if c.domain in found:
                    found[c.domain].sources[self.name] += "; " + note
                else:
                    found[c.domain] = c
        return list(found.values())
