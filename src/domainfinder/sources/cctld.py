"""ccTLD (and a few gTLD) permutations of the brand label."""

from __future__ import annotations

import asyncio

from ..data import load as load_data
from ..domains import suffix
from ..models import Candidate
from .base import Source, SourceContext


def permutations(labels: list[str], seed: str, suffixes: list[str]) -> list[str]:
    seed_sfx = suffix(seed)
    out: list[str] = []
    for lab in labels:
        for s in suffixes:
            d = f"{lab}.{s}"
            if d != seed and not (lab == seed.split(".")[0] and s == seed_sfx) and d not in out:
                out.append(d)
    return out


class CcTldSource(Source):
    name = "cctld"
    description = "brand label across common ccTLDs (existence check via NS/SOA)"

    async def candidates(self, ctx: SourceContext) -> list[Candidate]:
        names = permutations(ctx.brand_labels, ctx.seed.domain, list(load_data().cctlds))
        sem = asyncio.Semaphore(16)
        registered: list[str] = []

        async def check(d: str):
            async with sem:
                ns = await ctx.resolver.query(d, "NS")
                if ns.status == "ok":
                    registered.append(d)
                    return
                if ns.status in ("nodata", "error"):
                    soa = await ctx.resolver.query(d, "SOA")
                    if soa.status == "ok":
                        registered.append(d)

        await asyncio.gather(*(check(d) for d in names))
        ctx.notes.append(f"cctld: {len(registered)} of {len(names)} permutations are registered")
        return [Candidate(domain=d, sources={self.name: f"brand label .{d.split('.', 1)[1]}"}) for d in sorted(registered)]
