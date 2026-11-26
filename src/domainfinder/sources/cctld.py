"""TLD sweeps: the brand label across country-code and generic TLDs."""

from __future__ import annotations

import asyncio

from ..data import load as load_data
from ..domains import suffix
from ..models import Candidate
from .base import Source, SourceContext

IANA_TLDS = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
IANA_TTL = 7 * 86400


def permutations(labels: list[str], seed: str, suffixes: list[str]) -> list[str]:
    seed_sfx = suffix(seed)
    out: list[str] = []
    for lab in labels:
        for s in suffixes:
            d = f"{lab}.{s}"
            if d != seed and not (lab == seed.split(".")[0] and s == seed_sfx) and d not in out:
                out.append(d)
    return out


async def registered_names(ctx: SourceContext, names: list[str], parallel: int = 16) -> list[str]:
    """Cheap existence check: NS, then SOA. Only registered names get verified."""
    sem = asyncio.Semaphore(parallel)
    found: list[str] = []

    async def check(d: str):
        async with sem:
            ns = await ctx.resolver.query(d, "NS")
            if ns.status == "ok":
                found.append(d)
                return
            if ns.status in ("nodata", "error"):
                soa = await ctx.resolver.query(d, "SOA")
                if soa.status == "ok":
                    found.append(d)

    await asyncio.gather(*(check(d) for d in names))
    return sorted(found)


class _TldSweep(Source):
    async def suffixes(self, ctx: SourceContext) -> list[str]:
        raise NotImplementedError

    async def candidates(self, ctx: SourceContext) -> list[Candidate]:
        names = permutations(ctx.brand_labels, ctx.seed.domain, await self.suffixes(ctx))
        found = await registered_names(ctx, names)
        ctx.notes.append(f"{self.name}: {len(found)} of {len(names)} permutations are registered")
        return [Candidate(domain=d, sources={self.name: f"brand label .{d.split('.', 1)[1]}"}) for d in found]


class CcTldSource(_TldSweep):
    name = "cctld"
    description = "brand label across common ccTLDs (existence check via NS/SOA)"

    async def suffixes(self, ctx: SourceContext) -> list[str]:
        return list(load_data().cctlds)


class GTldSource(_TldSweep):
    name = "gtld"
    description = "brand label across common generic TLDs (.net, .org, .info, .io, ...); --all-tlds: every TLD"

    async def suffixes(self, ctx: SourceContext) -> list[str]:
        data = load_data()
        covered = set(data.cctlds)
        if self.settings.all_tlds:
            tlds = await iana_tlds(ctx)
            if tlds:
                return [t for t in tlds if t not in covered]
            ctx.notes.append("gtld: IANA TLD list unavailable; using the common generic TLDs")
        return [t for t in data.gtlds if t not in covered]


async def iana_tlds(ctx: SourceContext) -> list[str]:
    """Every delegated TLD, from IANA's list (fetched, cached for a week)."""
    r = await ctx.http.get(IANA_TLDS, ttl=IANA_TTL)
    if not r.ok:
        return []
    return [ln.strip().lower() for ln in r.text.splitlines() if ln.strip() and not ln.startswith("#")]
