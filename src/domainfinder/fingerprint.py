"""[1] Fingerprint a domain from DNS, RDAP, IP RDAP, the homepage and TLS."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from .collectors.dnsinfo import collect_dns
from .collectors.rdap import RdapClient
from .collectors.tls import fetch_cert
from .collectors.web import collect_web
from .collectors.whois import whois_lookup
from .data import load as load_data
from .dns import Resolver
from .domains import label
from .http import Http
from .models import Fingerprint
from .orgnames import is_meaningful

log = logging.getLogger(__name__)


@dataclass
class Collectors:
    http: Http
    resolver: Resolver
    rdap: RdapClient
    tls_check: bool = True
    max_ips: int = 3
    whois: bool = True


async def fingerprint(domain: str, c: Collectors, *, web: bool = True, rdap: bool = True) -> Fingerprint:
    fp = Fingerprint(domain=domain, brand_label=label(domain))
    await collect_dns(fp, c.resolver)
    apex_resolves = fp.apex_resolves
    if fp.registered is False:
        # NXDOMAIN: nothing else to look at, but RDAP can still say "held".
        return fp

    async def do_rdap():
        if rdap:
            fp.rdap = await c.rdap.domain(domain)
            if not fp.rdap.available and c.whois:
                w = await whois_lookup(domain, c.http.cache)
                if w is not None and w.available:
                    fp.rdap = w
            if fp.rdap.error:
                fp.errors.append(fp.rdap.error)

    async def do_ips():
        nbs = await asyncio.gather(*(c.rdap.ip(ip) for ip in fp.a[: c.max_ips]))
        seen = set()
        for nb in nbs:
            if nb and (nb.handle, nb.start) not in seen:
                seen.add((nb.handle, nb.start))
                fp.netblocks.append(nb)

    async def do_web():
        if web and (fp.a or fp.aaaa or fp.www_cname):
            fp.web = await collect_web(domain, c.http, apex_resolves=apex_resolves)

    async def do_tls():
        if c.tls_check and web and (fp.a or fp.aaaa):
            fp.cert = await fetch_cert(domain if apex_resolves else "www." + domain)

    await asyncio.gather(do_rdap(), do_ips(), do_web(), do_tls())
    if fp.registered is None and (fp.rdap.available or fp.a):
        fp.registered = True
    fp.org_names = org_names_of(fp)
    return fp


def org_names_of(fp: Fingerprint) -> list[str]:
    data = load_data()
    names: list[str] = []
    if fp.cert.subject_org and is_meaningful(fp.cert.subject_org):
        names.append(fp.cert.subject_org)
    for n in (fp.rdap.registrant_org,):
        if n and is_meaningful(n) and not data.is_proxy_registrant(n, fp.rdap.registrar) and n not in names:
            names.append(n)
    return names
