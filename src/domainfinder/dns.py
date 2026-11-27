"""DNS lookups: system resolver (dnspython) with DNS-over-HTTPS fallback."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

from .cache import Cache
from .http import Http

log = logging.getLogger(__name__)

RTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28}
DOH_ENDPOINTS = ("https://dns.google/resolve", "https://cloudflare-dns.com/dns-query")
DNS_TTL = 6 * 3600


@dataclass
class DnsAnswer:
    status: str  # ok | nxdomain | nodata | error
    records: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def exists(self) -> bool:
        return self.status in ("ok", "nodata")


def _txt_join(data: str) -> str:
    data = data.strip()
    if data.startswith('"') and data.endswith('"'):
        parts = [p for p in data[1:-1].split('" "')]
        return "".join(parts).replace('\\"', '"')
    return data


def _norm(rtype: str, data: str) -> str:
    if rtype == "TXT":
        return _txt_join(data)
    return data.strip().rstrip(".").lower() if rtype in ("NS", "CNAME") else data.strip()


class Resolver:
    def __init__(self, http: Http, cache: Cache | None = None, mode: str = "auto", timeout: float = 6.0):
        self.http = http
        self.cache = cache or Cache.memory()
        self.mode = mode
        self.timeout = timeout
        self._probe_lock = asyncio.Lock()
        self._effective: str | None = None if mode == "auto" else mode
        self._auth_failures = 0  # consecutive failed authoritative NS lookups
        self.auth_max_failures = 5

    async def _system(self, name: str, rtype: str) -> DnsAnswer:
        import dns.asyncresolver
        import dns.exception
        import dns.resolver

        r = dns.asyncresolver.Resolver()
        r.lifetime = self.timeout
        try:
            ans = await r.resolve(name, rtype, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return DnsAnswer("nxdomain")
        except (dns.exception.DNSException, OSError) as e:
            return DnsAnswer("error", error=f"{type(e).__name__}: {e}"[:200])
        if ans.rrset is None:
            return DnsAnswer("nodata")
        out = []
        for rr in ans.rrset:
            if rtype == "TXT":
                out.append("".join(s.decode("utf-8", "replace") for s in rr.strings))
            elif rtype == "MX":
                out.append(f"{rr.preference} {str(rr.exchange).rstrip('.').lower()}")
            elif rtype == "SOA":
                out.append(f"{str(rr.mname).rstrip('.').lower()} {str(rr.rname).rstrip('.').lower()} {rr.serial}")
            else:
                out.append(_norm(rtype, rr.to_text()))
        return DnsAnswer("ok", out)

    async def _doh(self, name: str, rtype: str) -> DnsAnswer:
        want = RTYPES[rtype]
        last_err = ""
        for ep in DOH_ENDPOINTS:
            r = await self.http.get(
                ep,
                params={"name": name, "type": rtype},
                headers={"Accept": "application/dns-json"},
                store=False,  # the resolver caches the parsed answer with its own lifetime
                timeout=self.timeout + 4,
                retries=1,
            )
            if not r.ok:
                last_err = f"{ep}: HTTP {r.status} {r.error}"
                continue
            try:
                d = r.json()
            except ValueError:
                last_err = f"{ep}: bad JSON"
                continue
            st = d.get("Status")
            if st == 3:
                return DnsAnswer("nxdomain")
            if st not in (0, None):
                last_err = f"{ep}: rcode {st}"
                if st == 2:  # SERVFAIL: try the other endpoint
                    continue
                return DnsAnswer("error", error=last_err)
            recs = [_norm(rtype, a.get("data", "")) for a in d.get("Answer") or [] if a.get("type") == want]
            if rtype == "MX":
                recs = [" ".join([p.split()[0], p.split()[1].rstrip(".").lower()]) for p in recs if len(p.split()) == 2]
            if rtype == "SOA":
                fixed = []
                for p in recs:
                    bits = p.split()
                    if len(bits) >= 3:
                        fixed.append(f"{bits[0].rstrip('.').lower()} {bits[1].rstrip('.').lower()} {bits[2]}")
                recs = fixed
            return DnsAnswer("ok" if recs else "nodata", recs)
        return DnsAnswer("error", error=last_err)

    async def authoritative_ns(self, domain: str, nameservers: list[str], max_servers: int = 3) -> DnsAnswer:
        """The domain's NS set as its own nameservers publish it (child zone).

        A recursive resolver may answer an NS query with the parent zone's
        delegation instead, which for some registries lists only part of the
        set. Asking one of the domain's nameservers directly and accepting only
        an authoritative answer gives the set its owner configured. Any
        failure (port 53 blocked, timeouts, lame servers) returns "error" and
        the caller keeps what it had."""
        import dns.asyncquery
        import dns.exception
        import dns.flags
        import dns.message
        import dns.rcode
        import dns.rdatatype

        key = f"dns-auth {domain.lower()} NS"
        cached = self.cache.get(key, DNS_TTL)
        if cached is not None:
            return DnsAnswer(**cached)
        if self._auth_failures >= self.auth_max_failures:  # direct DNS looks blocked on this network
            return DnsAnswer("error", error="direct DNS queries are not getting answers on this network")
        last = "no nameserver answered"
        for host in nameservers[:max_servers]:
            addrs = await self.query(host, "A")
            ips = [r for r in addrs.records if r.count(".") == 3][:1]
            for ip in ips:
                try:
                    q = dns.message.make_query(domain, "NS")
                    resp, _tcp = await dns.asyncquery.udp_with_fallback(q, ip, timeout=self.timeout)
                except (dns.exception.DNSException, OSError, ValueError) as e:
                    last = f"{host}: {type(e).__name__}"
                    continue
                if resp.rcode() != dns.rcode.NOERROR or not (resp.flags & dns.flags.AA):
                    last = f"{host}: not authoritative"
                    continue
                recs = sorted({_norm("NS", rr.to_text()) for rrset in resp.answer
                               if rrset.rdtype == dns.rdatatype.NS for rr in rrset})
                if recs:
                    self._auth_failures = 0
                    ans = DnsAnswer("ok", recs)
                    self.cache.set(key, ans.__dict__)
                    return ans
                last = f"{host}: empty answer"
        self._auth_failures += 1
        return DnsAnswer("error", error=last)

    async def _pick_mode(self) -> str:
        if self._effective:
            return self._effective
        async with self._probe_lock:
            if self._effective:
                return self._effective
            probe = await self._system("iana.org", "NS")
            self._effective = "system" if probe.status == "ok" else "doh"
            log.info("DNS mode: %s", self._effective)
            return self._effective

    async def query(self, name: str, rtype: str) -> DnsAnswer:
        rtype = rtype.upper()
        key = f"dns {name.lower()} {rtype}"
        cached = self.cache.get(key, DNS_TTL)
        if cached is not None:
            return DnsAnswer(**cached)
        mode = await self._pick_mode()
        ans = await (self._system(name, rtype) if mode == "system" else self._doh(name, rtype))
        if ans.status == "error" and mode == "system":
            ans = await self._doh(name, rtype)
        if ans.status != "error":
            self.cache.set(key, ans.__dict__)
        return ans
