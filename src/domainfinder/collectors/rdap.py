"""RDAP for domains (registry, then the registrar's server) and IP networks."""

from __future__ import annotations

from collections import Counter
import asyncio
import ipaddress
import logging
from typing import Any
from urllib.parse import urlsplit

from ..domains import clean
from ..http import Http
from ..contacts import contact, norm_email, norm_phone, norm_street
from ..models import Netblock, RdapInfo

log = logging.getLogger(__name__)

IANA_DNS = "https://data.iana.org/rdap/dns.json"
IANA_V4 = "https://data.iana.org/rdap/ipv4.json"
IANA_V6 = "https://data.iana.org/rdap/ipv6.json"
RDAP_ORG = "https://rdap.org"
BOOTSTRAP_TTL = 7 * 86400
RDAP_TTL = 3 * 86400
ACCEPT = {"Accept": "application/rdap+json, application/json"}


# ---------------------------------------------------------------- vCard ---

def vcard_fields(entity: dict[str, Any]) -> dict[str, Any]:
    """Pull fn/org/adr out of a jCard, tolerating short or malformed arrays."""
    out: dict[str, Any] = {"fn": "", "org": "", "region": "", "country": "", "kind": "",
                           "emails": [], "tels": [], "streets": []}
    va = entity.get("vcardArray")
    if not isinstance(va, list) or len(va) < 2 or not isinstance(va[1], list):
        return out
    for item in va[1]:
        if not isinstance(item, list) or len(item) < 4:
            continue
        name = str(item[0]).lower()
        params = item[1] if isinstance(item[1], dict) else {}
        value = item[3]
        if name == "fn" and isinstance(value, str):
            out["fn"] = value.strip()
        elif name == "org":
            if isinstance(value, list):
                value = " ".join(str(v) for v in value if v)
            out["org"] = str(value or "").strip()
        elif name == "kind" and isinstance(value, str):
            out["kind"] = value.lower()
        elif name == "email":
            e = norm_email(value)
            if e:
                out["emails"].append(e)
        elif name == "tel":
            t = norm_phone(value if isinstance(value, str) else "")
            if t:
                out["tels"].append(t)
        if name == "adr" and isinstance(value, list) and len(value) > 5:
            st = norm_street(value[2], value[3], value[5])
            if st:
                out["streets"].append(st)
        if name == "adr":
            cc = params.get("cc")
            if isinstance(cc, str):
                out["country"] = cc.strip().upper()
            if isinstance(value, list):
                if len(value) > 4 and isinstance(value[4], str):
                    out["region"] = value[4].strip()
                if len(value) > 6 and isinstance(value[6], str) and value[6].strip() and not out["country"]:
                    c = value[6].strip()
                    out["country"] = c.upper() if len(c) == 2 else c
            label = params.get("label")
            if not out["region"] and isinstance(label, str):
                out["label"] = label
    return out


def walk_entities(obj: dict[str, Any]):
    for e in obj.get("entities") or []:
        if isinstance(e, dict):
            yield e
            yield from walk_entities(e)


def _roles(e: dict[str, Any]) -> list[str]:
    r = e.get("roles") or []
    return [str(x).lower() for x in r] if isinstance(r, list) else []


def _placeholder(value: str) -> bool:
    from ..data import load as load_data

    return load_data().is_privacy_proxy(value)


def parse_domain(d: dict[str, Any], info: RdapInfo, source: str) -> None:
    info.available = True
    info.sources.append(source)
    for e in walk_entities(d):
        roles = _roles(e)
        v = vcard_fields(e)
        _collect_contacts(info, roles, v)
        if "registrar" in roles:
            name = v["org"] or v["fn"]
            if name and not info.registrar:
                info.registrar = name
            for pid in e.get("publicIds") or []:
                if isinstance(pid, dict) and "iana" in str(pid.get("type", "")).lower():
                    info.registrar_iana_id = str(pid.get("identifier", ""))
        if "registrant" in roles:
            org = v["org"] or (v["fn"] if v["kind"] == "org" else "")
            if org and not info.registrant_org:
                info.registrant_org = org
            if v["fn"] and not info.registrant_name:
                info.registrant_name = v["fn"]
            # Registries put placeholders like "REDACTED FOR PRIVACY" in these
            # fields; a placeholder is an unknown region, not a region.
            if v["region"] and not info.registrant_region and not _placeholder(v["region"]):
                info.registrant_region = v["region"]
            if v["country"] and not info.registrant_country and not _placeholder(v["country"]):
                info.registrant_country = v["country"]
    for ev in d.get("events") or []:
        if isinstance(ev, dict) and ev.get("eventAction") == "registration" and not info.created:
            info.created = str(ev.get("eventDate", ""))[:10]
    st = d.get("status")
    if isinstance(st, list):
        for s in st:
            if s not in info.status:
                info.status.append(str(s))
    if not info.nameservers:
        info.nameservers = sorted(
            {clean(n.get("ldhName", "")) for n in d.get("nameservers") or [] if isinstance(n, dict) and n.get("ldhName")}
        )


CONTACT_ROLES = ("registrant", "administrative", "technical", "billing")
REGISTRAR_ROLES = ("registrar", "abuse", "reseller", "sponsor", "proxy")


def _collect_contacts(info: RdapInfo, roles: list[str], v: dict[str, Any]) -> None:
    values = v["emails"] + v["tels"] + v["streets"]
    if not values:
        return
    if any(r in REGISTRAR_ROLES for r in roles):
        for x in values:
            if x not in info.registrar_contacts:
                info.registrar_contacts.append(x)
        return
    # A privacy/proxy service's contact data is shared by all its customers.
    if _placeholder(v["org"]) or _placeholder(v["fn"]):
        return
    for role in (r for r in CONTACT_ROLES if r in roles):
        c = contact(role, (v["emails"] or [None])[0], (v["tels"] or [None])[0], (v["streets"] or [None])[0])
        if c and c not in info.contacts:
            info.contacts.append(c)


def related_links(d: dict[str, Any], self_url: str) -> list[str]:
    out = []
    for link in d.get("links") or []:
        if not isinstance(link, dict):
            continue
        href = link.get("href") or ""
        if link.get("rel") == "related" and "rdap" in str(link.get("type", "rdap")) and href.startswith("http"):
            if href.rstrip("/").lower() != self_url.rstrip("/").lower():
                out.append(href)
    return out


# ------------------------------------------------------------- bootstrap ---

class Bootstrap:
    def __init__(self, http: Http):
        self.http = http
        self._dns: dict[str, str] | None = None
        self._ip: list[tuple[ipaddress._BaseNetwork, str]] | None = None
        self._lock = asyncio.Lock()

    async def _load(self, url: str) -> list:
        r = await self.http.get(url, ttl=BOOTSTRAP_TTL)
        if not r.ok:
            return []
        try:
            return r.json().get("services") or []
        except (ValueError, AttributeError):
            return []

    async def domain_base(self, domain: str) -> str | None:
        async with self._lock:
            if self._dns is None:
                self._dns = {}
                for svc in await self._load(IANA_DNS):
                    if len(svc) >= 2 and svc[1]:
                        url = next((u for u in svc[1] if u.startswith("https")), svc[1][0])
                        for tld in svc[0]:
                            self._dns[tld.lower()] = url
        tld = domain.rsplit(".", 1)[-1]
        return self._dns.get(tld)

    async def ip_base(self, ip: str) -> str | None:
        async with self._lock:
            if self._ip is None:
                self._ip = []
                for url in (IANA_V4, IANA_V6):
                    for svc in await self._load(url):
                        if len(svc) >= 2 and svc[1]:
                            base = next((u for u in svc[1] if u.startswith("https")), svc[1][0])
                            for cidr in svc[0]:
                                try:
                                    self._ip.append((ipaddress.ip_network(cidr), base))
                                except ValueError:
                                    pass
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        best = None
        for net, base in self._ip:
            if a.version == net.version and a in net and (best is None or net.prefixlen > best[0].prefixlen):
                best = (net, base)
        return best[1] if best else None


def _join(base: str, path: str) -> str:
    return base.rstrip("/") + "/" + path.lstrip("/")


class RdapClient:
    def __init__(self, http: Http):
        self.http = http
        self.bootstrap = Bootstrap(http)
        self._nets: list[Netblock] = []
        self.registrar_failures: Counter[str] = Counter()  # registrar RDAP host -> failed lookups
        self._ip_locks: dict[str, asyncio.Lock] = {}

    async def domain(self, domain: str) -> RdapInfo:
        info = RdapInfo()
        base = await self.bootstrap.domain_base(domain)
        url = _join(base, f"domain/{domain}") if base else f"{RDAP_ORG}/domain/{domain}"
        r = await self.http.get_follow(url, headers=ACCEPT, ttl=RDAP_TTL, retries=2)
        if r.status == 404:
            info.error = "not found in RDAP"
            return info
        if not r.ok:
            info.error = f"RDAP unavailable (HTTP {r.status or r.error})"
            return info
        try:
            data = r.json()
        except ValueError:
            info.error = "RDAP returned non-JSON"
            return info
        if not isinstance(data, dict) or data.get("errorCode"):
            info.error = f"RDAP error {data.get('errorCode') if isinstance(data, dict) else ''}"
            return info
        # The registrar's RDAP often carries registrant fields the registry lacks.
        for href in related_links(data, r.url)[:1]:
            rr = await self.http.get_follow(href, headers=ACCEPT, ttl=RDAP_TTL, retries=2)
            if not rr.ok:
                self.registrar_failures[urlsplit(href).hostname or href] += 1
            if rr.ok:
                try:
                    rel = rr.json()
                    if isinstance(rel, dict) and not rel.get("errorCode"):
                        parse_domain(rel, info, urlsplit(rr.url).hostname or href)
                except ValueError:
                    pass
        parse_domain(data, info, urlsplit(r.url).hostname or url)
        return info

    def _known_net(self, ip: str) -> Netblock | None:
        for n in self._nets:
            if n.contains(ip):
                return n
        return None

    async def ip(self, ip: str) -> Netblock | None:
        hit = self._known_net(ip)
        if hit:
            return hit
        lock = self._ip_locks.setdefault(ip.rsplit(".", 1)[0], asyncio.Lock())
        async with lock:
            hit = self._known_net(ip)
            if hit:
                return hit
            base = await self.bootstrap.ip_base(ip)
            url = _join(base, f"ip/{ip}") if base else f"{RDAP_ORG}/ip/{ip}"
            r = await self.http.get_follow(url, headers=ACCEPT, ttl=RDAP_TTL * 2, retries=2)
            if not r.ok:
                return None
            try:
                data = r.json()
            except ValueError:
                return None
            nb = parse_ip(data, urlsplit(r.url).hostname or "")
            if nb and nb.start and nb.end:
                self._nets.append(nb)
            return nb


def _rir_from_host(host: str) -> str:
    for rir in ("arin", "ripe", "apnic", "lacnic", "afrinic"):
        if rir in host:
            return rir
    return host


def parse_ip(d: dict[str, Any], host: str = "") -> Netblock | None:
    if not isinstance(d, dict) or d.get("errorCode"):
        return None
    nb = Netblock(
        handle=str(d.get("handle") or ""),
        name=str(d.get("name") or ""),
        start=str(d.get("startAddress") or ""),
        end=str(d.get("endAddress") or ""),
        country=str(d.get("country") or ""),
        rir=_rir_from_host(host or str(d.get("port43") or "")),
    )
    cidrs = []
    for c in d.get("cidr0_cidrs") or []:
        if isinstance(c, dict):
            pfx = c.get("v4prefix") or c.get("v6prefix")
            if pfx and c.get("length") is not None:
                cidrs.append(f"{pfx}/{c['length']}")
    if not cidrs and nb.start and nb.end:
        try:
            cidrs = [
                str(n)
                for n in ipaddress.summarize_address_range(ipaddress.ip_address(nb.start), ipaddress.ip_address(nb.end))
            ][:3]
        except (ValueError, TypeError):
            pass
    nb.cidr = ", ".join(cidrs)
    org = ""
    by_role: dict[str, str] = {}
    for e in walk_entities(d):
        v = vcard_fields(e)
        name = v["org"] or v["fn"]
        if not name:
            continue
        for role in _roles(e):
            by_role.setdefault(role, name)
    for role in ("registrant", "customer", "administrative", "technical"):
        if role in by_role:
            org = by_role[role]
            break
    if not org:
        for rem in d.get("remarks") or []:
            desc = rem.get("description") if isinstance(rem, dict) else None
            if isinstance(desc, list) and desc:
                org = str(desc[0])
                break
    nb.org = org
    return nb
