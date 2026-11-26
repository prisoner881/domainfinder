"""Editable reference lists (shared providers, parking services, ccTLDs...)."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources


def _read_lines(name: str) -> list[str]:
    text = resources.files(__package__).joinpath(name).read_text(encoding="utf-8")
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line.lower())
    return out


def _host_matches(host: str, patterns: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for p in patterns:
        if any(ch in p for ch in "*?["):
            if fnmatch.fnmatch(host, p):
                return True
        elif host == p or host.endswith("." + p):
            return True
    return False


@dataclass(frozen=True)
class ReferenceData:
    cctlds: tuple[str, ...]
    gtlds: tuple[str, ...]
    shared_dns: tuple[str, ...]
    selectable_dns: tuple[str, ...]
    shared_mail: tuple[str, ...]
    shared_spf: tuple[str, ...]
    shared_hosting_orgs: tuple[str, ...]
    parking: tuple[str, ...]
    parking_markers: tuple[str, ...]
    holding_ips: frozenset[str]
    holding_ns: tuple[str, ...]
    brand_registrars: tuple[str, ...]
    privacy_proxies: tuple[str, ...]
    common_third_party: frozenset[str] = frozenset()
    _org_res: tuple[re.Pattern, ...] = field(default=(), repr=False)

    def is_shared_dns(self, host: str) -> bool:
        return _host_matches(host, list(self.shared_dns))

    def is_selectable_dns(self, host: str) -> bool:
        return _host_matches(host, list(self.selectable_dns))

    def is_shared_mail(self, host: str) -> bool:
        return _host_matches(host, list(self.shared_mail))

    def is_shared_spf(self, host: str) -> bool:
        return _host_matches(host, list(self.shared_spf))

    def is_parking_host(self, host: str) -> bool:
        return _host_matches(host, list(self.parking))

    def is_holding_ns(self, host: str) -> bool:
        return _host_matches(host, list(self.holding_ns))

    def is_shared_hosting_org(self, org: str) -> bool:
        org = (org or "").lower()
        return any(r.search(org) for r in self._org_res)

    def is_brand_registrar(self, registrar: str) -> bool:
        r = (registrar or "").lower()
        return any(k in r for k in self.brand_registrars)

    def is_privacy_proxy(self, name: str) -> bool:
        n = (name or "").lower()
        return any(k in n for k in self.privacy_proxies)

    def is_proxy_registrant(self, org: str, registrar: str = "") -> bool:
        """A registrant name that is not the real owner: a privacy service, the
        registrar's own name (CSC writes "CSC Corporate Domains, Inc." into the
        registrant field of domains it manages), or any brand-protection
        registrar's name."""
        if not org:
            return False
        if self.is_privacy_proxy(org) or self.is_brand_registrar(org):
            return True
        if registrar:
            from ..orgnames import same_org

            return same_org(org, registrar)
        return False

    def has_parking_marker(self, html: str) -> str | None:
        h = (html or "").lower()
        for m in self.parking_markers:
            if m in h:
                return m
        return None


@lru_cache(maxsize=1)
def load() -> ReferenceData:
    holding = _read_lines("holding_pages.txt")
    orgs = _read_lines("shared_hosting_orgs.txt")
    return ReferenceData(
        cctlds=tuple(_read_lines("cctlds.txt")),
        gtlds=tuple(_read_lines("gtlds.txt")),
        shared_dns=tuple(_read_lines("shared_dns_providers.txt")),
        selectable_dns=tuple(_read_lines("selectable_dns_providers.txt")),
        shared_mail=tuple(_read_lines("shared_mail_providers.txt")),
        shared_spf=tuple(_read_lines("shared_spf_includes.txt")),
        shared_hosting_orgs=tuple(orgs),
        parking=tuple(_read_lines("parking_providers.txt")),
        parking_markers=tuple(_read_lines("parking_markers.txt")),
        holding_ips=frozenset(h[3:] for h in holding if h.startswith("ip:")),
        holding_ns=tuple(h[3:] for h in holding if h.startswith("ns:")),
        brand_registrars=tuple(_read_lines("brand_protection_registrars.txt")),
        privacy_proxies=tuple(_read_lines("privacy_proxies.txt")),
        common_third_party=frozenset(_read_lines("common_third_party.txt")),
        _org_res=tuple(re.compile(r"(?<![a-z0-9])" + re.escape(o) + r"(?![a-z0-9])") for o in orgs),
    )
