"""Data models shared by collectors, sources and the scorer."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Strength(str, Enum):
    STRONG = "strong"
    MEDIUM = "medium"
    WEAK = "weak"
    NEGATIVE = "negative"
    INFO = "info"


@dataclass
class Evidence:
    kind: str
    strength: Strength
    points: int
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "strength": self.strength.value, "points": self.points, "detail": self.detail}


@dataclass
class Netblock:
    handle: str = ""
    name: str = ""
    start: str = ""
    end: str = ""
    cidr: str = ""
    org: str = ""
    rir: str = ""
    country: str = ""

    def contains(self, ip: str) -> bool:
        import ipaddress

        try:
            a = ipaddress.ip_address(ip)
            return ipaddress.ip_address(self.start) <= a <= ipaddress.ip_address(self.end)
        except ValueError:
            return False

    def label(self) -> str:
        bits = [b for b in (self.rir.upper(), self.name or self.handle, self.cidr or f"{self.start}-{self.end}") if b]
        s = " ".join(bits)
        return f"{s} ({self.org})" if self.org else s


@dataclass
class RdapInfo:
    available: bool = False
    registrar: str = ""
    registrar_iana_id: str = ""
    registrant_org: str = ""
    registrant_name: str = ""
    registrant_region: str = ""
    registrant_country: str = ""
    created: str = ""
    status: list[str] = field(default_factory=list)
    nameservers: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    error: str = ""

    def region_key(self) -> str:
        if not (self.registrant_region or self.registrant_country):
            return ""
        return ", ".join(p for p in (self.registrant_region, self.registrant_country) if p).upper()


@dataclass
class WebInfo:
    fetched: bool = False
    start_url: str = ""
    chain: list[str] = field(default_factory=list)
    final_url: str = ""
    status: int = 0
    title: str = ""
    analytics_ids: list[str] = field(default_factory=list)
    linked_domains: list[str] = field(default_factory=list)
    csp_domains: list[str] = field(default_factory=list)
    parking_marker: str = ""
    error: str = ""


@dataclass
class CertInfo:
    fetched: bool = False
    subject_org: str = ""
    subject_cn: str = ""
    issuer: str = ""
    sans: list[str] = field(default_factory=list)
    sha256: str = ""  # fingerprint of the certificate itself
    spki_sha256: str = ""  # fingerprint of its public key
    has_scts: bool = False  # carries Certificate Transparency timestamps (publicly trusted)
    error: str = ""


@dataclass
class Fingerprint:
    domain: str
    brand_label: str = ""
    registered: bool | None = None  # None = unknown
    ns: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    mail_tenants: list[str] = field(default_factory=list)
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    apex_resolves: bool = True
    www_cname: list[str] = field(default_factory=list)
    netblocks: list[Netblock] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)
    spf_includes: list[str] = field(default_factory=list)
    verification_tokens: list[str] = field(default_factory=list)
    soa_rname: str = ""
    soa_mname: str = ""
    rdap: RdapInfo = field(default_factory=RdapInfo)
    cert: CertInfo = field(default_factory=CertInfo)
    web: WebInfo = field(default_factory=WebInfo)
    org_names: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Candidate:
    domain: str
    sources: dict[str, str] = field(default_factory=dict)  # source name → note
    hints: list[Evidence] = field(default_factory=list)  # evidence a source already holds

    def add_source(self, name: str, note: str = "") -> None:
        if name not in self.sources or (note and not self.sources[name]):
            self.sources[name] = note


class Classification(str, Enum):
    OWNED = "owned"
    REVIEW = "review"
    REJECTED = "rejected"


@dataclass
class Result:
    domain: str
    score: int
    classification: Classification
    status: str
    evidence: list[Evidence]
    sources: dict[str, str]
    fingerprint: Fingerprint | None = None

    def summary(self, max_items: int = 4) -> str:
        ev = sorted(
            (e for e in self.evidence if e.strength is not Strength.INFO),
            key=lambda e: -abs(e.points),
        )
        return "; ".join(e.detail for e in ev[:max_items])

    def to_dict(self, include_fingerprint: bool = False, idn: str = "unicode") -> dict[str, Any]:
        from .domains import display, humanize, to_ascii, to_unicode

        d: dict[str, Any] = {
            "domain": display(self.domain, idn),
            "domain_ascii": to_ascii(self.domain),
            "domain_unicode": to_unicode(self.domain),
            "score": self.score,
            "classification": self.classification.value,
            "status": humanize(self.status, idn),
            "sources": {k: humanize(v, idn) for k, v in self.sources.items()},
            "evidence": [{**e.to_dict(), "detail": humanize(e.detail, idn)} for e in self.evidence],
        }
        if include_fingerprint and self.fingerprint is not None:
            # Raw technical record: host names stay in the ASCII form DNS uses.
            d["fingerprint"] = self.fingerprint.to_dict()
        return d
