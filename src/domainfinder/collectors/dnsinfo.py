"""DNS-derived fingerprint fields: NS, MX + mail tenant, A/AAAA, TXT, SOA."""

from __future__ import annotations

import asyncio
import re

from ..dns import Resolver
from ..domains import registrable
from ..models import Fingerprint

# Mail gateways whose MX host names embed a customer/tenant ID.
MAIL_TENANT_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("proofpoint", re.compile(r"^mx[a-z0-9]?-([0-9a-f]{6,10})\.gslb\.pphosted\.com$")),
    ("proofpoint", re.compile(r"^mx[0-9a-z]*-([0-9a-f]{6,10})\.[a-z0-9.-]*pphosted\.com$")),
    ("cisco-ironport", re.compile(r"^(?:mx\d*|esa\d*)\.([a-z0-9-]+)\.iphmx\.com$")),
    ("barracuda", re.compile(r"^(d\d+[a-z]?)\.ess\.barracudanetworks\.com$")),
    ("barracuda", re.compile(r"^([a-z0-9-]+)\.ess\.(?:[a-z]{2}\.)?barracudanetworks\.com$")),
    ("mimecast-custom", re.compile(r"^([a-z0-9-]+)\.mimecast-offshore\.com$")),
]

# TXT verification tokens worth comparing across domains.
TOKEN_PREFIXES = (
    "google-site-verification=",
    "ms=",
    "facebook-domain-verification=",
    "atlassian-domain-verification=",
    "apple-domain-verification=",
    "adobe-idp-site-verification=",
    "adobe-sign-verification=",
    "docusign=",
    "globalsign-domain-verification=",
    "_globalsign-domain-verification=",
    "zoom-domain-verification",
    "webexdomainverification.",
    "cisco-ci-domain-verification=",
    "dropbox-domain-verification=",
    "stripe-verification=",
    "miro-verification=",
    "onetrust-domain-verification=",
    "smartsheet-site-validation=",
    "slack-domain-verification=",
    "citrix-verification-code=",
    "workplace-domain-verification=",
    "hubspot-developer-verification=",
    "knowbe4-site-verification=",
    "pardot",
    "sophos-domain-verification=",
    "airtable-verification=",
    "logmein-verification-code=",
    "amazonses:",
    "wrike-verification=",
    "box-domain-verification=",
    "cursor-domain-verification",
    "openai-domain-verification=",
    "anthropic-domain-verification",
)


def mail_tenant(host: str) -> str | None:
    host = host.lower().rstrip(".")
    for provider, pat in MAIL_TENANT_PATTERNS:
        m = pat.match(host)
        if m:
            return f"{provider}:{m.group(1)}"
    return None


def parse_spf_includes(txts: list[str]) -> list[str]:
    out: list[str] = []
    for t in txts:
        if not t.lower().startswith("v=spf1"):
            continue
        for tok in t.split():
            tl = tok.lower().lstrip("+?~-")
            for key in ("include:", "redirect="):
                if tl.startswith(key):
                    target = tl[len(key):].strip(".")
                    if "%{" not in target and target not in out:
                        out.append(target)
    return out


def parse_tokens(txts: list[str]) -> list[str]:
    out = []
    for t in txts:
        tl = t.strip().lower()
        if tl.startswith("v=spf1") or tl.startswith("v=dmarc"):
            continue
        for p in TOKEN_PREFIXES:
            if tl.startswith(p):
                # tokens are case-sensitive in their value; keep the original
                tok = t.strip()
                if len(tok) > len(p) + 6 and tok not in out:
                    out.append(tok)
                break
    return out


async def collect_dns(fp: Fingerprint, resolver: Resolver) -> None:
    d = fp.domain
    ns, mx, a, aaaa, txt, soa, www = await asyncio.gather(
        resolver.query(d, "NS"),
        resolver.query(d, "MX"),
        resolver.query(d, "A"),
        resolver.query(d, "AAAA"),
        resolver.query(d, "TXT"),
        resolver.query(d, "SOA"),
        resolver.query("www." + d, "CNAME"),
    )
    if ns.status == "nxdomain" or soa.status == "nxdomain":
        fp.registered = False
    elif ns.status == "ok":
        fp.registered = True
    for ans, label in ((ns, "NS"), (a, "A")):
        if ans.status == "error":
            fp.errors.append(f"DNS {label}: {ans.error}")
    fp.ns = sorted(set(ns.records))
    hosts = []
    for rec in mx.records:
        parts = rec.split()
        if len(parts) == 2 and parts[1] not in ("", ".", "null", "localhost"):  # RFC 7505 null MX
            hosts.append(parts[1])
    fp.mx = sorted(set(hosts))
    fp.mail_tenants = sorted({t for t in (mail_tenant(h) for h in fp.mx) if t})
    fp.a = sorted(set(r for r in a.records if re.match(r"^\d+\.\d+\.\d+\.\d+$", r)))
    fp.aaaa = sorted(set(r for r in aaaa.records if ":" in r))
    fp.txt = txt.records
    fp.spf_includes = parse_spf_includes(txt.records)
    fp.verification_tokens = parse_tokens(txt.records)
    fp.www_cname = sorted(set(www.records))
    if soa.records:
        bits = soa.records[0].split()
        if len(bits) >= 2:
            fp.soa_mname, fp.soa_rname = bits[0], bits[1]
    fp.apex_resolves = bool(fp.a or fp.aaaa)
    if fp.registered is not False:
        await collect_dmarc(fp, resolver)
    # Apex has no A record: fall back to www for hosting evidence.
    if not fp.a and fp.registered is not False:
        wa = await resolver.query("www." + d, "A")
        fp.a = sorted(set(r for r in wa.records if re.match(r"^\d+\.\d+\.\d+\.\d+$", r)))


def rname_domain(rname: str) -> str | None:
    """SOA rname 'hostmaster.zdp.com' → registrable 'zdp.com'."""
    if not rname or "." not in rname:
        return None
    local, _, rest = rname.partition(".")
    return registrable(rest)


# A name nobody would authorize specifically: if it resolves, the report host
# authorizes every domain (a wildcard), which proves nothing.
_DMARC_PROBE = "domainfinder-wildcard-probe"


def parse_dmarc_addresses(record: str) -> list[str]:
    """rua/ruf report addresses from a DMARC record, lower-cased, sizes stripped:
    'v=DMARC1; p=reject; rua=mailto:a@x.com!10m,mailto:b@y.com' → [a@x.com, b@y.com]."""
    out: list[str] = []
    for part in record.split(";"):
        key, _, value = part.strip().partition("=")
        if key.strip().lower() not in ("rua", "ruf"):
            continue
        for uri in value.split(","):
            uri = uri.strip()
            if not uri.lower().startswith("mailto:"):
                continue
            addr = uri[7:].split("!", 1)[0].strip().lower()
            if "@" in addr and addr not in out:
                out.append(addr)
    return out


async def collect_dmarc(fp: Fingerprint, resolver: Resolver) -> None:
    """DMARC report addresses, and whether each external report host authorizes
    this domain (RFC 7489 §7.1: <domain>._report._dmarc.<report host>)."""
    ans = await resolver.query("_dmarc." + fp.domain, "TXT")
    record = next((t for t in ans.records if t.strip().lower().startswith("v=dmarc1")), "")
    fp.dmarc_addresses = parse_dmarc_addresses(record)
    hosts = sorted({a.split("@", 1)[1] for a in fp.dmarc_addresses})
    for host in hosts:
        if registrable(host) == fp.domain:
            continue  # reports to itself need no authorization
        specific = await resolver.query(f"{fp.domain}._report._dmarc.{host}", "TXT")
        if not any(t.strip().lower().startswith("v=dmarc1") for t in specific.records):
            fp.dmarc_auth[host] = "none"
            continue
        probe = await resolver.query(f"{_DMARC_PROBE}._report._dmarc.{host}", "TXT")
        wildcard = any(t.strip().lower().startswith("v=dmarc1") for t in probe.records)
        fp.dmarc_auth[host] = "wildcard" if wildcard else "specific"
