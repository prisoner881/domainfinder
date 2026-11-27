"""WHOIS (port 43) fallback for TLDs that have no RDAP service.

Only registries listed in WHOIS_SERVERS are asked, and only when RDAP has
nothing. Today that is .edu, whose registry (EDUCAUSE) publishes the real
institution as registrant. Port 43 is often blocked in sandboxes and some
networks; a failure just means no WHOIS evidence.
"""

from __future__ import annotations

import asyncio
import re

from ..cache import Cache
from ..contacts import REDACTED
from ..models import RdapInfo

WHOIS_SERVERS = {"edu": "whois.educause.edu"}
WHOIS_TTL = 7 * 86400
US_STATE = re.compile(r",\s*([A-Z]{2})\s+\d{5}(?:-\d{4})?\s*$")


def parse_educause(text: str, info: RdapInfo) -> bool:
    """EDUCAUSE format: a 'Registrant:' header followed by indented lines,
    the first being the institution's name, then address lines."""
    lines = text.replace("\r", "").split("\n")
    for i, line in enumerate(lines):
        if line.strip().lower() == "registrant:":
            block = []
            for nxt in lines[i + 1:]:
                if not nxt.strip():
                    break
                if not nxt[:1].isspace():  # next header
                    break
                block.append(nxt.strip())
            if not block:
                return False
            info.available = True
            info.registrant_org = block[0]
            for addr in block[1:]:
                m = US_STATE.search(addr)
                if m:
                    info.registrant_region = m.group(1)
            if block[-1].upper() in ("USA", "UNITED STATES", "US"):
                info.registrant_country = "US"
            info.registrar = info.registrar or "EDUCAUSE"
            info.sources.append("whois.educause.edu")
            _educause_contacts(lines, block, info)
            return True
    return False


PHONE_LINE = re.compile(r"^\+?[\d\s().-]{8,}$")
CONTACT_HEADERS = {"administrative contact:": "administrative", "technical contact:": "technical",
                   "registrant:": "registrant"}


def _educause_contacts(lines: list[str], registrant: list[str], info: RdapInfo) -> None:
    """Emails, phones and the street address from EDUCAUSE's contact blocks."""
    from ..contacts import contact, norm_email, norm_phone, norm_street

    # The registrant block: name, street lines..., "City, ST 12345", country.
    addr = [a for a in registrant[1:] if a.upper() not in ("USA", "UNITED STATES", "US")]
    if len(addr) >= 2:
        street = norm_street(" ".join(addr[:-1]), addr[-1])
        c = contact("registrant", street=street)
        if c:
            info.contacts.append(c)
    for i, line in enumerate(lines):
        role = CONTACT_HEADERS.get(line.strip().lower())
        if not role or role == "registrant":
            continue
        email = phone = None
        for nxt in lines[i + 1:]:
            if not nxt.strip() or not nxt[:1].isspace():
                break
            t = nxt.strip()
            email = email or norm_email(t)
            if PHONE_LINE.match(t):
                phone = phone or norm_phone(t)
        c = contact(role, email, phone)
        if c and c not in info.contacts:
            info.contacts.append(c)


async def whois_lookup(domain: str, cache: Cache, timeout: float = 8.0) -> RdapInfo | None:
    tld = domain.rsplit(".", 1)[-1].lower()
    server = WHOIS_SERVERS.get(tld)
    if not server:
        return None
    key = f"whois {server} {domain}"
    text = cache.get(key, WHOIS_TTL)
    if text is None:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(server, 43), timeout)
            writer.write(f"{domain}\r\n".encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(65536), timeout)
            text = data.decode("utf-8", "replace")
        except Exception:  # noqa: BLE001 - blocked port, DNS failure, reset: no WHOIS evidence
            text = None
        finally:
            if writer is not None:
                writer.close()
        if text is None:
            stale = cache.get_stale(key)  # an expired answer beats none
            if stale is None or not isinstance(stale[0], str):
                return None
            text = stale[0]
        else:
            cache.set(key, text)
    info = RdapInfo()
    if tld == "edu" and parse_educause(text, info):
        return info
    if "no match" in text.lower():
        info.error = "not found in WHOIS"
        return info
    return None


# ---------------------------------------------------------------------------
# Registrar WHOIS: the fallback when a registrar's RDAP refuses (rate limits).
# The registry's WHOIS names the registrar's WHOIS server ("Registrar WHOIS
# Server:"); the registrar's answer carries the registrant fields and
# contacts in ICANN's standard "Key: Value" layout.

IANA_WHOIS = "whois.iana.org"
REGISTRY_WHOIS = {"com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com"}
SERVER_TTL = 30 * 86400
REGISTRAR_SERVER = re.compile(r"^\s*Registrar WHOIS Server:\s*(\S+)", re.I | re.M)
IANA_SERVER = re.compile(r"^\s*whois:\s*(\S+)", re.I | re.M)
WHOIS_SPACING = 1.0  # seconds between queries to one WHOIS server
_server_locks: dict[str, asyncio.Lock] = {}


async def whois_query(server: str, query: str, cache: Cache, ttl: int = WHOIS_TTL,
                      timeout: float = 8.0, max_bytes: int = 200_000) -> str | None:
    """One port-43 query, cached; one at a time per server, a second apart.
    A failure returns an older cached answer if there is one, else None."""
    key = f"whois {server} {query}"
    text = cache.get(key, ttl)
    if isinstance(text, str):
        return text
    lock = _server_locks.setdefault(server, asyncio.Lock())
    async with lock:
        writer = None
        text = None
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(server, 43), timeout)
            writer.write(f"{query}\r\n".encode())
            await writer.drain()
            chunks, size = [], 0
            while size < max_bytes:
                chunk = await asyncio.wait_for(reader.read(65536), timeout)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            text = b"".join(chunks).decode("utf-8", "replace") or None
        except Exception:  # noqa: BLE001 - blocked port, refused, timeout
            text = None
        finally:
            if writer is not None:
                writer.close()
            await asyncio.sleep(WHOIS_SPACING)
    if text is None:
        stale = cache.get_stale(key)
        return stale[0] if stale and isinstance(stale[0], str) else None
    cache.set(key, text)
    return text


async def registry_whois_server(tld: str, cache: Cache) -> str | None:
    if tld in REGISTRY_WHOIS:
        return REGISTRY_WHOIS[tld]
    text = await whois_query(IANA_WHOIS, tld, cache, ttl=SERVER_TTL)
    m = IANA_SERVER.search(text or "")
    return m.group(1).lower().rstrip(".") if m else None


async def registrar_whois(domain: str, cache: Cache) -> RdapInfo | None:
    """Registrant fields and contacts from WHOIS: the registry's answer, then
    the registrar's server it names. None when nothing could be asked."""
    registry = await registry_whois_server(domain.rsplit(".", 1)[-1].lower(), cache)
    if not registry:
        return None
    text = await whois_query(registry, domain, cache)
    if not text:
        return None
    info = RdapInfo()
    parse_icann_whois(text, info, registry)  # thick registries answer with the registrant themselves
    m = REGISTRAR_SERVER.search(text)
    server = m.group(1).lower().rstrip(".") if m else ""
    server = server.split("://", 1)[-1].split("/", 1)[0]
    if server and server != registry:
        more = await whois_query(server, domain, cache)
        if more:
            parse_icann_whois(more, info, server)
    return info if info.available else None


def parse_icann_whois(text: str, info: RdapInfo, source: str) -> bool:
    """ICANN's registration data layout ("Registrant Organization: ...").
    Fills what `info` lacks; redaction placeholders and privacy services are
    ignored, the registrar's abuse contacts kept apart. True if anything was
    found."""
    from ..contacts import contact, norm_email, norm_phone, norm_street
    from .rdap import _placeholder

    fields: dict[str, str] = {}
    for line in text.replace("\r", "").split("\n"):
        k, sep, v = line.partition(":")
        k, v = k.strip().lower(), v.strip()
        if sep and v and k and k not in fields and len(k) < 60:
            fields[k] = v
    if not any(k.startswith(("registrant", "admin", "tech", "registrar")) for k in fields):
        return False
    info.available = True
    if source not in info.sources:
        info.sources.append(source)
    org = fields.get("registrant organization", "")
    if org and not info.registrant_org and not _placeholder(org) and not REDACTED.search(org):
        info.registrant_org = org
    for attr, key in (("registrant_region", "registrant state/province"), ("registrant_country", "registrant country")):
        v = fields.get(key, "")
        if v and not getattr(info, attr) and not _placeholder(v) and not REDACTED.search(v):
            setattr(info, attr, v)
    if not info.registrar and fields.get("registrar"):
        info.registrar = fields["registrar"]
    for role, prefix in (("registrant", "registrant"), ("administrative", "admin"),
                         ("technical", "tech"), ("billing", "billing")):
        if _placeholder(fields.get(f"{prefix} organization", "")) or _placeholder(fields.get(f"{prefix} name", "")):
            continue  # a privacy service's contact data is shared by all its customers
        street = norm_street(fields.get(f"{prefix} street", ""), fields.get(f"{prefix} city", ""),
                             fields.get(f"{prefix} postal code", ""))
        c = contact(role, norm_email(fields.get(f"{prefix} email")), norm_phone(fields.get(f"{prefix} phone")), street)
        if c and c not in info.contacts:
            info.contacts.append(c)
    for key in ("registrar abuse contact email", "registrar abuse contact phone"):
        v = norm_email(fields.get(key)) or norm_phone(fields.get(key))
        if v and v not in info.registrar_contacts:
            info.registrar_contacts.append(v)
    return True
