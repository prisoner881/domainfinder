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
            return None
        finally:
            if writer is not None:
                writer.close()
        cache.set(key, text)
    info = RdapInfo()
    if tld == "edu" and parse_educause(text, info):
        return info
    if "no match" in text.lower():
        info.error = "not found in WHOIS"
        return info
    return None
