"""WHOIS/RDAP contact data points (email, phone, street address), normalized.

Most registries and registrars redact contacts since GDPR (2018); what is
published is usually a placeholder ("REDACTED FOR PRIVACY") or a web form, so
these only add evidence where real contact data is published (several ccTLDs,
.edu, some registrars). Placeholders and malformed values normalize to None.
"""

from __future__ import annotations

import re

REDACTED = re.compile(
    r"redact|privacy|private|withheld|not ?disclosed|data ?protect|gdpr|please query|query the rdds|"
    r"contact the registrar|statutory|masked|hidden|anonymi[sz]ed|not available|n/a\b", re.I)
EMAIL = re.compile(r"^[^@\s]+@[a-z0-9.-]+\.[a-z]{2,}$")


def norm_email(value) -> str | None:
    if not isinstance(value, str):
        return None
    v = value.strip().lower()
    if v.startswith("mailto:"):
        v = v[7:]
    if not EMAIL.match(v) or REDACTED.search(v):
        return None
    return v


def norm_phone(value) -> str | None:
    """Digits only; at least 8 of them (shorter is an extension or junk)."""
    if not isinstance(value, str) or REDACTED.search(value):
        return None
    v = value.strip()
    if v.lower().startswith("tel:"):
        v = v[4:]
    v = v.split(";ext=")[0].split(" ext")[0]
    digits = re.sub(r"\D", "", v)
    return digits if len(digits) >= 8 else None


def norm_street(street, city="", postal="") -> str | None:
    """Street + city + postal code, lower-cased and punctuation-free. Needs a
    street and at least a city or a postal code to mean anything."""
    if isinstance(street, list):
        street = " ".join(str(s) for s in street if s)
    parts = [str(p or "").strip() for p in (street, city, postal)]
    if not parts[0] or not (parts[1] or parts[2]):
        return None
    joined = " ".join(parts)
    if REDACTED.search(joined):
        return None
    out = " ".join(re.sub(r"[^a-z0-9]+", " ", joined.lower()).split())
    return out if len(out) >= 8 else None


def contact(role: str, email=None, phone=None, street=None) -> dict[str, str] | None:
    c = {"role": role}
    for k, v in (("email", email), ("phone", phone), ("street", street)):
        if v:
            c[k] = v
    return c if len(c) > 1 else None
