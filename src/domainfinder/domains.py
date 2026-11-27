"""Domain-name helpers built on tldextract's bundled public-suffix list."""

from __future__ import annotations

import re
from functools import lru_cache

import tldextract

# suffix_list_urls=() → use the snapshot shipped with tldextract: no network,
# deterministic results in tests.
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def clean(name: str) -> str:
    name = (name or "").strip().lower().rstrip(".")
    if "://" in name:
        name = name.split("://", 1)[1]
    name = name.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in name:
        name = name.rsplit("@", 1)[1]
    name = name.split(":", 1)[0]
    while name.startswith("*."):
        name = name[2:]
    return name.strip(".")


@lru_cache(maxsize=65536)
def registrable(name: str) -> str | None:
    """Registrable domain (eTLD+1) of a host name, or None."""
    name = clean(name)
    if not name or " " in name:
        return None
    ext = _extract(name)
    if not ext.domain or not ext.suffix:
        return None
    try:
        name.encode("ascii")
    except UnicodeEncodeError:
        try:
            name = name.encode("idna").decode("ascii")
            ext = _extract(name)
        except UnicodeError:
            return None
    if not all(_LABEL.match(p) for p in ext.domain.split(".")):
        return None
    return f"{ext.domain}.{ext.suffix}"


def label(domain: str) -> str:
    """The registrable label: 'zdp' for zdp.com, 'zdp' for zdp.co.uk."""
    return _extract(clean(domain)).domain


def suffix(domain: str) -> str:
    return _extract(clean(domain)).suffix


def is_subdomain_of(host: str, domain: str) -> bool:
    host, domain = clean(host), clean(domain)
    return host == domain or host.endswith("." + domain)


_PUNY = re.compile(r"(?<![a-z0-9-])((?:[a-z0-9-]+\.)*xn--[a-z0-9-]+(?:\.[a-z0-9-]+)*)", re.I)


def _label_to_unicode(lab: str) -> str:
    if not lab.lower().startswith("xn--"):
        return lab
    try:
        import idna  # IDNA 2008 / UTS 46, what browsers and registries use

        return idna.decode(lab)
    except Exception:  # noqa: BLE001 - fall back to the stdlib's IDNA 2003 codec
        try:
            return lab.encode("ascii").decode("idna")
        except UnicodeError:
            return lab


def to_unicode(domain: str) -> str:
    """'zdp.xn--vuq861b' → 'zdp.信息'; other names come back unchanged."""
    if "xn--" not in domain.lower():
        return domain
    return ".".join(_label_to_unicode(lab) for lab in domain.split("."))


def to_ascii(domain: str) -> str:
    """'zdp.信息' → 'zdp.xn--vuq861b' (the form DNS uses)."""
    try:
        domain.encode("ascii")
        return domain
    except UnicodeEncodeError:
        pass
    try:
        import idna

        return idna.encode(domain, uts46=True).decode("ascii")
    except Exception:  # noqa: BLE001
        return domain.encode("idna").decode("ascii")


def display(domain: str, idn: str = "unicode") -> str:
    """The domain in the requested form: 'unicode' (readable) or 'punycode' (ASCII)."""
    return to_unicode(domain) if idn == "unicode" else to_ascii(domain)


def humanize(text: str, idn: str = "unicode") -> str:
    """Rewrite every Punycode name inside free text (evidence, status, notes)."""
    if idn != "unicode" or "xn--" not in (text or "").lower():
        return text
    return _PUNY.sub(lambda m: to_unicode(m.group(1)), text)
