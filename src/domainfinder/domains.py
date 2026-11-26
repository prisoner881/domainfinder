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
    """The registrable label: 'adp' for adp.com, 'adp' for adp.co.uk."""
    return _extract(clean(domain)).domain


def suffix(domain: str) -> str:
    return _extract(clean(domain)).suffix


def is_subdomain_of(host: str, domain: str) -> bool:
    host, domain = clean(host), clean(domain)
    return host == domain or host.endswith("." + domain)


def to_unicode(domain: str) -> str:
    """'adp.xn--vuq861b' → 'adp.信息'; other names come back unchanged."""
    if "xn--" not in domain:
        return domain
    out = []
    for lab in domain.split("."):
        if lab.startswith("xn--"):
            try:
                lab = lab.encode("ascii").decode("idna")
            except UnicodeError:
                pass
        out.append(lab)
    return ".".join(out)


def display(domain: str) -> str:
    """Punycode names with their readable form: 'adp.xn--vuq861b (adp.信息)'."""
    u = to_unicode(domain)
    return domain if u == domain else f"{domain} ({u})"
