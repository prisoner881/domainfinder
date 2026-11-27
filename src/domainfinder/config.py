"""Settings from environment variables (and an optional .env file)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except ValueError:
        return default


def _bool(name: str, default: bool) -> bool:
    v = _env(name, "1" if default else "0").lower()
    return v in ("1", "true", "yes", "on")


def default_cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "domainfinder"


@dataclass
class Settings:
    dns_mode: str = "auto"
    cache_dir: Path = field(default_factory=default_cache_dir)
    cache_ttl_hours: int = 24
    use_cache: bool = True
    concurrency: int = 12
    high_threshold: int = 70
    review_threshold: int = 40
    http_timeout: float = 20.0
    hackertarget: bool = True
    shared_ns_threshold: int = 5000
    sec_user_agent: str = ""
    contact: str = ""  # optional contact added to the User-Agent for Wikidata (Wikimedia policy)
    viewdns_key: str = field(default="", repr=False)
    securitytrails_key: str = field(default="", repr=False)
    whoisxml_key: str = field(default="", repr=False)
    domaintools_user: str = field(default="", repr=False)
    domaintools_key: str = field(default="", repr=False)
    tls_check: bool = True
    whoisxml_search: str = "both"  # current | historic | both
    whoisxml_max_pages: int = 1  # purchase pages (10,000 domains, 1 credit each) per search
    wikidata: bool = True  # subsidiaries' websites from Wikidata
    acquisitions: bool = True  # CT search for acquired companies' names learned from owned domains
    csp_discovery: bool = True  # one hop: domains in the CSP of owned/review domains become candidates
    all_tlds: bool = False  # gtld sweep over every TLD (IANA list) instead of the common ones
    whois: bool = True  # port-43 WHOIS fallback for TLDs without RDAP (.edu)
    crtsh_timeout: float = 120.0
    crtsh_db: bool = True  # try crt.sh's public PostgreSQL database before its web API
    crtsh_db_limit: int = 50_000  # identities per database search (the web API stops at 10,000)
    idn: str = "unicode"  # how internationalized names are written out: unicode | punycode

    @classmethod
    def from_env(cls, load_dotenv_file: bool = True) -> "Settings":
        if load_dotenv_file:
            try:
                from dotenv import load_dotenv

                load_dotenv(override=False)
            except ImportError:  # pragma: no cover - optional
                pass
        cache_dir = _env("DOMAINFINDER_CACHE_DIR")
        return cls(
            dns_mode=_env("DOMAINFINDER_DNS_MODE", "auto") or "auto",
            cache_dir=Path(cache_dir) if cache_dir else default_cache_dir(),
            cache_ttl_hours=_int("DOMAINFINDER_CACHE_TTL_HOURS", 24),
            concurrency=_int("DOMAINFINDER_CONCURRENCY", 12),
            high_threshold=_int("DOMAINFINDER_HIGH_THRESHOLD", 70),
            review_threshold=_int("DOMAINFINDER_REVIEW_THRESHOLD", 40),
            hackertarget=_bool("DOMAINFINDER_HACKERTARGET", True),
            shared_ns_threshold=_int("DOMAINFINDER_SHARED_NS_THRESHOLD", 5000),
            sec_user_agent=_env("DOMAINFINDER_SEC_USER_AGENT"),
            contact=_env("DOMAINFINDER_CONTACT"),
            viewdns_key=_env("VIEWDNS_API_KEY"),
            securitytrails_key=_env("SECURITYTRAILS_API_KEY"),
            whoisxml_key=_env("WHOISXML_API_KEY"),
            domaintools_user=_env("DOMAINTOOLS_API_USERNAME"),
            domaintools_key=_env("DOMAINTOOLS_API_KEY"),
            whois=_bool("DOMAINFINDER_WHOIS", True),
            all_tlds=_bool("DOMAINFINDER_ALL_TLDS", False),
            csp_discovery=_bool("DOMAINFINDER_CSP", True),
            wikidata=_bool("DOMAINFINDER_WIKIDATA", True),
            crtsh_db=_bool("DOMAINFINDER_CRTSH_DB", True),
            crtsh_db_limit=max(1000, _int("DOMAINFINDER_CRTSH_DB_LIMIT", 50_000)),
            acquisitions=_bool("DOMAINFINDER_ACQUISITIONS", True),
            whoisxml_search=_env("DOMAINFINDER_WHOISXML_SEARCH", "both").lower() or "both",
            whoisxml_max_pages=_int("DOMAINFINDER_WHOISXML_MAX_PAGES", 1),
            idn="punycode" if _env("DOMAINFINDER_IDN").lower() == "punycode" else "unicode",
        )
