"""Candidate sources. Add a new one by subclassing Source and listing it here."""

from __future__ import annotations

from .base import Source, SourceContext
from .cctld import CcTldSource, GTldSource
from .crtsh import CrtshDomainSource, CrtshOrgSource
from .edgar import EdgarSource
from .links import SeedLinkSource
from .paid import DomainToolsSource, SecurityTrailsSource
from .whoisxml import WhoisXmlSource
from .reverse_ns import HackerTargetSource, ViewDnsSource

ALL_SOURCES: list[type[Source]] = [
    CrtshOrgSource,
    CrtshDomainSource,
    CcTldSource,
    GTldSource,
    SeedLinkSource,
    EdgarSource,
    HackerTargetSource,
    ViewDnsSource,
    SecurityTrailsSource,
    WhoisXmlSource,
    DomainToolsSource,
]

__all__ = ["ALL_SOURCES", "Source", "SourceContext"]
