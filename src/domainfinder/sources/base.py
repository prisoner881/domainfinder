"""The Source interface every candidate provider implements (free or paid)."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..models import Candidate, Fingerprint

if TYPE_CHECKING:
    from ..config import Settings
    from ..fingerprint import Collectors

log = logging.getLogger(__name__)


@dataclass
class CtOrgHit:
    """A registrable domain seen in certificates whose Subject O= is the seed's org."""

    org: str
    count: int = 0
    latest_not_after: str = ""
    current: bool = False


@dataclass
class SourceContext:
    seed: Fingerprint
    settings: "Settings"
    collectors: "Collectors"
    org_names: list[str] = field(default_factory=list)
    brand_labels: list[str] = field(default_factory=list)
    # Filled by the crt.sh organization source, read by the scorer.
    ct_org_domains: dict[str, CtOrgHit] = field(default_factory=dict)
    # Domain → subsidiary name from SEC Exhibit 21, read by the scorer.
    subsidiary_names: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def http(self):
        return self.collectors.http

    @property
    def resolver(self):
        return self.collectors.resolver


class Source(ABC):
    #: short identifier used in output and on the command line
    name: str = ""
    #: one line for --list-sources
    description: str = ""
    paid: bool = False

    def __init__(self, settings: "Settings"):
        self.settings = settings

    def enabled(self) -> bool:
        return True

    def disabled_reason(self) -> str:
        return ""

    @abstractmethod
    async def candidates(self, ctx: SourceContext) -> list[Candidate]:
        """Return candidate domains (registrable, lower-case, not the seed)."""

    async def ns_usage(self, ns_host: str) -> int | None:
        """How many domains use this nameserver (None when the source can't say).

        Paid reverse-NS sources implement this; the scorer treats an NS set
        used by more than settings.shared_ns_threshold domains as shared.
        """
        return None


def make_candidates(domains, source: str, seed: str, note: str = "") -> list[Candidate]:
    from ..data import load as load_data
    from ..domains import registrable

    skip = load_data().common_third_party
    out: dict[str, Candidate] = {}
    for d in domains:
        rd = registrable(d)
        if not rd or rd == seed or rd in skip:
            continue
        c = out.setdefault(rd, Candidate(domain=rd))
        c.add_source(source, note)
    return list(out.values())
