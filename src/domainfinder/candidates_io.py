"""Reading candidate domains discovered by other processes (--import, --candidate)."""

from __future__ import annotations

import csv
import io
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .domains import registrable, to_ascii


@dataclass
class ImportResult:
    source: str
    entries: int = 0  # non-empty entries read
    domains: list[str] = field(default_factory=list)  # unique registrable domains, in input order
    invalid: list[str] = field(default_factory=list)  # entries that are not domain names
    reduced: int = 0  # entries that were host names/URLs, reduced to their registrable domain

    def summary(self) -> str:
        bits = [f"{len(self.domains)} candidate domain(s) from {self.entries} entr{'y' if self.entries == 1 else 'ies'}"]
        if self.reduced:
            bits.append(f"{self.reduced} host name(s)/URL(s) reduced to their registrable domain")
        dupes = self.entries - len(self.invalid) - len(self.domains)
        if dupes > 0:
            bits.append(f"{dupes} duplicate(s) merged")
        if self.invalid:
            shown = ", ".join(self.invalid[:5]) + (" …" if len(self.invalid) > 5 else "")
            bits.append(f"{len(self.invalid)} skipped as not a domain ({shown})")
        return f"import {self.source}: " + "; ".join(bits)


def parse_domain_list(text: str, source: str = "input") -> ImportResult:
    """Split on commas and newlines (CSV quoting understood); '#' starts a comment.

    Each entry is reduced to its registrable domain, so 'https://www.Example.co.uk/x'
    and 'mail.example.co.uk' both become 'example.co.uk'.
    """
    res = ImportResult(source=source)
    seen: set[str] = set()
    lines = [ln.split("#", 1)[0] for ln in text.lstrip("﻿").splitlines()]
    for row in csv.reader(io.StringIO("\n".join(lines)), skipinitialspace=True):
        for raw in row:
            entry = raw.strip().strip("'\"").strip()
            if not entry:
                continue
            res.entries += 1
            rd = registrable(entry)
            if not rd:
                res.invalid.append(entry)
                continue
            if rd != to_ascii(entry.lower().rstrip(".")):
                res.reduced += 1
            if rd not in seen:
                seen.add(rd)
                res.domains.append(rd)
    return res


def read_domain_file(path: str) -> ImportResult:
    """Read a file of candidate domains; '-' reads standard input."""
    if path == "-":
        return parse_domain_list(sys.stdin.read(), "stdin")
    text = Path(path).expanduser().read_text(encoding="utf-8-sig", errors="replace")
    return parse_domain_list(text, path)
