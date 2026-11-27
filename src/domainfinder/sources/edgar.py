"""SEC EDGAR Exhibit 21 (subsidiaries) → '<name>.com' guesses (US public companies)."""

from __future__ import annotations

import html as htmllib
import logging
import re

from ..models import Candidate
from ..orgnames import normalize, same_org
from .base import Source, SourceContext

log = logging.getLogger(__name__)

TICKERS = "https://www.sec.gov/files/company_tickers.json"
SUBMISSIONS = "https://data.sec.gov/submissions/CIK{cik:010d}.json"
ARCHIVE = "https://www.sec.gov/Archives/edgar/data/{cik}/{acc}/"
TTL = 7 * 86400
CELL = re.compile(r"<t[dh][^>]*>(.*?)</t[dh]>", re.I | re.S)
TAG = re.compile(r"<[^>]+>")
NOT_NAMES = re.compile(r"^(name|jurisdiction|state|country|subsidiar|percent|owned|organized|incorporat|\(?\d)", re.I)


# Exhibit 21 file names vary by filer: ex21.htm, ex-21.htm, ex211.htm,
# zdp-20260630xexhibit21.htm, exhibit21_1.htm ...
EX21_NAME = re.compile(r"(?:ex|exhibit)[-_.]?21", re.I)
HREF = re.compile(r'href="([^"]+)"', re.I)

ROW = re.compile(r"<tr[^>]*>(.*?)</tr>", re.I | re.S)
TABLE = re.compile(r"<table[^>]*>(.*?)</table>", re.I | re.S)


def _text(cell: str) -> str:
    return " ".join(htmllib.unescape(TAG.sub(" ", cell)).split())


def _name_column(rows: list[list[str]]) -> int:
    """The leftmost column that is regularly filled in. Later columns hold the
    jurisdiction or ownership; empty leading columns are layout spacers."""
    width = max(len(r) for r in rows)
    filled = [sum(1 for r in rows if i < len(r) and r[i]) for i in range(width)]
    best = max(filled)
    return next(i for i, n in enumerate(filled) if n >= best / 2)


def subsidiary_names(doc: str) -> list[str]:
    """Subsidiary names from an Exhibit 21: only each table's name column."""
    names: list[str] = []
    cells: list[str] = []
    for table in TABLE.findall(doc) or ([doc] if ROW.search(doc) else []):
        rows = [[_text(c) for c in CELL.findall(r)] for r in ROW.findall(table)]
        rows = [r for r in rows if any(r)]
        if not rows:
            continue
        col = _name_column(rows)
        cells += [r[col] for r in rows if col < len(r) and r[col]]
    if not cells:
        cells = doc.splitlines()
    for raw in cells:
        text = " ".join(htmllib.unescape(TAG.sub(" ", raw)).split())
        if not (3 <= len(text) <= 90) or NOT_NAMES.match(text):
            continue
        if not re.search(r"[A-Za-z]{3}", text):
            continue
        if text not in names:
            names.append(text)
    return names


def ex21_from_index(page: str) -> list[str]:
    """Exhibit 21 documents from a filing's -index.htm, by their declared
    document type (EX-21, EX-21.1, ...), whatever the file is called."""
    out = []
    for row in ROW.findall(page):
        cells = [_text(c) for c in CELL.findall(row)]
        if any(re.fullmatch(r"EX-21(\.\d+)?", c, re.I) for c in cells):
            m = HREF.search(row)
            if m:
                out.append(m.group(1).rsplit("/", 1)[-1])
    return out


def guesses(name: str) -> list[str]:
    toks = normalize(name).split()
    if not toks or len(toks) > 3:
        return []
    slug = "".join(toks)
    if not (4 <= len(slug) <= 30) or not slug.isalnum():
        return []
    return [f"{slug}.com"]


class EdgarSource(Source):
    name = "edgar"
    description = "SEC EDGAR Exhibit 21 subsidiary names → <name>.com guesses"

    def enabled(self) -> bool:
        return bool(self.settings.sec_user_agent)

    def disabled_reason(self) -> str:
        return "set DOMAINFINDER_SEC_USER_AGENT (name + contact e-mail, per SEC policy)"

    async def candidates(self, ctx: SourceContext) -> list[Candidate]:
        hdr = {"User-Agent": self.settings.sec_user_agent}
        r = await ctx.http.get(TICKERS, headers=hdr, ttl=TTL)
        if not r.ok:
            ctx.notes.append(f"edgar: ticker list unavailable (HTTP {r.status})")
            return []
        cik = None
        try:
            for row in r.json().values():
                if any(same_org(row.get("title", ""), o) for o in ctx.org_names):
                    cik = int(row["cik_str"])
                    break
        except (ValueError, KeyError, AttributeError):
            return []
        if cik is None:
            ctx.notes.append("edgar: no SEC registrant matches the seed's organization")
            return []
        r = await ctx.http.get(SUBMISSIONS.format(cik=cik), headers=hdr, ttl=TTL)
        if not r.ok:
            return []
        try:
            recent = r.json()["filings"]["recent"]
            idx = next(i for i, f in enumerate(recent["form"]) if f == "10-K")
            acc = recent["accessionNumber"][idx].replace("-", "")
        except (ValueError, KeyError, StopIteration):
            ctx.notes.append("edgar: no 10-K found")
            return []
        base = ARCHIVE.format(cik=cik, acc=acc)
        dashed = f"{acc[:10]}-{acc[10:12]}-{acc[12:]}"
        r = await ctx.http.get(base + "index.json", headers=hdr, ttl=TTL, cache_404=False)
        index_status = r.status
        try:
            items = r.json()["directory"]["item"] if r.ok else []
        except (ValueError, KeyError):
            items = []
        ex21 = [i["name"] for i in items if EX21_NAME.search(i.get("name", ""))]
        if not ex21:  # unusual file name: the filing index declares each document's type
            r = await ctx.http.get(base + f"{dashed}-index.htm", headers=hdr, ttl=TTL)
            ex21 = ex21_from_index(r.text) if r.ok else []
            if not r.ok and index_status != 200:
                ctx.notes.append(f"edgar: filing index unavailable (HTTP {r.status or index_status or r.error})")
                return []
        if not ex21:
            ctx.notes.append(f"edgar: latest 10-K ({dashed}) lists no Exhibit 21 document")
            return []
        r = await ctx.http.get(base + ex21[0], headers=hdr, ttl=TTL)
        if not r.ok:
            return []
        out: dict[str, Candidate] = {}
        for name in subsidiary_names(r.text):
            for g in guesses(name):
                if g == ctx.seed.domain:
                    continue
                ctx.subsidiary_names.setdefault(g, name)
                out.setdefault(g, Candidate(domain=g, sources={self.name: f"Exhibit 21: {name}"}))
        ctx.notes.append(f"edgar: {len(out)} guesses from CIK {cik} Exhibit 21")
        # Only guesses that exist are worth verifying.
        exist = []
        for d, c in out.items():
            ns = await ctx.resolver.query(d, "NS")
            if ns.status == "ok":
                exist.append(c)
        return exist
