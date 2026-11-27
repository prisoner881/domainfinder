"""Homepage fetch: redirect chain, analytics IDs, outbound links, CSP domains."""

from __future__ import annotations

import html as htmllib
import re
from urllib.parse import urljoin, urlsplit

from ..data import load as load_data
from ..domains import registrable
from ..http import Http
from ..models import WebInfo

ANALYTICS_PATTERNS = [
    ("ga4", re.compile(r"\b(G-[A-Z0-9]{8,12})\b")),
    ("ua", re.compile(r"\b(UA-\d{4,10}-\d{1,4})\b")),
    ("gtm", re.compile(r"\b(GTM-[A-Z0-9]{5,9})\b")),
    ("adobe-launch", re.compile(r"assets\.adobedtm\.com/(?:launch-)?([0-9a-f]{10,}|[A-Za-z0-9]{6,}/)")),
    ("fb-pixel", re.compile(r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{10,20})['\"]")),
    ("hotjar", re.compile(r"hjid\s*:\s*(\d{5,10})")),
    ("onetrust", re.compile(r"data-domain-script=['\"]([0-9a-f-]{36})")),
]
HREF = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#\s]+)""", re.I)
TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
TAG = re.compile(r"<(link|meta)\b([^>]*)>", re.I)
ATTR = re.compile(r"""([a-zA-Z:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""")


def extract_canonical(html: str, base_url: str) -> str:
    """The page's declared canonical URL: <link rel="canonical"> first, then og:url."""
    og = ""
    for m in TAG.finditer(html[:300_000]):
        attrs = {a.group(1).lower(): (a.group(2) or a.group(3) or a.group(4) or "") for a in ATTR.finditer(m.group(2))}
        if m.group(1).lower() == "link" and "canonical" in attrs.get("rel", "").lower().split() and attrs.get("href"):
            return urljoin(base_url, htmllib.unescape(attrs["href"]).strip())
        if m.group(1).lower() == "meta" and attrs.get("property", "").lower() == "og:url" and attrs.get("content"):
            og = og or urljoin(base_url, htmllib.unescape(attrs["content"]).strip())
    return og


def extract_analytics(html: str) -> list[str]:
    out = []
    for kind, pat in ANALYTICS_PATTERNS:
        for m in pat.finditer(html):
            v = f"{kind}:{m.group(1).rstrip('/')}"
            if v not in out:
                out.append(v)
    return out


def extract_links(html: str, base_url: str) -> list[str]:
    doms: list[str] = []
    for m in HREF.finditer(html):
        href = htmllib.unescape(m.group(1))
        if href.startswith(("mailto:", "tel:", "javascript:", "data:")):
            continue
        url = urljoin(base_url, href)
        host = urlsplit(url).hostname
        if not host:
            continue
        rd = registrable(host)
        if rd and rd not in doms:
            doms.append(rd)
    return doms


def extract_csp_domains(csp: str) -> list[str]:
    doms: list[str] = []
    for tok in re.split(r"[\s;]+", csp or ""):
        if "." not in tok or tok.startswith("'"):
            continue
        rd = registrable(tok.replace("*.", ""))
        if rd and rd not in doms:
            doms.append(rd)
    return doms


async def collect_web(domain: str, http: Http, apex_resolves: bool = True, budget: float = 30.0) -> WebInfo:
    import asyncio

    try:
        return await asyncio.wait_for(_collect_web(domain, http, apex_resolves), budget)
    except asyncio.TimeoutError:
        return WebInfo(error=f"no web response within {budget:.0f}s")


async def _collect_web(domain: str, http: Http, apex_resolves: bool) -> WebInfo:
    info = WebInfo()
    host = domain if apex_resolves else f"www.{domain}"
    for start in (f"http://{host}/", f"https://{host}/"):
        hops, resp = await http.fetch_page(start)
        if resp.status == 0 and len(hops) <= 1:
            info.error = resp.error
            continue
        info.fetched = True
        info.start_url = start
        info.chain = [h.url for h in hops]
        info.final_url = hops[-1].url if hops else start
        info.status = resp.status
        text = resp.text or ""
        m = TITLE.search(text)
        if m:
            info.title = " ".join(htmllib.unescape(m.group(1)).split())[:200]
        info.analytics_ids = extract_analytics(text)
        info.canonical_url = extract_canonical(text, info.final_url)
        info.linked_domains = extract_links(text, info.final_url)
        info.csp_domains = extract_csp_domains(resp.headers.get("content-security-policy", ""))
        marker = load_data().has_parking_marker(text[:200_000])
        if marker:
            info.parking_marker = marker
        info.error = ""
        break
    return info


def chain_domains(info: WebInfo) -> list[str]:
    out = []
    for u in info.chain:
        rd = registrable(urlsplit(u).hostname or "")
        if rd and rd not in out:
            out.append(rd)
    return out
