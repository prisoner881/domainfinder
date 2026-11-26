"""Polite async HTTP: per-host concurrency and spacing, backoff, Retry-After, cache."""

from __future__ import annotations

import asyncio
import email.utils
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from . import USER_AGENT
from .cache import Cache

log = logging.getLogger(__name__)

# host → (max concurrent requests, minimum seconds between request starts)
HOST_LIMITS: dict[str, tuple[int, float]] = {
    "crt.sh": (2, 1.0),
    "rdap.org": (2, 0.5),
    "api.hackertarget.com": (1, 1.5),
    "api.viewdns.info": (1, 1.0),
    "data.sec.gov": (2, 0.15),
    "www.sec.gov": (2, 0.15),
    "efts.sec.gov": (2, 0.15),
    "dns.google": (8, 0.0),
    "cloudflare-dns.com": (8, 0.0),
}
DEFAULT_LIMIT = (4, 0.0)
RETRY_STATUSES = {429, 500, 502, 503, 504}
MAX_RETRY_AFTER = 60.0


@dataclass
class Response:
    status: int
    url: str
    text: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    error: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def json(self) -> Any:
        import json

        return json.loads(self.text)

    def to_cache(self) -> dict[str, Any]:
        return {"status": self.status, "url": self.url, "text": self.text, "headers": self.headers}

    @classmethod
    def from_cache(cls, d: dict[str, Any]) -> "Response":
        return cls(status=d["status"], url=d["url"], text=d.get("text", ""), headers=d.get("headers", {}))


@dataclass
class Hop:
    url: str
    status: int
    location: str = ""


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return min(float(value), MAX_RETRY_AFTER)
    try:
        dt = email.utils.parsedate_to_datetime(value)
        return max(0.0, min(dt.timestamp() - time.time(), MAX_RETRY_AFTER))
    except (TypeError, ValueError):
        return None


class _HostGate:
    def __init__(self, concurrent: int, interval: float):
        self.sem = asyncio.Semaphore(concurrent)
        self.interval = interval
        self.next_start = 0.0
        self.lock = asyncio.Lock()

    async def __aenter__(self):
        await self.sem.acquire()
        if self.interval:
            async with self.lock:
                now = time.monotonic()
                wait = self.next_start - now
                self.next_start = max(now, self.next_start) + self.interval
            if wait > 0:
                await asyncio.sleep(wait)
        return self

    async def __aexit__(self, *exc):
        self.sem.release()


KEEP_HEADERS = ("content-type", "location", "content-security-policy", "retry-after", "server")


class Http:
    def __init__(
        self,
        cache: Cache | None = None,
        timeout: float = 20.0,
        retries: int = 3,
        user_agent: str = USER_AGENT,
        client: httpx.AsyncClient | None = None,
    ):
        self.cache = cache or Cache.memory()
        self.timeout = timeout
        self.retries = retries
        self.user_agent = user_agent
        common = dict(
            follow_redirects=False,
            headers={"User-Agent": user_agent, "Accept-Encoding": "gzip, deflate"},
            trust_env=True,
        )
        # Two pools: slow or dead web hosts must never starve the API calls
        # (DNS-over-HTTPS, RDAP, crt.sh) that every candidate depends on.
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, pool=120.0),
            limits=httpx.Limits(max_connections=64, max_keepalive_connections=32),
            **common,
        )
        self._web = client or httpx.AsyncClient(
            timeout=httpx.Timeout(12.0, connect=6.0, pool=60.0),
            limits=httpx.Limits(max_connections=128, max_keepalive_connections=8),
            **common,
        )
        self._gates: dict[str, _HostGate] = {}
        self.stats: dict[str, int] = {}

    async def aclose(self) -> None:
        await self._client.aclose()
        if self._web is not self._client:
            await self._web.aclose()

    def _gate(self, host: str) -> _HostGate:
        g = self._gates.get(host)
        if g is None:
            c, i = HOST_LIMITS.get(host, DEFAULT_LIMIT)
            g = self._gates[host] = _HostGate(c, i)
        return g

    async def _request(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        retries: int | None = None,
        max_bytes: int = 20_000_000,
        web: bool = False,
    ) -> Response:
        host = urlsplit(url).hostname or ""
        client = self._web if web else self._client
        attempts = (self.retries if retries is None else retries) + 1
        last = Response(status=0, url=url, error="not attempted")
        for attempt in range(attempts):
            delay: float | None = None
            async with self._gate(host):
                self.stats[host] = self.stats.get(host, 0) + 1
                try:
                    req = client.build_request("GET", url, params=params, headers=headers,
                                               timeout=timeout or (None if web else self.timeout))
                    resp = await client.send(req, stream=True)
                    try:
                        body = bytearray()
                        async for chunk in resp.aiter_bytes():
                            body.extend(chunk)
                            if len(body) > max_bytes:
                                break
                        enc = resp.encoding or "utf-8"
                        try:
                            text = body.decode(enc, errors="replace")
                        except LookupError:
                            text = body.decode("utf-8", errors="replace")
                    finally:
                        await resp.aclose()
                    hdrs = {k: resp.headers[k] for k in KEEP_HEADERS if k in resp.headers}
                    last = Response(status=resp.status_code, url=str(resp.url), text=text, headers=hdrs)
                    if resp.status_code not in RETRY_STATUSES:
                        return last
                    delay = _parse_retry_after(resp.headers.get("retry-after"))
                except (httpx.TransportError, httpx.DecodingError) as e:
                    last = Response(status=0, url=url, error=f"{type(e).__name__}: {e}"[:300])
            if attempt + 1 < attempts:
                if delay is None:
                    delay = min(2 ** (attempt + 1), 30) + random.uniform(0, 1)
                log.debug("retrying %s in %.1fs (%s)", url, delay, last.status or last.error)
                await asyncio.sleep(delay)
        return last

    async def get(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        ttl: int | None = None,
        timeout: float | None = None,
        retries: int | None = None,
        cache_errors: bool = False,
    ) -> Response:
        """GET a URL (no redirect following), cached by URL+params."""
        key = "GET " + str(httpx.URL(url, params=params))
        cached = self.cache.get(key, ttl)
        if cached is not None:
            return Response.from_cache(cached)
        resp = await self._request(url, params=params, headers=headers, timeout=timeout, retries=retries)
        if resp.status and (resp.ok or resp.status in (301, 302, 303, 307, 308, 404) or cache_errors):
            self.cache.set(key, resp.to_cache())
        return resp

    async def get_follow(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        max_redirects: int = 5,
        ttl: int | None = None,
        timeout: float | None = None,
        retries: int | None = None,
    ) -> Response:
        """GET following redirects (for APIs like RDAP that redirect)."""
        current = url
        for _ in range(max_redirects + 1):
            r = await self.get(current, headers=headers, ttl=ttl, timeout=timeout, retries=retries)
            loc = r.headers.get("location")
            if r.status in (301, 302, 303, 307, 308) and loc:
                current = urljoin(current, loc)
                continue
            return r
        return r

    async def fetch_page(
        self,
        url: str,
        *,
        max_redirects: int = 10,
        max_bytes: int = 600_000,
        ttl: int | None = None,
        timeout: float | None = None,
    ) -> tuple[list[Hop], Response]:
        """Fetch a web page hop by hop, recording the redirect chain."""
        key = f"PAGE {url}"
        cached = self.cache.get(key, ttl)
        if cached is not None:
            hops = [Hop(**h) for h in cached["hops"]]
            return hops, Response.from_cache(cached["resp"])
        hops: list[Hop] = []
        current = url
        resp = Response(status=0, url=url, error="no request")
        for _ in range(max_redirects + 1):
            resp = await self._request(current, timeout=timeout, retries=0, max_bytes=max_bytes, web=True)
            loc = resp.headers.get("location", "")
            hops.append(Hop(url=current, status=resp.status, location=loc))
            if resp.status in (301, 302, 303, 307, 308) and loc:
                current = urljoin(current, loc)
                continue
            break
        resp.text = resp.text[:max_bytes]
        if resp.status:
            self.cache.set(key, {"hops": [h.__dict__ for h in hops], "resp": resp.to_cache()})
        return hops, resp
