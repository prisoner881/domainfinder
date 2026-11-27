"""crt.sh's public PostgreSQL database (guest@crt.sh:5432/certwatch).

crt.sh is a web front end on a public, read-only PostgreSQL database. The
web JSON API caps every search at 10,000 identities and its front end is
often overloaded (404/502/504). The same searches run directly against the
database are lighter (only the columns we need) and can go past the cap.

The queries mirror the SQL crt.sh itself runs for each kind of search (as
shown by crt.sh's ``showSQL=Y`` option), so both routes give the same rows;
the only intended difference is the row limit.

Any failure falls back to the web API: a refused or blocked connection
(many networks block outbound port 5432) turns the database off for the rest
of the run; a failed query falls back for that query, and two failed queries
turn it off. Nothing here is required for a run to succeed.
"""

from __future__ import annotations

import asyncio
import contextvars
import logging
from typing import Any

log = logging.getLogger(__name__)

HOST = "crt.sh"
PORT = 5432
DBNAME = "certwatch"
USER = "guest"

# The run's database client, if any (set by the pipeline; read by crtsh_json).
CURRENT: contextvars.ContextVar["CrtshDb | None"] = contextvars.ContextVar("crtsh_db", default=None)

_EXPIRY = """
                      AND coalesce(x509_notAfter(cai.CERTIFICATE), 'infinity'::timestamp) >= date_trunc('year', now() AT TIME ZONE 'UTC')
                      AND x509_notAfter(cai.CERTIFICATE) >= now() AT TIME ZONE 'UTC'"""

# Same matching as crt.sh's own search SQL for ?q= and ?O=.
_MATCH = {
    "q": "cai.NAME_VALUE ILIKE ('%%' || %(v)s::text || '%%')",
    "O": "plainto_tsquery('certwatch', %(v)s::text) @@ to_tsvector('certwatch', cai.NAME_VALUE)"
         "\n                      AND cai.NAME_TYPE = '2.5.4.10'",  # organizationName
}

_SQL = """WITH ci AS (
    SELECT min(sub.CERTIFICATE_ID) ID,
           min(sub.ISSUER_CA_ID) ISSUER_CA_ID,
           array_agg(DISTINCT sub.NAME_VALUE) NAME_VALUES,
           x509_commonName(sub.CERTIFICATE) COMMON_NAME,
           x509_notBefore(sub.CERTIFICATE) NOT_BEFORE,
           x509_notAfter(sub.CERTIFICATE) NOT_AFTER,
           count(sub.CERTIFICATE_ID)::bigint RESULT_COUNT
        FROM (SELECT cai.*
                  FROM certificate_and_identities cai
                  WHERE plainto_tsquery('certwatch', %(v)s::text) @@ identities(cai.CERTIFICATE)
                      AND {match}{expiry}
                  LIMIT {limit:d}
             ) sub
        GROUP BY sub.CERTIFICATE
)
SELECT ci.ISSUER_CA_ID, ca.NAME ISSUER_NAME, ci.COMMON_NAME,
       array_to_string(ci.NAME_VALUES, chr(10)) NAME_VALUE,
       ci.ID ID, ci.NOT_BEFORE, ci.NOT_AFTER, ci.RESULT_COUNT
    FROM ci, ca
    WHERE ci.ISSUER_CA_ID = ca.ID
    ORDER BY NOT_BEFORE DESC"""

CERT_SQL = "SELECT c.CERTIFICATE FROM certificate c WHERE c.ID = %(id)s::bigint"


def build_query(params: dict[str, str], limit: int) -> tuple[str, dict[str, Any]] | None:
    """SQL + arguments for a crt.sh web-API parameter set ({"q"|"O": value,
    optional "exclude": "expired"}); None for searches we don't translate."""
    kinds = [k for k in ("q", "O") if params.get(k)]
    if len(kinds) != 1 or set(params) - {"q", "O", "exclude"}:
        return None
    kind = kinds[0]
    expiry = _EXPIRY if params.get("exclude") == "expired" else ""
    sql = _SQL.format(match=_MATCH[kind], expiry=expiry, limit=int(limit))
    return sql, {"v": params[kind]}


def _iso(v: Any) -> str:
    return v.isoformat() if hasattr(v, "isoformat") else ("" if v is None else str(v))


def to_rows(columns: list[str], records: list[tuple]) -> list[dict[str, Any]]:
    """Database records → the same dicts crt.sh's JSON API returns."""
    out = []
    for rec in records:
        d = dict(zip((c.lower() for c in columns), rec))
        out.append({
            "issuer_ca_id": d.get("issuer_ca_id"),
            "issuer_name": d.get("issuer_name") or "",
            "common_name": d.get("common_name") or "",
            "name_value": d.get("name_value") or "",
            "id": d.get("id"),
            "not_before": _iso(d.get("not_before")),
            "not_after": _iso(d.get("not_after")),
            "result_count": int(d.get("result_count") or 1),
        })
    return out


class CrtshDb:
    def __init__(self, host: str = HOST, port: int = PORT, limit: int = 50_000, connect_timeout: float = 10.0,
                 max_failures: int = 2):
        self.host = host
        self.port = port
        self.limit = limit
        self.connect_timeout = connect_timeout
        self.max_failures = max_failures
        self.disabled_reason = ""
        self.queries = 0  # answered by the database
        self.fallbacks = 0  # handed to the web API
        self._failures = 0
        self._conn = None
        self._lock = asyncio.Lock()

    # -- connection -----------------------------------------------------------------
    async def _connect(self):
        import psycopg  # optional at import time: missing driver → web API

        return await asyncio.wait_for(
            psycopg.AsyncConnection.connect(
                host=self.host, port=self.port, dbname=DBNAME, user=USER,
                connect_timeout=int(self.connect_timeout), autocommit=True,
                prepare_threshold=None,  # no server-side prepared statements on a shared guest server
                application_name="domainfinder",
            ),
            timeout=self.connect_timeout + 5,
        )

    async def _drop(self) -> None:
        conn, self._conn = self._conn, None
        if conn is not None:
            try:
                await conn.close()
            except Exception:  # pragma: no cover - best effort
                pass

    def _disable(self, reason: str) -> None:
        if not self.disabled_reason:
            reason = " ".join(reason.split())
            self.disabled_reason = reason if len(reason) <= 160 else reason[:157].rstrip() + "..."
            log.info("crt.sh database off for this run: %s", self.disabled_reason)

    async def _execute(self, sql: str, args: dict[str, Any], timeout: float) -> tuple[list[str], list[tuple]] | None:
        """Run one query; None (and the reason recorded) on any failure."""
        if self.disabled_reason:
            return None
        async with self._lock:  # one connection, one query at a time
            if self.disabled_reason:
                return None
            if self._conn is None or getattr(self._conn, "closed", False):
                try:
                    self._conn = await self._connect()
                except ImportError:
                    self._disable("the psycopg driver is not installed")
                    return None
                except Exception as e:  # refused, blocked, timed out, too many connections...
                    self._disable(f"cannot connect to {self.host}:{self.port} ({type(e).__name__}: {e})".strip())
                    return None
            try:
                async with self._conn.cursor() as cur:
                    await asyncio.wait_for(cur.execute(sql, args), timeout)
                    records = await asyncio.wait_for(cur.fetchall(), timeout)
                    columns = [c.name for c in (cur.description or [])]
                self._failures = 0
                return columns, records
            except Exception as e:  # statement timeout, dropped connection, schema change...
                self._failures += 1
                log.info("crt.sh database query failed (%s: %s)", type(e).__name__, e)
                await self._drop()
                if self._failures >= self.max_failures:
                    self._disable(f"{self._failures} queries failed (last: {type(e).__name__})")
                return None

    # -- searches -------------------------------------------------------------------
    async def search(self, params: dict[str, str], timeout: float) -> list[dict[str, Any]] | None:
        q = build_query(params, self.limit)
        if q is None:
            return None
        res = await self._execute(*q, timeout=timeout)
        if res is None:
            self.fallbacks += 1
            return None
        self.queries += 1
        return to_rows(*res)

    async def certificate_der(self, cert_id: int, timeout: float = 60.0) -> bytes | None:
        res = await self._execute(CERT_SQL, {"id": int(cert_id)}, timeout)
        if not res or not res[1]:
            if res is None:
                self.fallbacks += 1
            return None
        self.queries += 1
        der = res[1][0][0]
        return bytes(der) if der is not None else None

    def summary(self) -> str:
        if self.disabled_reason and not self.queries:
            return f"crt.sh: web API used (database unavailable: {self.disabled_reason})"
        parts = [f"crt.sh: {self.queries} quer{'y' if self.queries == 1 else 'ies'} via the database"]
        if self.fallbacks:
            parts.append(f"{self.fallbacks} fell back to the web API")
        if self.disabled_reason:
            parts.append(f"database turned off mid-run: {self.disabled_reason}")
        return "; ".join(parts)

    async def aclose(self) -> None:
        await self._drop()
