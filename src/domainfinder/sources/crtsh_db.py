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
of the run; a failed query falls back for that query, and three failures in
a row turn it off. Nothing here is required for a run to succeed.
"""

from __future__ import annotations

import asyncio
import contextvars
import logging
import time
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


class ConnectFailed(Exception):
    """Every address of crt.sh failed; the message lists each address's error."""


def _first_line(e: BaseException) -> str:
    text = str(e).strip().splitlines()
    if isinstance(e, ConnectFailed):
        return " ".join(str(e).split())
    return f"{type(e).__name__}: {text[0]}" if text else type(e).__name__


def describe(params: dict[str, str]) -> str:
    kind = "O" if params.get("O") else "q"
    extra = ", current only" if params.get("exclude") == "expired" else ""
    return f"{kind}={params.get(kind)!r}{extra}"


class CrtshDb:
    def __init__(self, host: str = HOST, port: int = PORT, limit: int = 50_000, connect_timeout: float = 10.0,
                 max_failures: int = 3, search_timeout: float | None = None, max_idle: float = 30.0):
        self.host = host
        self.port = port
        self.limit = limit
        self.connect_timeout = connect_timeout
        self.max_failures = max_failures
        self.search_timeout = search_timeout  # per search; None = the caller's (web API) timeout
        self.max_idle = max_idle  # seconds a connection may sit unused before it is replaced
        self._last_used = 0.0
        self.disabled_reason = ""
        self.queries = 0  # answered by the database
        self.fallbacks = 0  # handed to the web API
        self.failures: list[str] = []  # what went wrong, for the run's notes
        self._failures = 0  # consecutive
        self._connected_once = False
        self._conn = None
        self._lock = asyncio.Lock()

    # -- connection -----------------------------------------------------------------
    async def _addresses(self) -> list[str]:
        """crt.sh's addresses, IPv4 first: networks without working IPv6 are
        common, and a dead IPv6 route must not hide a working IPv4 one."""
        import socket

        infos = await asyncio.get_running_loop().getaddrinfo(self.host, self.port, type=socket.SOCK_STREAM)
        v4 = [i[4][0] for i in infos if i[0] == socket.AF_INET]
        v6 = [i[4][0] for i in infos if i[0] == socket.AF_INET6]
        return list(dict.fromkeys(v4 + v6))

    async def _connect(self):
        import psycopg  # optional at import time: missing driver → web API

        errors = []
        for addr in await self._addresses():
            try:
                return await asyncio.wait_for(
                    psycopg.AsyncConnection.connect(
                        host=self.host, hostaddr=addr, port=self.port, dbname=DBNAME, user=USER,
                        connect_timeout=int(self.connect_timeout), autocommit=True,
                        prepare_threshold=None,  # no server-side prepared statements on a shared guest server
                        application_name="domainfinder",
                    ),
                    timeout=self.connect_timeout + 5,
                )
            except Exception as e:
                errors.append(f"{addr}: {_first_line(e)}")
        raise ConnectFailed("; ".join(errors) or f"{self.host} has no address")

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
            self.disabled_reason = reason if len(reason) <= 200 else reason[:197].rstrip() + "..."
            log.info("crt.sh database off for this run: %s", self.disabled_reason)

    def _failed(self, what: str, why: str) -> None:
        self._failures += 1
        self.failures.append(f"{what}: {why}")
        log.info("crt.sh database: %s failed (%s)", what, why)
        if self._failures >= self.max_failures:
            self._disable(f"{self._failures} failures in a row (last: {why})")

    def _connection_lost(self, e: BaseException) -> bool:
        """The connection itself went away (closed by crt.sh's pooler when
        idle, server restart...), as opposed to the query failing."""
        conn = self._conn
        why = str(e)
        return (conn is None or getattr(conn, "broken", False) or getattr(conn, "closed", False)
                or "idle_timeout" in why or "server closed the connection" in why
                or type(e).__name__ in ("ProtocolViolation", "AdminShutdown", "InterfaceError"))

    async def _ensure_connection(self, what: str) -> bool:
        if self._conn is not None and not getattr(self._conn, "closed", False):
            # crt.sh's connection pooler drops idle clients; don't find out mid-query.
            if time.monotonic() - self._last_used <= self.max_idle:
                return True
            await self._drop()
        try:
            self._conn = await self._connect()
        except ImportError:
            self._disable("the psycopg driver is not installed")
            return False
        except Exception as e:
            if not self._connected_once:  # never reached: blocked or refused, so stop trying
                self._disable(f"cannot connect to {self.host}:{self.port} ({_first_line(e)})")
            else:  # it worked earlier in this run: a passing problem, not a blocked port
                self._failed(f"reconnecting for {what}", _first_line(e))
            return False
        self._connected_once = True
        self._last_used = time.monotonic()
        return True

    async def _execute(self, sql: str, args: dict[str, Any], timeout: float, what: str = "query"
                       ) -> tuple[list[str], list[tuple]] | None:
        """Run one query; None (and the reason recorded) on any failure. A
        connection lost under us is replaced and the query tried once more."""
        if self.disabled_reason:
            return None
        async with self._lock:  # one connection, one query at a time
            for attempt in (1, 2):
                if self.disabled_reason or not await self._ensure_connection(what):
                    return None
                try:
                    # crt.sh's pooler runs in statement-pooling mode: no
                    # transactions, and each statement may reach a different
                    # server connection, so a SET would change someone else's
                    # session. The time limit is ours alone; on expiry the
                    # query is cancelled (the pooler forwards cancel requests).
                    async with self._conn.cursor() as cur:
                        await asyncio.wait_for(cur.execute(sql, args), timeout)
                        records = await asyncio.wait_for(cur.fetchall(), timeout)
                        columns = [c.name for c in (cur.description or [])]
                    self._failures = 0
                    self._last_used = time.monotonic()
                    return columns, records
                except Exception as e:  # statement timeout, dropped connection, schema change...
                    why = _first_line(e)
                    timed_out = isinstance(e, asyncio.TimeoutError) or "statement timeout" in why \
                        or "query_timeout" in why
                    if not timed_out and attempt == 1 and self._connection_lost(e):
                        log.info("crt.sh database: connection lost before %s (%s); reconnecting", what, why)
                        await self._drop()
                        continue
                    self._failed(what, f"no answer within {int(timeout)} s" if timed_out else why)
                    await self._cancel_or_drop()
                    return None
        return None

    async def _cancel_or_drop(self) -> None:
        """Keep a healthy connection; cancel anything still running; drop a broken one."""
        conn = self._conn
        if conn is None:
            return
        if not getattr(conn, "broken", False) and not getattr(conn, "closed", False):
            try:
                cancel = getattr(conn, "cancel_safe", None)
                if cancel is not None:
                    await asyncio.wait_for(cancel(), 10)
                return
            except Exception:
                pass
        await self._drop()

    # -- searches -------------------------------------------------------------------
    async def search(self, params: dict[str, str], timeout: float) -> list[dict[str, Any]] | None:
        q = build_query(params, self.limit)
        if q is None:
            return None
        res = await self._execute(*q, timeout=self.search_timeout or timeout, what=describe(params))
        if res is None:
            self.fallbacks += 1
            return None
        self.queries += 1
        return to_rows(*res)

    async def certificate_der(self, cert_id: int, timeout: float = 60.0) -> bytes | None:
        res = await self._execute(CERT_SQL, {"id": int(cert_id)}, timeout, what=f"certificate {cert_id}")
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
            parts.append(f"{self.fallbacks} via the web API instead")
        if self.failures:
            shown = self.failures[:4] + ([f"{len(self.failures) - 4} more"] if len(self.failures) > 4 else [])
            parts.append("database failures: " + " | ".join(shown))
        if self.disabled_reason:
            parts.append(f"database turned off mid-run ({self.disabled_reason})")
        return "; ".join(parts)

    async def aclose(self) -> None:
        await self._drop()
