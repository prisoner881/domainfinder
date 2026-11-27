"""1.2.0: crt.sh's public database first, its web API as the fallback."""

import datetime
import json

import pytest
import respx

from domainfinder.cache import Cache
from domainfinder.http import Http
from domainfinder.sources import crtsh_db
from domainfinder.sources.crtsh import CtRows, crtsh_json, seed_org_from_ct
from domainfinder.sources.crtsh_db import CURRENT, CrtshDb, build_query, to_rows

COLS = ["issuer_ca_id", "issuer_name", "common_name", "name_value", "id", "not_before", "not_after", "result_count"]
WHEN = datetime.datetime(2026, 1, 2, 3, 4, 5)
LATER = datetime.datetime(2027, 1, 2, 3, 4, 5)


class Col:
    def __init__(self, name):
        self.name = name


class FakeCursor:
    def __init__(self, conn):
        self.conn = conn
        self.description = None
        self._rows = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, sql, args=None):
        if sql.startswith("SET "):
            self.conn.settings.append(sql)
            return
        self.conn.calls.append((sql, args))
        answer = self.conn.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        cols, rows = answer
        self.description = [Col(c) for c in cols]
        self._rows = rows

    async def fetchall(self):
        return self._rows


class FakeConn:
    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = []
        self.settings = []
        self.transactions = 0
        self.closed = False
        self.broken = False

    def cursor(self):
        return FakeCursor(self)

    def transaction(self):
        conn = self

        class Tx:
            async def __aenter__(self):
                conn.transactions += 1

            async def __aexit__(self, *exc):
                return False

        return Tx()

    async def close(self):
        self.closed = True


def db_with(*answers, **kw):
    """A CrtshDb whose connections answer with `answers` in order."""
    db = CrtshDb(**kw)
    db.conns = []

    async def connect():
        conn = FakeConn(answers if not db.conns else db.conns[-1].answers)
        db.conns.append(conn)
        return conn

    db._connect = connect
    return db


def rows(*names, cn="www.adp.com", org=None):
    return (COLS, [(1, "C=US, O=DigiCert Inc", cn, org or n, 100 + i, WHEN, LATER, 1) for i, n in enumerate(names)])


async def using(db, coro):
    token = CURRENT.set(db)
    try:
        return await coro
    finally:
        CURRENT.reset(token)


# --- the SQL ---------------------------------------------------------------------------------

def test_queries_mirror_crtsh_own_search_sql():
    sql, args = build_query({"q": "%.adp.com", "exclude": "expired"}, 50_000)
    assert args == {"v": "%.adp.com"}
    assert "FROM certificate_and_identities cai" in sql
    assert "plainto_tsquery('certwatch', %(v)s::text) @@ identities(cai.CERTIFICATE)" in sql
    assert "cai.NAME_VALUE ILIKE ('%%' || %(v)s::text || '%%')" in sql
    assert "x509_notAfter(cai.CERTIFICATE) >= now() AT TIME ZONE 'UTC'" in sql
    assert "LIMIT 50000" in sql

    sql, args = build_query({"O": "Automatic Data Processing, Inc."}, 20_000)
    assert "cai.NAME_TYPE = '2.5.4.10'" in sql and "to_tsvector('certwatch', cai.NAME_VALUE)" in sql
    assert "x509_notAfter(cai.CERTIFICATE) >=" not in sql  # expired certificates included
    assert "LIMIT 20000" in sql


def test_unsupported_searches_are_left_to_the_web_api():
    assert build_query({"d": "123"}, 10) is None
    assert build_query({"q": "a.com", "O": "B"}, 10) is None
    assert build_query({"q": "a.com", "output": "json"}, 10) is None


def test_placeholders_become_the_same_parameter_as_crtsh_uses():
    psycopg = pytest.importorskip("psycopg")
    from psycopg._queries import PostgresQuery
    from psycopg.adapt import Transformer

    sql, args = build_query({"q": "%.adp.com"}, 10)
    q = PostgresQuery(Transformer())
    q.convert(sql, args)
    text = q.query.decode()
    assert "ILIKE ('%' || $1::text || '%')" in text and "%(v)s" not in text
    assert psycopg  # the driver is installed with the package


def test_records_become_the_web_apis_rows():
    out = to_rows(["ISSUER_NAME", "COMMON_NAME", "NAME_VALUE", "ID", "NOT_BEFORE", "NOT_AFTER", "RESULT_COUNT"],
                  [("C=US, O=DigiCert Inc", "adp.com", "adp.com\nwww.adp.com", 7, WHEN, LATER, 2)])
    assert out == [{"issuer_ca_id": None, "issuer_name": "C=US, O=DigiCert Inc", "common_name": "adp.com",
                    "name_value": "adp.com\nwww.adp.com", "id": 7, "not_before": "2026-01-02T03:04:05",
                    "not_after": "2027-01-02T03:04:05", "result_count": 2}]


# --- database first, web API second ---------------------------------------------------------

async def test_database_answers_and_is_cached(tmp_path):
    cache = Cache(tmp_path / "c.sqlite", 3600)
    http = Http(cache=cache)
    db = db_with(rows("adp.com", "mykplan.com"))
    with respx.mock(assert_all_called=False) as mock:
        web = mock.get(url__startswith="https://crt.sh/")
        got = await using(db, crtsh_json(http, {"q": "adp.com", "exclude": "expired"}, 30))
        again = await using(db, crtsh_json(http, {"q": "adp.com", "exclude": "expired"}, 30))
    assert isinstance(got, CtRows) and got.backend == "database" and got.cap == 50_000
    assert [r["name_value"] for r in got] == ["adp.com", "mykplan.com"]
    assert list(again) == list(got) and again.backend == "database"
    assert len(db.conns[0].calls) == 1  # the second search came from the cache
    assert not web.called
    assert db.summary() == "crt.sh: 1 query via the database"
    await http.aclose()
    cache.close()


@respx.mock
async def test_blocked_port_falls_back_to_the_web_api_and_stops_trying():
    respx.get(url__startswith="https://crt.sh/").respond(json=[{"common_name": "adp.com", "name_value": "adp.com"}])
    http = Http()
    db = CrtshDb()
    attempts = []

    async def refused():
        attempts.append(1)
        raise ConnectionRefusedError("connection refused")

    db._connect = refused
    a = await using(db, crtsh_json(http, {"q": "adp.com"}, 30))
    b = await using(db, crtsh_json(http, {"O": "ADP"}, 30))
    assert a.backend == "web" and b.backend == "web" and a[0]["common_name"] == "adp.com"
    assert len(attempts) == 1  # a refused connection turns the database off for the run
    assert "cannot connect to crt.sh:5432" in db.summary() and "web API used" in db.summary()
    await http.aclose()


@respx.mock
async def test_failed_query_falls_back_for_that_query_then_three_in_a_row_turn_the_database_off():
    respx.get(url__startswith="https://crt.sh/").respond(json=[{"common_name": "web.com", "name_value": "web.com"}])
    http = Http()
    db = db_with(TimeoutError(), rows("adp.com"), TimeoutError(), RuntimeError("x"), RuntimeError("y"))
    got = [await using(db, crtsh_json(http, {"q": f"{c}.com"}, 30)) for c in "abcdef"]
    assert [r.backend for r in got] == ["web", "database", "web", "web", "web", "web"]
    assert db.disabled_reason.startswith("3 failures in a row")
    assert db.queries == 1 and db.fallbacks == 4  # the sixth never reached the database
    assert len(db.conns) == 1  # a healthy connection is kept after a failed query
    assert db.conns[0].settings == [] and db.conns[0].transactions == 0  # statement pooling: no SET, no BEGIN
    assert db.failures[0] == "q='a.com': no answer within 30 s"
    assert "database failures: q='a.com': no answer within 30 s" in db.summary()
    await http.aclose()


@respx.mock
async def test_broken_connection_is_replaced_and_a_failed_reconnect_is_not_a_blocked_port():
    respx.get(url__startswith="https://crt.sh/").respond(json=[])
    http = Http()
    db = CrtshDb()
    conns = []

    async def connect():
        if len(conns) == 1:
            raise crtsh_db.ConnectFailed("1.2.3.4: OperationalError: too many connections")
        conn = FakeConn([rows("adp.com"), RuntimeError("server closed the connection"), rows("x.com")])
        conns.append(conn)
        return conn

    db._connect = connect
    a = await using(db, crtsh_json(http, {"q": "a.com"}, 30))
    conns[0].broken = True  # the next query finds the connection dead
    b = await using(db, crtsh_json(http, {"q": "b.com"}, 30))
    c = await using(db, crtsh_json(http, {"q": "c.com"}, 30))  # reconnect fails once
    assert (a.backend, b.backend, c.backend) == ("database", "web", "web")
    assert conns[0].closed  # the broken connection was dropped
    assert not db.disabled_reason  # it worked earlier: keep trying
    assert "reconnecting for q='c.com': 1.2.3.4: OperationalError: too many connections" in db.failures
    await http.aclose()


async def test_ipv4_addresses_are_tried_first(monkeypatch):
    import socket

    db = CrtshDb()

    async def fake_getaddrinfo(host, port, type=0):
        return [(socket.AF_INET6, 1, 6, "", ("2a0e:ac00::1", port, 0, 0)),
                (socket.AF_INET, 1, 6, "", ("91.199.212.73", port))]

    class Loop:
        getaddrinfo = staticmethod(fake_getaddrinfo)

    monkeypatch.setattr("asyncio.get_running_loop", lambda: Loop())
    assert await CrtshDb._addresses(db) == ["91.199.212.73", "2a0e:ac00::1"]


@respx.mock
async def test_missing_driver_falls_back_quietly(monkeypatch):
    respx.get(url__startswith="https://crt.sh/").respond(json=[])
    http = Http()
    db = CrtshDb()

    async def no_driver():
        raise ImportError("No module named 'psycopg'")

    db._connect = no_driver
    out = await using(db, crtsh_json(http, {"q": "adp.com"}, 30))
    assert out == [] and out.backend == "web"
    assert db.disabled_reason == "the psycopg driver is not installed"
    await http.aclose()


@respx.mock
async def test_without_a_database_client_only_the_web_api_is_used():
    route = respx.get(url__startswith="https://crt.sh/").respond(json=[{"common_name": "x.com"}])
    http = Http()
    out = await crtsh_json(http, {"q": "adp.com"}, 30)  # no client in context (--no-crtsh-db)
    assert out.backend == "web" and route.called
    await http.aclose()


# --- the row limit ---------------------------------------------------------------------------

def test_truncation_is_exact_for_the_database_and_estimated_for_the_web():
    full = CtRows([{"result_count": 2}] * 5, "database", 10)
    short = CtRows([{"result_count": 1}] * 9, "database", 10)
    assert full.truncated and not short.truncated
    assert CtRows([], "web").backend == "web"
    assert CtRows([{}] * 9995, "web").truncated and not CtRows([{}] * 500, "web").truncated


async def test_organization_search_reports_the_limit_of_the_route_used():
    from domainfinder.config import Settings
    from domainfinder.sources.crtsh import CrtshOrgSource
    from test_sources import ctx_for

    many = (COLS, [(1, "DigiCert", f"www.d{i}.com", "Automatic Data Processing, Inc.", i, WHEN, LATER, 1)
                   for i in range(1000)])
    db = db_with(many, many, limit=1000)
    http = Http()
    ctx = ctx_for(http=http)
    out = await using(db, CrtshOrgSource(Settings()).candidates(ctx))
    assert len(out) == 1000
    assert any("1,000-row limit of crt.sh's database" in n for n in ctx.notes)
    await http.aclose()


# --- the seed's organization name from a certificate -----------------------------------------

def _der_with_org(org: str) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                      x509.NameAttribute(NameOID.COMMON_NAME, "adp.com")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(WHEN).not_valid_after(LATER).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


async def test_seed_organization_comes_from_certificates_in_the_database():
    search = (COLS, [(1, "C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1", "www.adp.com",
                      "www.adp.com", 42, WHEN, LATER, 1)])
    db = db_with(search, (["certificate"], [(_der_with_org("Automatic Data Processing, Inc."),)]))
    http = Http()
    with respx.mock(assert_all_called=False) as mock:
        web = mock.get(url__startswith="https://crt.sh/")
        orgs = await using(db, seed_org_from_ct(http, "adp.com"))
    assert orgs == ["Automatic Data Processing, Inc."]
    assert not web.called
    assert db.conns[0].calls[1][1] == {"id": 42}
    await http.aclose()


# --- settings ---------------------------------------------------------------------------------

def test_settings_and_flag(monkeypatch):
    from domainfinder.cli import build_parser
    from domainfinder.config import Settings

    assert Settings().crtsh_db is True and Settings().crtsh_db_limit == 50_000
    monkeypatch.setenv("DOMAINFINDER_CRTSH_DB", "0")
    monkeypatch.setenv("DOMAINFINDER_CRTSH_DB_LIMIT", "200000")
    s = Settings.from_env(load_dotenv_file=False)
    assert s.crtsh_db is False and s.crtsh_db_limit == 200_000
    assert build_parser().parse_args(["adp.com", "--no-crtsh-db"]).no_crtsh_db is True


def test_module_constants():
    assert (crtsh_db.HOST, crtsh_db.PORT, crtsh_db.DBNAME, crtsh_db.USER) == ("crt.sh", 5432, "certwatch", "guest")
    assert json.dumps(to_rows(COLS, rows("adp.com")[1]))  # rows are cacheable as JSON


# --- 1.2.2: crt.sh's connection pooler ---------------------------------------------------------

@respx.mock
async def test_connection_closed_by_the_pooler_is_replaced_and_the_query_retried():
    respx.get(url__startswith="https://crt.sh/").respond(json=[])
    http = Http()
    db = CrtshDb()
    conns = []

    class IdleTimeout(Exception):
        pass

    IdleTimeout.__name__ = "ProtocolViolation"

    async def connect():
        answers = [rows("adp.com"), IdleTimeout("client_idle_timeout")] if not conns else [rows("adp.fr")]
        conns.append(FakeConn(answers))
        return conns[-1]

    db._connect = connect
    a = await using(db, crtsh_json(http, {"q": "adp.com"}, 30))
    b = await using(db, crtsh_json(http, {"O": "ADP France"}, 30))
    assert (a.backend, b.backend) == ("database", "database")
    assert b[0]["name_value"] == "adp.fr"
    assert len(conns) == 2 and conns[0].closed
    assert db.failures == [] and db.fallbacks == 0  # a lost connection is not the database failing
    assert not any(c.transactions or c.settings for c in conns)  # crt.sh's pooler allows neither
    await http.aclose()


async def test_idle_connection_is_replaced_before_the_next_query(monkeypatch):
    db = db_with(rows("a.com"), rows("b.com"), max_idle=30)
    clock = [1000.0]
    monkeypatch.setattr(crtsh_db.time, "monotonic", lambda: clock[0])
    await db.search({"q": "a.com"}, 30)
    clock[0] += 200  # minutes of verification later
    await db.search({"q": "b.com"}, 30)
    assert len(db.conns) == 2 and db.conns[0].closed and db.queries == 2


async def test_database_searches_get_their_own_time_limit_and_cancel_on_expiry(monkeypatch):
    import asyncio

    db = db_with(rows("a.com"), search_timeout=300)
    limits = []
    real_wait_for = asyncio.wait_for

    async def spy(aw, timeout):
        limits.append(timeout)
        return await real_wait_for(aw, timeout)

    monkeypatch.setattr(crtsh_db.asyncio, "wait_for", spy)
    await db.search({"O": "Automatic Data Processing, Inc."}, 120)
    assert limits[:2] == [300, 300]  # the database limit, not the web API's 120 s
    assert db.conns[0].settings == []  # never a SET on crt.sh's shared server connections

    # On expiry the query is cancelled and the healthy connection kept.
    monkeypatch.setattr(crtsh_db.asyncio, "wait_for", real_wait_for)
    cancelled = []

    async def never_answers(self, sql, args=None):
        await asyncio.sleep(10)

    async def cancel_safe(self):
        cancelled.append(True)

    monkeypatch.setattr(FakeCursor, "execute", never_answers)
    monkeypatch.setattr(FakeConn, "cancel_safe", cancel_safe, raising=False)
    slow = db_with(rows("b.com"))
    out = await slow._execute("SELECT 1", {}, 0.05, what="slow search")
    assert out is None and slow.failures == ["slow search: no answer within 0 s"]
    assert cancelled == [True] and slow._conn is not None and not slow._conn.closed


def test_database_timeout_setting(monkeypatch):
    from domainfinder.config import Settings

    assert Settings().crtsh_db_timeout == 300
    monkeypatch.setenv("DOMAINFINDER_CRTSH_DB_TIMEOUT", "600")
    assert Settings.from_env(load_dotenv_file=False).crtsh_db_timeout == 600
