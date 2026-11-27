"""1.5.0: the cache file in the run directory, compressed, pruned, shared safely
between runs; error answers never cached; expired answers used when a fresh
lookup fails; DNS-over-HTTPS answers not cached forever."""

import json
import sqlite3
import time

import httpx
import respx

from domainfinder.cache import CACHE_FILE, Cache
from domainfinder.config import Settings
from domainfinder.http import Http, json_answer
from domainfinder.pipeline import cache_note

DAY = 86400


def age(path, key, days):
    """Make a cache entry `days` old."""
    db = sqlite3.connect(path)
    db.execute("UPDATE kv SET t = ? WHERE k = ?", (time.time() - days * DAY, key))
    db.commit()
    db.close()


# --- the cache file ---------------------------------------------------------------------------

def test_default_location_is_the_run_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("DOMAINFINDER_CACHE_DIR", raising=False)
    s = Settings.from_env(load_dotenv_file=False)
    assert s.cache_dir == tmp_path and CACHE_FILE == "domainfinder-cache.sqlite"


def test_values_are_compressed_and_old_plain_rows_still_read(tmp_path):
    p = tmp_path / CACHE_FILE
    c = Cache(p, 3600)
    page = {"text": "<html>" + "x" * 50_000 + "</html>"}
    c.set("PAGE a", page)
    raw = sqlite3.connect(p).execute("SELECT v FROM kv WHERE k = 'PAGE a'").fetchone()[0]
    assert isinstance(raw, bytes) and len(raw) < 2_000 and c.get("PAGE a") == page
    db = sqlite3.connect(p)  # a row as 1.4.x wrote it
    db.execute("INSERT INTO kv VALUES ('old', ?, ?)", (time.time(), json.dumps([1, 2])))
    db.commit()
    assert c.get("old") == [1, 2]


def test_expired_entries_stay_available_as_stale_until_max_stale(tmp_path):
    p = tmp_path / CACHE_FILE
    c = Cache(p, 3600, max_stale=30 * DAY)
    c.set("k", "v")
    age(p, "k", 5)
    assert c.get("k", 3 * DAY) is None
    value, seconds = c.get_stale("k")
    assert value == "v" and 4.9 * DAY < seconds < 5.1 * DAY
    age(p, "k", 31)
    assert c.get_stale("k") is None


def test_entries_past_max_stale_are_pruned_on_open(tmp_path):
    p = tmp_path / CACHE_FILE
    c = Cache(p, 3600, max_stale=30 * DAY)
    c.set("old", 1)
    c.set("new", 2)
    c.close()
    age(p, "old", 40)
    c2 = Cache(p, 3600, max_stale=30 * DAY)
    assert c2.stats["pruned"] == 1 and c2.get_stale("old") is None and c2.get("new") == 2


def test_two_runs_can_write_the_same_file(tmp_path):
    p = tmp_path / CACHE_FILE
    a, b = Cache(p, 3600), Cache(p, 3600)
    for i in range(50):
        a.set(f"a{i}", i)
        b.set(f"b{i}", i)
    assert a.get("b49") == 49 and b.get("a49") == 49
    assert a.stats["write_skipped"] == b.stats["write_skipped"] == 0
    assert sqlite3.connect(p).execute("PRAGMA journal_mode").fetchone()[0] == "wal"


# --- error answers and the stale fallback -----------------------------------------------------

@respx.mock
async def test_an_error_answer_with_http_200_is_not_cached(tmp_path):
    route = respx.get("https://api.example/q").respond(200, text="API count exceeded - Increase Quota")
    http = Http(cache=Cache(tmp_path / CACHE_FILE, 3600))
    for _ in range(2):
        r = await http.get("https://api.example/q", valid=lambda resp: "quota" not in resp.text.lower())
        assert r.ok and not r.cached
    assert route.call_count == 2  # asked again: the quota message was never replayed from the cache
    await http.aclose()


@respx.mock
async def test_a_failed_lookup_falls_back_to_the_expired_answer(tmp_path):
    p = tmp_path / CACHE_FILE
    http = Http(cache=Cache(p, 3600), retries=1)
    respx.get("https://crt.example/?q=x").respond(200, json=[{"name_value": "a.example"}])
    first = await http.get("https://crt.example/", params={"q": "x"}, ttl=3 * DAY, valid=json_answer)
    assert first.ok and not first.stale_age
    age(p, "GET https://crt.example/?q=x", 5)
    respx.get("https://crt.example/?q=x").respond(502)
    r = await http.get("https://crt.example/", params={"q": "x"}, ttl=3 * DAY, valid=json_answer)
    assert r.ok and r.cached and r.stale_age > 4 * DAY and r.json() == [{"name_value": "a.example"}]
    assert http.stale_hosts == {"crt.example": 1}
    assert "older cached answers used: crt.example 1" in cache_note(http)
    await http.aclose()


@respx.mock
async def test_no_stale_answer_means_the_failure_is_returned(tmp_path):
    http = Http(cache=Cache(tmp_path / CACHE_FILE, 3600), retries=1)
    respx.get("https://crt.example/none").respond(503)
    r = await http.get("https://crt.example/none")
    assert r.status == 503 and not http.stale_hosts
    await http.aclose()


@respx.mock
async def test_post_json_error_payload_is_not_cached_and_stale_is_used(tmp_path):
    p = tmp_path / CACHE_FILE
    http = Http(cache=Cache(p, 3600), retries=1)
    valid = lambda resp: json_answer(resp, "domainsCount")  # noqa: E731
    respx.post("https://api.example/rw").mock(side_effect=[
        httpx.Response(200, json={"domainsCount": 3}),
        httpx.Response(200, json={"ErrorMessage": "Insufficient credits"}),
    ])
    ok = await http.post_json("https://api.example/rw", {"q": 1, "apiKey": "s"}, cache_payload={"q": 1}, valid=valid)
    assert ok.json() == {"domainsCount": 3}
    key = "POST https://api.example/rw " + json.dumps({"q": 1})
    age(p, key, 10)
    r = await http.post_json("https://api.example/rw", {"q": 1, "apiKey": "s"}, cache_payload={"q": 1}, valid=valid,
                             ttl=7 * DAY)
    assert r.json() == {"domainsCount": 3} and r.stale_age > 9 * DAY  # the error answer was not stored
    await http.aclose()


@respx.mock
async def test_dns_over_https_answers_are_not_cached_by_the_http_layer(tmp_path):
    from domainfinder.dns import Resolver

    p = tmp_path / CACHE_FILE
    http = Http(cache=Cache(p, 3600))
    respx.get(url__startswith="https://dns.google/resolve").respond(
        json={"Status": 0, "Answer": [{"type": 1, "data": "192.0.2.1"}]})
    respx.get(url__startswith="https://cloudflare-dns.com/").respond(
        json={"Status": 0, "Answer": [{"type": 1, "data": "192.0.2.1"}]})
    res = Resolver(http, cache=http.cache, mode="doh")
    ans = await res.query("x.example", "A")
    assert ans.records == ["192.0.2.1"]
    keys = [k for (k,) in sqlite3.connect(p).execute("SELECT k FROM kv")]
    assert not any(k.startswith("GET https://dns.google") or k.startswith("GET https://cloudflare-dns") for k in keys)
    await http.aclose()


async def test_whois_uses_an_expired_answer_when_port_43_fails_without_refreshing_it(tmp_path, monkeypatch):
    import asyncio

    from domainfinder.collectors import whois

    p = tmp_path / CACHE_FILE
    cache = Cache(p, 3600)
    text = open(__file__.replace("test_v150.py", "fixtures/whois_educause_example.txt")).read()
    key = f"whois {whois.WHOIS_SERVERS['edu']} exampleu.edu"
    cache.set(key, text)
    age(p, key, 10)

    async def refused(*a, **k):
        raise ConnectionRefusedError

    monkeypatch.setattr(asyncio, "open_connection", refused)
    info = await whois.whois_lookup("exampleu.edu", cache, timeout=1)
    assert info is not None and info.registrar == "EDUCAUSE"
    t = sqlite3.connect(p).execute("SELECT t FROM kv WHERE k = ?", (key,)).fetchone()[0]
    assert time.time() - t > 9 * DAY  # still marked old: not re-stored as if fresh
