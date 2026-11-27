"""1.5.3: RDAP answers are cached only when they are real RDAP objects (a stub
answered with HTTP 200 by a rate-limited registrar is a failed lookup); the
review note names the evidence it is about."""

import sqlite3

import httpx
import respx
from helpers import cand, fp, seed_fp, web

from domainfinder.cache import CACHE_FILE, Cache
from domainfinder.collectors.rdap import RdapClient
from domainfinder.http import Http
from domainfinder.verify import Scorer, SeedProfile

STUB = {"rdapConformance": ["rdap_level_0"], "notices": [{"title": "Rate limited"}]}
FULL = {"objectClassName": "domain", "ldhName": "X-ZDP.COM", "entities": [
    {"roles": ["registrant"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                                         ["email", {}, "text", "dns@zdp.com"]]]}]}


@respx.mock
async def test_a_registrar_stub_with_http_200_is_not_cached_and_counts_as_failed(tmp_path):
    respx.get("https://data.iana.org/rdap/dns.json").respond(
        json={"services": [[["com"], ["https://rdap.verisign.com/com/v1/"]]]})
    respx.get("https://rdap.verisign.com/com/v1/domain/x-zdp.com").respond(json={
        "objectClassName": "domain", "ldhName": "X-ZDP.COM",
        "links": [{"rel": "related", "href": "https://rdap.registrar.example/domain/X-ZDP.COM"}]})
    respx.get("https://rdap.registrar.example/domain/X-ZDP.COM").mock(
        side_effect=[httpx.Response(200, json=STUB), httpx.Response(200, json=FULL)])
    p = tmp_path / CACHE_FILE
    http = Http(cache=Cache(p, 3600), retries=1)
    c = RdapClient(http)
    info = await c.domain("x-zdp.com")
    assert info.contacts == [] and c.registrar_failures == {"rdap.registrar.example": 1}
    keys = [k for (k,) in sqlite3.connect(p).execute("SELECT k FROM kv")]
    assert not any("rdap.registrar.example" in k for k in keys)  # the stub was not stored
    assert await c.retry_failed(spacing=0) == 1 and info.contacts[0]["email"] == "dns@zdp.com"
    await http.aclose()


def test_review_note_names_website_evidence_rather_than_registration():
    seed = seed_fp()
    s = Scorer(SeedProfile.build(seed, ["Zyntara Data Processing, Inc."], ["zdp"]), 70, 40)
    site = fp("zdpcloud.com", web=web("https://zdpcloud.com/", csp_domains=["zdp.com", "zdpsoftware.com"]))
    r = s.score(site, cand("zdpcloud.com"), {"zdpsoftware.com"})
    notes = [e for e in r.evidence if e.kind in ("no_control", "registration_only")]
    assert [e.kind for e in notes] == ["no_control"]
    assert "Content-Security-Policy" in notes[0].detail and "registration" not in notes[0].detail


@respx.mock
async def test_a_stub_cached_by_an_older_version_is_ignored(tmp_path):
    import json as _json

    from domainfinder.collectors.rdap import registrar_answer

    p = tmp_path / CACHE_FILE
    cache = Cache(p, 3600)
    cache.set("GET https://rdap.registrar.example/domain/X-ZDP.COM",
              {"status": 200, "url": "https://rdap.registrar.example/domain/X-ZDP.COM",
               "text": _json.dumps(STUB), "headers": {}})
    route = respx.get("https://rdap.registrar.example/domain/X-ZDP.COM").respond(json=FULL)
    http = Http(cache=cache)
    r = await http.get("https://rdap.registrar.example/domain/X-ZDP.COM", valid=registrar_answer)
    assert route.call_count == 1 and r.json() == FULL
    await http.aclose()
