import json
import sqlite3
import zlib

import httpx
import respx

from domainfinder.cache import Cache
from domainfinder.config import Settings
from domainfinder.http import Http
from domainfinder.sources.base import SourceContext
from domainfinder.sources.whoisxml import ENDPOINT, WhoisXmlSource, org_variants
from helpers import ZDP_NS, cand, fp, rdap, seed_fp

ORG = "Zyntara Data Processing, Inc."
KEY = "at_SECRETKEY123"


class Collectors:
    def __init__(self, http):
        self.http = http
        self.resolver = None


def ctx_for(http, orgs=(ORG,)):
    return SourceContext(seed=seed_fp(), settings=Settings(), collectors=Collectors(http),
                         org_names=list(orgs), brand_labels=["zdp"])


def fake_api(answers, calls):
    """answers: {(searchType, mode, term): response dict}; default count 0."""
    def handler(request):
        body = json.loads(request.content)
        calls.append(body)
        term = body["advancedSearchTerms"][0]["term"]
        resp = answers.get((body["searchType"], body["mode"], term))
        if resp is None:
            resp = {"domainsCount": 0, "nextPageSearchAfter": None}
        if isinstance(resp, httpx.Response):
            return resp
        return httpx.Response(200, json=resp)
    return handler


def test_org_variants():
    assert org_variants("Zyntara Data Processing, Inc.") == [
        "Zyntara Data Processing, Inc.", "Zyntara Data Processing, Inc",
        "Zyntara Data Processing Inc.", "Zyntara Data Processing Inc"]
    assert org_variants("Elmridge University") == ["Elmridge University"]


@respx.mock
async def test_preview_then_purchase_and_evidence(tmp_path):
    calls = []
    answers = {
        ("current", "preview", ORG): {"domainsCount": 2, "nextPageSearchAfter": None},
        ("current", "purchase", ORG): {"domainsCount": 2, "nextPageSearchAfter": None,
                                       "domainsList": ["timeguard.com", "zdp.com"]},
        ("historic", "preview", ORG): {"domainsCount": 2, "nextPageSearchAfter": None},
        ("historic", "purchase", ORG): {"domainsCount": 2, "nextPageSearchAfter": None,
                                        "domainsList": [{"domainName": "timeguard.com"}, {"domainName": "votenow.com"}]},
    }
    respx.post(ENDPOINT).mock(side_effect=fake_api(answers, calls))
    http = Http(cache=Cache(tmp_path / "c.sqlite", 3600))
    ctx = ctx_for(http)
    out = {c.domain: c for c in await WhoisXmlSource(Settings(whoisxml_key=KEY)).candidates(ctx)}
    assert set(out) == {"timeguard.com", "votenow.com"}  # the seed itself is dropped
    assert out["timeguard.com"].hints[0].kind == "whois_org"  # current wins over historic
    assert out["votenow.com"].hints[0].kind == "whois_org_historic"
    purchases = [c for c in calls if c["mode"] == "purchase"]
    assert len(purchases) == 2
    assert all(c["advancedSearchTerms"][0]["exactMatch"] for c in calls)
    assert all(c["apiKey"] == KEY for c in calls)
    assert any("2 credit(s) spent" in n for n in ctx.notes)

    # Same searches again: everything comes from the cache, nothing is spent.
    calls.clear()
    ctx2 = ctx_for(http)
    await WhoisXmlSource(Settings(whoisxml_key=KEY)).candidates(ctx2)
    assert calls == [] and any("0 credit(s) spent" in n for n in ctx2.notes)
    await http.aclose()
    # The key never reaches the cache.
    db = sqlite3.connect(tmp_path / "c.sqlite")
    rows = [(k, zlib.decompress(v).decode() if isinstance(v, bytes) else v) for k, v in db.execute("SELECT k, v FROM kv")]
    assert rows and not any(KEY in (k + v) for k, v in rows)


@respx.mock
async def test_zero_count_spends_no_credit():
    calls = []
    respx.post(ENDPOINT).mock(side_effect=fake_api({}, calls))
    http = Http()
    out = await WhoisXmlSource(Settings(whoisxml_key=KEY, whoisxml_search="current")).candidates(ctx_for(http))
    assert out == [] and calls and all(c["mode"] == "preview" for c in calls)
    await http.aclose()


@respx.mock
async def test_error_stops_the_source_and_never_shows_the_key():
    calls = []
    err = httpx.Response(403, json={"code": 403, "messages": f"Access restricted for key {KEY}"})
    answers = {("current", "preview", ORG): err}
    respx.post(ENDPOINT).mock(side_effect=fake_api(answers, calls))
    http = Http(retries=0)
    ctx = ctx_for(http)
    out = await WhoisXmlSource(Settings(whoisxml_key=KEY)).candidates(ctx)
    assert out == [] and len(calls) == 1  # stopped after the first failure
    assert any("HTTP 403" in n for n in ctx.notes)
    assert not any(KEY in n for n in ctx.notes)
    await http.aclose()


@respx.mock
async def test_more_than_one_page_is_reported_not_bought():
    calls = []
    answers = {
        ("current", "preview", ORG): {"domainsCount": 15000, "nextPageSearchAfter": None},
        ("current", "purchase", ORG): {"domainsCount": 15000, "nextPageSearchAfter": "1673000000",
                                       "domainsList": ["a1.com"]},
    }
    respx.post(ENDPOINT).mock(side_effect=fake_api(answers, calls))
    http = Http()
    ctx = ctx_for(http)
    await WhoisXmlSource(Settings(whoisxml_key=KEY, whoisxml_search="current")).candidates(ctx)
    assert len([c for c in calls if c["mode"] == "purchase"]) == 1
    assert any("truncated" in n for n in ctx.notes)
    await http.aclose()


def test_exact_current_registrant_match_puts_a_held_domain_on_the_main_list():
    """timeguard.com: MarkMonitor holding page, OH, no other link — review before, owned with WhoisXML."""
    from domainfinder.models import Classification as C
    from domainfinder.models import Evidence, Strength
    from domainfinder.verify import Scorer, SeedProfile

    s = Scorer(SeedProfile.build(seed_fp(), [ORG], ["zdp"]))
    held = dict(a=["15.197.70.98"], ns=["ns1.markmonitor.com"], rdap=rdap())
    before = s.score(fp("timeguard.com", **held), cand("timeguard.com"), set())
    assert before.classification is C.REVIEW
    c = cand("timeguard.com", "whoisxml")
    c.hints = [Evidence("whois_org", Strength.STRONG, 60, "WhoisXML: registrant organization is 'X' (current WHOIS)")]
    after = s.score(fp("timeguard.com", **held), c, set())
    assert after.classification is C.OWNED
    # Historic-only: weak, stays in review.
    c2 = cand("timeguard.com", "whoisxml")
    c2.hints = [Evidence("whois_org_historic", Strength.WEAK, 15, "historic")]
    assert s.score(fp("timeguard.com", **held), c2, set()).classification is C.REVIEW
