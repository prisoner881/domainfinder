import json

import httpx
import respx

from domainfinder.config import Settings
from domainfinder.dns import DnsAnswer
from domainfinder.models import Fingerprint
from domainfinder.sources import ALL_SOURCES
from domainfinder.sources.base import SourceContext, make_candidates
from domainfinder.sources.cctld import CcTldSource, permutations
from domainfinder.sources.crtsh import CrtshOrgSource, collect_org_hits
from domainfinder.sources.edgar import guesses, subsidiary_names
from domainfinder.sources.reverse_ns import HackerTargetSource, combine, pivot_hosts
from helpers import ADP_NS, seed_fp

ORG = "Automatic Data Processing, Inc."


class FakeResolver:
    def __init__(self, registered):
        self.registered = set(registered)
        self.asked = []

    async def query(self, name, rtype):
        self.asked.append((name, rtype))
        if name in self.registered:
            return DnsAnswer("ok", ["ns1.example.net"])
        return DnsAnswer("nxdomain")


class FakeCollectors:
    def __init__(self, http=None, resolver=None):
        self.http = http
        self.resolver = resolver


def ctx_for(seed=None, http=None, resolver=None, **kw):
    return SourceContext(seed=seed or seed_fp(), settings=Settings(), collectors=FakeCollectors(http, resolver),
                         org_names=[ORG], brand_labels=["adp"], **kw)


def test_make_candidates_drops_seed_and_common_third_parties():
    cs = make_candidates(["www.adp.ca", "adp.com", "linkedin.com", "workmarket.com", "bad name"], "x", "adp.com")
    assert sorted(c.domain for c in cs) == ["adp.ca", "workmarket.com"]


def test_crtsh_org_hits_filter_fuzzy_matches_and_track_currency():
    rows = [
        {"common_name": "www.mastertax.com", "name_value": "Automatic Data Processing, Inc", "not_after": "2099-01-01T00:00:00"},
        {"common_name": "proxyvote.com", "name_value": "Automatic Data Processing, Inc.", "not_after": "2006-01-01T00:00:00"},
        {"common_name": "elsewhere.com", "name_value": "Automatic Data Systems Ltd", "not_after": "2099-01-01T00:00:00"},
    ]
    hits = {}
    collect_org_hits(rows, [ORG], hits)
    assert set(hits) == {"mastertax.com", "proxyvote.com"}
    assert hits["mastertax.com"].current and not hits["proxyvote.com"].current


@respx.mock
async def test_crtsh_org_source_queries_and_records_hits():
    from domainfinder.http import Http

    rows = [{"common_name": "workscape.com", "name_value": ORG, "not_after": "2099-01-01T00:00:00"},
            {"common_name": "adp.com", "name_value": ORG, "not_after": "2099-01-01T00:00:00"}]
    route = respx.get("https://crt.sh/").respond(text=json.dumps(rows))
    http = Http()
    ctx = ctx_for(http=http)
    out = await CrtshOrgSource(Settings()).candidates(ctx)
    assert [c.domain for c in out] == ["workscape.com"]
    assert ctx.ct_org_domains["workscape.com"].current
    assert route.calls[0].request.url.params["O"] == ORG
    await http.aclose()


def test_cctld_permutations_skip_the_seed():
    p = permutations(["adp"], "adp.com", ["com", "fr", "co.uk"])
    assert p == ["adp.fr", "adp.co.uk"]


async def test_cctld_source_keeps_registered_only():
    res = FakeResolver({"adp.ca", "adp.fr"})
    ctx = ctx_for(resolver=res)
    out = await CcTldSource(Settings()).candidates(ctx)
    assert [c.domain for c in out] == ["adp.ca", "adp.fr"]


def test_reverse_ns_pivots():
    hosts, how = pivot_hosts(sorted(ADP_NS), "adp.com")
    assert how == "intersection" and len(hosts) == 3
    hosts, how = pivot_hosts(["ns1.example-corp.com", "ns2.example-corp.com"], "example-corp.com")
    assert how == "union"
    assert pivot_hosts(["ns01.domaincontrol.com", "ns02.domaincontrol.com"], "x.com") == ([], "")
    assert combine([{"a", "b"}, {"b", "c"}], "intersection") == {"b"}
    assert combine([{"a"}, {"b"}], "union") == {"a", "b"}


@respx.mock
async def test_hackertarget_intersects_and_stops_on_quota():
    from domainfinder.http import Http

    answers = iter(["adp.com\nworkforcenow.com\nother.com", "workforcenow.com\nadp.com", "API count exceeded"])
    respx.get("https://api.hackertarget.com/findshareddns/").mock(
        side_effect=lambda req: httpx.Response(200, text=next(answers)))
    http = Http()
    ctx = ctx_for(http=http)
    out = await HackerTargetSource(Settings()).candidates(ctx)
    assert [c.domain for c in out] == ["workforcenow.com"]
    assert any("API count" in n for n in ctx.notes)
    await http.aclose()


def test_edgar_exhibit21_parsing():
    doc = """<table><tr><td>Name</td><td>Jurisdiction</td></tr>
    <tr><td>ADP Canada Co.</td><td>Canada</td></tr>
    <tr><td>Workforce Software, LLC</td><td>Delaware</td></tr>
    <tr><td>Automatic Data Processing Insurance Agency of the Pacific Northwest, Inc.</td><td>WA</td></tr>
    <tr><td>100%</td><td></td></tr></table>"""
    names = subsidiary_names(doc)
    assert "ADP Canada Co." in names and "Workforce Software, LLC" in names
    assert "100%" not in names and "Name" not in names
    assert guesses("Workforce Software, LLC") == ["workforcesoftware.com"]
    assert guesses("ADP Canada Co.") == ["adpcanada.com"]
    assert guesses("Automatic Data Processing Insurance Agency of the Pacific Northwest, Inc.") == []


def test_paid_sources_are_off_without_keys_and_on_with_them():
    names = {cls(Settings()).name: cls(Settings()).enabled() for cls in ALL_SOURCES}
    assert names["securitytrails"] is False and names["whoisxml"] is False and names["domaintools"] is False
    assert names["edgar"] is False and names["viewdns"] is False
    s = Settings(securitytrails_key="k", whoisxml_key="k", domaintools_user="u", domaintools_key="k")
    on = {cls(s).name: cls(s).enabled() for cls in ALL_SOURCES}
    assert on["securitytrails"] and on["whoisxml"] and on["domaintools"]


def test_settings_repr_never_shows_keys():
    s = Settings(securitytrails_key="SECRET123", whoisxml_key="SECRET456")
    assert "SECRET" not in repr(s)
