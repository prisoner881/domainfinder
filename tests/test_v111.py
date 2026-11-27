"""1.1.1: shared-certificate guard on public keys and the certificate hop; Wikidata 403; EDGAR Exhibit 21 lookup."""

import httpx
import respx
from helpers import ZDP_NS, cand, fp, rdap
from test_certs import cert, link, scorer

from domainfinder import pipeline
from domainfinder.config import Settings
from domainfinder.models import CertInfo, Result
from domainfinder.models import Classification as C
from domainfinder.sources.edgar import EX21_NAME, EdgarSource, ex21_from_index
from domainfinder.sources.wikidata import ENDPOINT, WikidataSource, refusal_reason, user_agent
from domainfinder.verify import score_all

VENDOR_SANS = ["zdpunemploymentclaims.com"] + [f"vendor{i}.com" for i in range(8)]


def infra_owned(domain, c):
    """A domain proven ours on infrastructure, presenting certificate `c`."""
    return fp(domain, ns=sorted(ZDP_NS), mail_tenants=["proofpoint:0099aa01"], rdap=rdap(), cert=c)


# --- public keys of shared certificates ---------------------------------------------------

def test_key_of_a_vendor_certificate_on_an_owned_domain_links_nothing():
    # zdpunemploymentclaims.com is ZDP's but hosted by a vendor whose certificate
    # names the vendor's other customers; those customers share its key.
    items = [
        (infra_owned("zdpunemploymentclaims.com", cert(*VENDOR_SANS, key="vendorkey")), cand("zdpunemploymentclaims.com")),
        (fp("vendor3.com", cert=cert(*VENDOR_SANS, key="vendorkey", sha="c2")), cand("vendor3.com")),
        (fp("othercustomer.com", cert=cert("othercustomer.com", key="vendorkey", sha="c3")), cand("othercustomer.com")),
    ]
    res = {r.domain: r for r in score_all(scorer(), items)}
    assert res["zdpunemploymentclaims.com"].classification is C.OWNED
    assert link(res["vendor3.com"]) == "" and res["vendor3.com"].classification is C.REJECTED
    assert link(res["othercustomer.com"]) == "" and res["othercustomer.com"].classification is C.REJECTED


def test_key_reused_by_a_host_across_many_customers_links_nothing():
    items = [(infra_owned("taskhive.com", cert("taskhive.com", key="hostkey")), cand("taskhive.com"))]
    items += [(fp(f"cust{i}.com", cert=cert(f"cust{i}.com", key="hostkey", sha=f"s{i}")), cand(f"cust{i}.com"))
              for i in range(5)]
    res = {r.domain: r for r in score_all(scorer(), items)}
    assert all(link(res[f"cust{i}.com"]) == "" for i in range(5))


def test_key_shared_by_a_few_of_our_own_domains_still_links():
    items = [(infra_owned("taskhive.com", cert("taskhive.com", key="wmkey")), cand("taskhive.com")),
             (fp("th.solutions", rdap=rdap(), cert=cert("th.solutions", key="wmkey", sha="c2")), cand("th.solutions"))]
    res = {r.domain: r for r in score_all(scorer(), items)}
    assert "same public key as taskhive.com's" in link(res["th.solutions"])


# --- certificate hop -------------------------------------------------------------------------

def owned(f):
    return Result(f.domain, 90, C.OWNED, "", [], {}, f)


def test_cert_san_hop_skips_a_vendor_certificate_naming_none_of_ours():
    vendor = fp("zdpunemploymentclaims.com", cert=CertInfo(fetched=True, sans=VENDOR_SANS, has_scts=True))
    corporate = fp("zdpces.com", cert=CertInfo(fetched=True, has_scts=True, sans=[
        "zdpces.com", "zdp.com", "enrollhub.com", "new1.com", "new2.com", "new3.com"]))
    small = fp("frontkit.io", cert=CertInfo(fetched=True, sans=["frontkit.io", "deals.new"], has_scts=True))
    out = {c.domain for c in pipeline.hop_candidates([owned(vendor), owned(corporate), owned(small)], set(), "zdp.com")}
    assert out == {"enrollhub.com", "new1.com", "new2.com", "new3.com", "deals.new"}


# --- Wikidata --------------------------------------------------------------------------------

def test_wikidata_user_agent_carries_contact_only_when_set():
    assert "contact" not in user_agent("")
    assert user_agent("Research Team team@example.org").endswith("; contact: Research Team team@example.org)")


def test_refusal_reason_strips_the_error_page():
    page = "<html><head><title>T</title><style>p{}</style></head><body><p>Please set a user-agent</p></body></html>"
    assert refusal_reason(page) == "Please set a user-agent"


@respx.mock
async def test_wikidata_403_explains_itself_and_is_not_cached():
    from domainfinder.http import Http
    from test_sources import ctx_for

    route = respx.get(ENDPOINT).respond(403, text="<p>Please respect our robot policy</p>")
    http = Http()
    ctx = ctx_for(http=http)
    assert await WikidataSource(Settings()).candidates(ctx) == []
    note = next(n for n in ctx.notes if n.startswith("wikidata"))
    assert "HTTP 403" in note and "robot policy" in note and "DOMAINFINDER_CONTACT" in note
    await WikidataSource(Settings()).candidates(ctx)
    assert route.call_count == 2  # refusals are retried on the next run, never cached
    sent = route.calls[-1].request.headers["User-Agent"]
    assert "contact" not in sent
    await WikidataSource(Settings(contact="Research Team team@example.org")).candidates(ctx)
    assert "team@example.org" in route.calls[-1].request.headers["User-Agent"]
    await http.aclose()


# --- EDGAR -----------------------------------------------------------------------------------

def test_exhibit21_file_names():
    for name in ("ex21.htm", "ex-21.htm", "ex211.htm", "zdp-20260630xexhibit21.htm", "exhibit21_1.htm"):
        assert EX21_NAME.search(name), name
    for name in ("ex-2.1.htm", "ex10-21.htm", "R21.htm", "zdp-20260630.htm"):
        assert not EX21_NAME.search(name), name


def test_exhibit21_from_filing_index_by_document_type():
    page = """<table><tr><th>Seq</th><th>Description</th><th>Document</th><th>Type</th></tr>
    <tr><td>1</td><td>10-K</td><td><a href="/Archives/edgar/data/99999/x/zdp-20260630.htm">zdp-20260630.htm</a></td><td>10-K</td></tr>
    <tr><td>5</td><td>Subsidiaries</td><td><a href="/Archives/edgar/data/99999/x/subsidiaries.htm">subsidiaries.htm</a></td><td>EX-21.1</td></tr>
    </table>"""
    assert ex21_from_index(page) == ["subsidiaries.htm"]


@respx.mock
async def test_edgar_finds_an_oddly_named_exhibit21_through_the_filing_index():
    from domainfinder.dns import DnsAnswer
    from domainfinder.http import Http
    from test_sources import ctx_for

    class Res:
        async def query(self, name, rtype):
            return DnsAnswer("ok", ["ns1.example."]) if name == "shiftlanesoftware.com" else DnsAnswer("nxdomain")

    base = "https://www.sec.gov/Archives/edgar/data/99999/000009999926000030/"
    respx.get("https://www.sec.gov/files/company_tickers.json").respond(
        json={"0": {"cik_str": 99999, "title": "ZYNTARA DATA PROCESSING INC"}})
    respx.get("https://data.sec.gov/submissions/CIK0000099999.json").respond(
        json={"filings": {"recent": {"form": ["8-K", "10-K"], "accessionNumber": ["x", "0000099999-26-000030"]}}})
    respx.get(base + "index.json").respond(json={"directory": {"item": [{"name": "zdp-20260630.htm"},
                                                                         {"name": "subsidiaries.htm"}]}})
    respx.get(base + "0000099999-26-000030-index.htm").respond(
        text='<tr><td><a href="/x/subsidiaries.htm">subsidiaries.htm</a></td><td>EX-21</td></tr>')
    respx.get(base + "subsidiaries.htm").respond(
        text="<table><tr><td>Shiftlane Software, LLC</td><td>Delaware</td></tr>"
             "<tr><td>Nonexistent Holdings</td><td>Delaware</td></tr></table>")
    http = Http()
    ctx = ctx_for(http=http, resolver=Res())
    out = await EdgarSource(Settings(sec_user_agent="Example Corp research@example.org")).candidates(ctx)
    assert [c.domain for c in out] == ["shiftlanesoftware.com"]
    await http.aclose()


# --- held domain named exactly after the organization ----------------------------------------

def test_held_domain_named_after_the_organization_counts_like_the_brand():
    from domainfinder.verify import Scorer, SeedProfile
    from helpers import seed_fp

    s = Scorer(SeedProfile.build(seed_fp(), ["Zyntara Data Processing, Inc."], ["zdp"]))
    held = dict(rdap=rdap(), ns=["ns1.markmonitor.com", "ns2.markmonitor.com"])
    r = s.score(fp("zyntaradataprocessing.com", **held), cand("zyntaradataprocessing.com"), set())
    assert "held_brand" in {e.kind for e in r.evidence}
    assert any("the seed organization's name" in e.detail for e in r.evidence)
    assert r.classification is C.REVIEW  # 1.3.0: registration only, no control evidence
    # a name that merely contains part of the organization's name gets no such credit
    r = s.score(fp("dataprocessingsolutions.com", **held), cand("dataprocessingsolutions.com"), set())
    assert "held_brand" not in {e.kind for e in r.evidence} and r.classification is not C.OWNED


def test_org_named_domain_evidence_reads_naturally():
    from domainfinder.verify import Scorer, SeedProfile
    from helpers import seed_fp

    s = Scorer(SeedProfile.build(seed_fp(), ["Zyntara Data Processing, Inc."], ["zdp"]))
    r = s.score(fp("zyntaradataprocessing.com", rdap=rdap()), cand("zyntaradataprocessing.com"), set())
    details = [e.detail for e in r.evidence if e.kind == "brand_label"]
    assert details == ["named after the organization"]
