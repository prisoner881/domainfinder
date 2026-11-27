"""1.1.0: CT co-certificates, DMARC reporting, certificate hop, acquisition names, Wikidata."""

import json

import httpx
import respx
from helpers import ZDP_NS, cand, fp, rdap, seed_fp, web

from domainfinder import pipeline
from domainfinder.collectors.dnsinfo import collect_dmarc, parse_dmarc_addresses
from domainfinder.config import Settings
from domainfinder.dns import DnsAnswer
from domainfinder.models import CertInfo, Classification as C, Evidence, Result, Strength, WebInfo
from domainfinder.sources.wikidata import ENDPOINT, WikidataSource, build_query, website_variants
from domainfinder.verify import Scorer, SeedProfile

ORG = "Zyntara Data Processing, Inc."


def kinds(r):
    return {e.kind for e in r.evidence}


def scorer(**kw):
    return Scorer(SeedProfile.build(seed_fp(), [ORG], ["zdp"]), **kw)


# --- #1 CT co-certificates -------------------------------------------------------------

def test_ct_cocertificate_is_strong_evidence():
    s = scorer(ct_cocerts={"zdpworld.de": [["zdp.com", "zdpworld.de"]]})
    r = s.score(fp("zdpworld.de"), cand("zdpworld.de"), set())
    assert "ct_cocert" in kinds(r)


def test_ct_cocertificate_shared_by_unrelated_customers_is_ignored():
    cdn = ["zdp.com", "smallshop.com"] + [f"customer{i}.com" for i in range(10)]
    s = scorer(ct_cocerts={"smallshop.com": [cdn]})
    assert "ct_cocert" not in kinds(s.score(fp("smallshop.com"), cand("smallshop.com"), set()))


def test_ct_cocertificate_not_added_twice_when_the_live_certificate_links():
    live = CertInfo(fetched=True, sans=["zdpworld.de", "zdp.com"], sha256="x", spki_sha256="k", has_scts=True)
    s = scorer(ct_cocerts={"zdpworld.de": [["zdp.com", "zdpworld.de"]]})
    r = s.score(fp("zdpworld.de", cert=live), cand("zdpworld.de"), set())
    assert "cert_link" in kinds(r) and "ct_cocert" not in kinds(r)


@respx.mock
async def test_crtsh_san_records_current_cocertificates_only():
    from domainfinder.http import Http
    from domainfinder.sources.crtsh import CrtshDomainSource
    from test_sources import ctx_for

    rows = [{"name_value": "zdp.com\nwww.zdpworld.de", "not_after": "2099-01-01T00:00:00"},
            {"name_value": "zdp.com\nold-brand.com", "not_after": "2001-01-01T00:00:00"}]
    respx.get("https://crt.sh/").respond(text=json.dumps(rows))
    http = Http()
    ctx = ctx_for(http=http)
    out = await CrtshDomainSource(Settings()).candidates(ctx)
    assert {c.domain for c in out} == {"zdpworld.de", "old-brand.com"}  # both are candidates...
    assert ctx.ct_cocerts == {"zdpworld.de": [["zdp.com", "zdpworld.de"]]}  # ...but only the current cert is evidence
    await http.aclose()


# --- #2 DMARC ----------------------------------------------------------------------------

def test_parse_dmarc_addresses():
    rec = "v=DMARC1; p=reject; rua=mailto:dmarc@ZDP.com!10m, mailto:x9k2m4q7@rua.agari.com; ruf=mailto:f@zdp.com"
    assert parse_dmarc_addresses(rec) == ["dmarc@zdp.com", "x9k2m4q7@rua.agari.com", "f@zdp.com"]
    assert parse_dmarc_addresses("v=DMARC1; p=none") == []


class Res:
    def __init__(self, txt):
        self.txt = txt

    async def query(self, name, rtype):
        recs = self.txt.get(name)
        return DnsAnswer("ok", recs) if recs else DnsAnswer("nxdomain")


async def test_collect_dmarc_checks_authorization_and_wildcards():
    f = fp("zdpworld.de")
    await collect_dmarc(f, Res({
        "_dmarc.zdpworld.de": ["v=DMARC1; p=reject; rua=mailto:dmarc@zdp.com,mailto:r@reports.vendor.net"],
        "zdpworld.de._report._dmarc.zdp.com": ["v=DMARC1"],
    }))
    assert f.dmarc_auth == {"zdp.com": "specific", "reports.vendor.net": "none"}
    g = fp("lookalike.com")
    await collect_dmarc(g, Res({
        "_dmarc.lookalike.com": ["v=DMARC1; rua=mailto:dmarc@zdp.com"],
        "lookalike.com._report._dmarc.zdp.com": ["v=DMARC1"],
        "domainfinder-wildcard-probe._report._dmarc.zdp.com": ["v=DMARC1"],  # zdp.com authorizes everyone
    }))
    assert g.dmarc_auth == {"zdp.com": "wildcard"}


def test_dmarc_evidence_levels():
    s = scorer()
    authorized = fp("zdpworld.de", dmarc_addresses=["dmarc@zdp.com"], dmarc_auth={"zdp.com": "specific"})
    assert "dmarc_auth" in kinds(s.score(authorized, cand("zdpworld.de"), set()))
    # Anyone can write rua=mailto:dmarc@zdp.com into their own record: weak only.
    forged = fp("zdpp-login.com", dmarc_addresses=["dmarc@zdp.com"], dmarc_auth={"zdp.com": "none"})
    r = s.score(forged, cand("zdpp-login.com"), set())
    assert "dmarc_to_seed" in kinds(r) and r.classification is C.REJECTED
    wildcard = fp("other.com", dmarc_addresses=["dmarc@zdp.com"], dmarc_auth={"zdp.com": "wildcard"})
    assert "dmarc_to_seed" in kinds(s.score(wildcard, cand("other.com"), set()))


def test_dmarc_vendor_address_needs_a_customer_specific_mailbox():
    seed = seed_fp()
    seed.dmarc_addresses = ["x9k2m4q7@rua.agari.com", "rua@dmarc.brevo.com"]
    s = Scorer(SeedProfile.build(seed, [ORG], ["zdp"]))
    same_tenant = fp("zdpx.com", dmarc_addresses=["x9k2m4q7@rua.agari.com"])
    assert "dmarc_vendor" in kinds(s.score(same_tenant, cand("zdpx.com"), set()))
    shared_default = fp("unrelated.com", dmarc_addresses=["rua@dmarc.brevo.com"])
    assert not {"dmarc_vendor", "dmarc_auth"} & kinds(s.score(shared_default, cand("unrelated.com"), set()))


# --- #3 certificate hop --------------------------------------------------------------------

def owned(f):
    return Result(f.domain, 90, C.OWNED, "", [], {}, f)


def test_cert_san_hop_uses_trusted_certificates_only():
    good = fp("frontkit.io", cert=CertInfo(fetched=True, sans=["frontkit.io", "deals.new"], has_scts=True))
    intercepted = fp("x.com", cert=CertInfo(fetched=True, sans=["x.com", "proxy-sister.com"], has_scts=False))
    default_cert = fp("y.com", cert=CertInfo(fetched=True, sans=["unrelated.com", "other.net"], has_scts=True))
    out = pipeline.hop_candidates([owned(good), owned(intercepted), owned(default_cert)], set(), "zdp.com")
    assert [(c.domain, list(c.sources)) for c in out] == [("deals.new", ["cert-san"])]


# --- #4 acquisition names --------------------------------------------------------------------

def acq_result(domain, org, infra=("ns_set", "mail_tenant"), cls=C.OWNED):
    ev = [Evidence(k, Strength.STRONG, 50, k) for k in infra]
    f = fp(domain, cert=CertInfo(fetched=True, subject_org=org, sans=[domain], has_scts=True))
    return Result(domain, 100, cls, "", ev, {}, f)


def test_acquisition_names_come_only_from_well_proven_owned_domains():
    results = [
        acq_result("shiftlanesoftware.com", "Shiftlane Software, LLC"),
        acq_result("zdpworld.de", ORG),  # the seed's own name: not an acquisition
        acq_result("weak.com", "Weakly Linked Corp", infra=("redirect",)),  # one infra match only
        acq_result("rev.com", "Review Pending Inc", cls=C.REVIEW),  # not owned
        acq_result("short.com", "WFS"),  # too short to search safely
    ]
    assert pipeline.acquisition_names(results, [ORG]) == [("Shiftlane Software, LLC", "shiftlanesoftware.com")]


SEED_FP = seed_fp()
FPS = {
    "zdp.com": SEED_FP,
    # verified on infrastructure, certificate in an acquired company's name
    "shiftlanesoftware.com": fp("shiftlanesoftware.com", ns=sorted(ZDP_NS), mail_tenants=["proofpoint:0099aa01"],
                                cert=CertInfo(fetched=True, subject_org="Shiftlane Software, LLC",
                                              sans=["shiftlanesoftware.com"], has_scts=True)),
    # only found through the acquired company's certificates
    "sls.cloud": fp("sls.cloud", ns=sorted(ZDP_NS), rdap=rdap()),
}


async def fake_fp(domain, collectors, **kw):
    return FPS.get(domain) or fp(domain, registered=False)


async def no_org(*a, **kw):
    return [ORG]


async def test_pipeline_searches_ct_for_acquisition_names(monkeypatch, tmp_path):
    calls = []

    async def fake_crtsh(http, params, timeout):
        calls.append(params)
        if params.get("O") == "Shiftlane Software, LLC":
            return [{"common_name": "app.sls.cloud", "name_value": "Shiftlane Software, LLC",
                     "not_after": "2099-01-01T00:00:00"}]
        return []

    monkeypatch.setattr(pipeline, "fingerprint", fake_fp)
    monkeypatch.setattr(pipeline, "seed_org_from_ct", no_org)
    monkeypatch.setattr(pipeline, "crtsh_json", fake_crtsh)
    monkeypatch.setattr(pipeline, "ALL_SOURCES", [])
    rep = await pipeline.run("zdp.com", Settings(cache_dir=tmp_path, use_cache=False),
                             extra_candidates=["shiftlanesoftware.com"])
    by = {r.domain: r for r in rep.results}
    assert any(c.get("O") == "Shiftlane Software, LLC" for c in calls)
    assert by["sls.cloud"].sources == {"acq-ct": "certificate O=Shiftlane Software, LLC (name from shiftlanesoftware.com)"}
    assert "ct_org_acquired" in kinds(by["sls.cloud"])
    assert by["sls.cloud"].classification is C.OWNED  # same NS set + registration (+ CT in the acquired name)
    assert any(n.startswith("acquisitions: ") for n in rep.notes)


# --- #5 Wikidata ---------------------------------------------------------------------------

def test_wikidata_query_matches_the_website_exactly():
    v = website_variants("zdp.com")
    assert "https://www.zdp.com/" in v and "http://zdp.com" in v and len(v) == 8
    q = build_query("zdp.信息")
    assert "<https://www.zdp.xn--vuq861b/>" in q and "wdt:P856" in q and "wdt:P355" in q


@respx.mock
async def test_wikidata_source():
    from domainfinder.http import Http
    from test_sources import ctx_for

    answers = iter([httpx.Response(429, headers={"Retry-After": "0"}),
                    httpx.Response(200, json={"results": {"bindings": [
                        {"subLabel": {"value": "Taskhive"}, "site": {"value": "https://www.taskhive.com/"}},
                        {"subLabel": {"value": "ZDP itself?"}, "site": {"value": "https://zdp.com"}}]}})])
    respx.get(ENDPOINT).mock(side_effect=lambda req: next(answers))
    http = Http()
    ctx = ctx_for(http=http)
    out = await WikidataSource(Settings()).candidates(ctx)
    assert [(c.domain, c.sources["wikidata"]) for c in out] == [("taskhive.com", "Wikidata: official website of Taskhive")]
    assert not WikidataSource(Settings(wikidata=False)).enabled()
    await http.aclose()
