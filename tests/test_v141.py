"""1.4.1: certificate hop vouched for by owned domains only; certificates in an
acquired company's name are weaker; holding infrastructure of the seed's
brand-protection registrar stands in for missing registration data."""

from helpers import cand, fp, rdap, seed_fp, web

from domainfinder import pipeline
from domainfinder.models import CertInfo, Result
from domainfinder.models import Classification as C
from domainfinder.models import RdapInfo
from domainfinder.sources.base import CtOrgHit
from domainfinder.verify import CONTROL_KINDS, Scorer, SeedProfile

ORG = "Zyntara Data Processing, Inc."
VENDOR_SANS = ["eruathletics.com", "eruclubsports.com"] + [f"college{i}sports.com" for i in range(20)]


def result(domain, cls, sans):
    f = fp(domain, cert=CertInfo(fetched=True, sans=sans, has_scts=True))
    return Result(domain, 65 if cls is C.REVIEW else 90, cls, "", [], {}, f)


def test_review_domains_do_not_vouch_for_each_others_vendor_certificate():
    rs = [result("eruathletics.com", C.REVIEW, VENDOR_SANS), result("eruclubsports.com", C.REVIEW, VENDOR_SANS)]
    assert pipeline.hop_candidates(rs, set(), "eru.edu") == []


def test_an_owned_domain_on_the_certificate_still_vouches():
    rs = [result("eruathletics.com", C.REVIEW, VENDOR_SANS), result("eruclubsports.com", C.OWNED, ["eruclubsports.com"])]
    out = {c.domain for c in pipeline.hop_candidates(rs, set(), "eru.edu")}
    assert "college3sports.com" in out


# --- certificates in an acquired company's name -----------------------------------------------

def scorer(ct=None, seed=None):
    return Scorer(SeedProfile.build(seed or seed_fp(), [ORG], ["zdp"]), 70, 40, ct or {})


def test_acquired_company_certificate_is_medium_and_not_control():
    hit = CtOrgHit("HANSA BANK AG", 3, "2027-05-01", True, acquired="hansa-paynetic.com")
    r = scorer({"hansa-direct.de": hit}).score(fp("hansa-direct.de"), cand("hansa-direct.de"), set())
    e = next(e for e in r.evidence if e.kind == "ct_org_acquired")
    assert e.points == 25 and e.strength.value == "medium" and "a name found on hansa-paynetic.com" in e.detail
    assert "ct_org_acquired" not in CONTROL_KINDS and "ct_org_current" not in {x.kind for x in r.evidence}
    assert r.classification is C.REJECTED


def test_expired_acquired_company_certificates_are_weak():
    hit = CtOrgHit("Old Corp", 1, "2019-01-01", False, acquired="x-zdp.com")
    r = scorer({"old.com": hit}).score(fp("old.com"), cand("old.com"), set())
    assert {e.kind: e.points for e in r.evidence}["ct_org_acquired_historic"] == 5


# --- holding infrastructure where no registration data is published ------------------------------

NO_RDAP = RdapInfo()  # e.g. .ae, .be, .ch: no RDAP service


def held_cctld(**kw):
    return fp("zdp.ae", ns=["ns1.markmonitor.com", "ns2.markmonitor.com"], rdap=NO_RDAP, **kw)


def test_redirect_from_the_seeds_registrar_holding_infrastructure_is_owned():
    r = scorer().score(held_cctld(web=web("http://zdp.ae/", "https://www.zdp.com/")), cand("zdp.ae"), set())
    e = next(e for e in r.evidence if e.kind == "held_brand_registrar")
    assert "holding infrastructure of the seed's brand-protection registrar (Markmonitor Inc.;" in e.detail
    assert r.classification is C.OWNED


def test_holding_infrastructure_alone_stays_in_review():
    r = scorer().score(held_cctld(), cand("zdp.ae"), set())
    assert "held_brand_registrar" in {e.kind for e in r.evidence} and r.classification is C.REVIEW


def test_another_registrars_holding_infrastructure_infers_nothing():
    seed = seed_fp()
    seed.rdap = rdap(registrar="CSC Corporate Domains, Inc.", iana="299")
    r = scorer(seed=seed).score(held_cctld(web=web("http://zdp.ae/", "https://www.zdp.com/")), cand("zdp.ae"), set())
    assert "held_brand_registrar" not in {e.kind for e in r.evidence} and r.classification is C.REVIEW


def test_published_registration_data_wins_over_inference():
    other = rdap(registrar="GoDaddy.com, LLC", iana="146", region="AZ")
    r = scorer().score(fp("zdp.ae", ns=["ns1.markmonitor.com"], rdap=other), cand("zdp.ae"), set())
    assert not {"held_brand_registrar", "held_brand", "held"} & {e.kind for e in r.evidence}
