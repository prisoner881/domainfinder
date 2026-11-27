"""1.5.1: a site the seed hosts for a client (its certificate on a domain the
client registered elsewhere) stops at needs review."""

from helpers import ZDP_NS, cand, fp, rdap, seed_fp

from domainfinder.models import CertInfo
from domainfinder.models import Classification as C
from domainfinder.verify import Scorer, SeedProfile

ORG = "Zyntara Data Processing, Inc."
CERT = CertInfo(fetched=True, subject_org=ORG, has_scts=True)


def scorer(seed=None):
    s = seed or seed_fp()
    s.spf_includes = ["_spf.zdp.com"]
    return Scorer(SeedProfile.build(s, [ORG], ["zdp"]), 70, 40)


def client_site(domain="riverbendcu.org", **kw):
    kw.setdefault("rdap", rdap(registrar="GoDaddy.com, LLC", iana="146", region="ARIZONA", org="Domains By Proxy, LLC"))
    return fp(domain, cert=CERT, spf_includes=["_spf.zdp.com"], **kw)


def kinds(r):
    return {e.kind for e in r.evidence}


def test_seed_certificate_and_mail_relay_on_a_client_registered_domain_is_review():
    r = scorer().score(client_site(), cand("riverbendcu.org"), set())
    assert r.classification is C.REVIEW and r.score == 69 and "operated_for_client" in kinds(r)
    note = next(e.detail for e in r.evidence if e.kind == "operated_for_client")
    assert "registered by someone else at GoDaddy.com, LLC (the seed uses Markmonitor Inc.)" in note


def test_the_same_site_registered_by_the_seed_stays_owned():
    r = scorer().score(client_site(rdap=rdap(org=ORG)), cand("riverbendcu.org"), set())
    assert r.classification is C.OWNED and "operated_for_client" not in kinds(r)


def test_seed_dns_or_any_registration_link_keeps_it_owned():
    on_dns = client_site(ns=sorted(ZDP_NS))
    assert scorer().score(on_dns, cand("riverbendcu.org"), set()).classification is C.OWNED
    same_registrar = client_site(rdap=rdap(region="TX"))  # the seed's registrar, another region
    r = scorer().score(same_registrar, cand("riverbendcu.org"), set())
    assert "operated_for_client" not in kinds(r)


def test_unpublished_registration_or_brand_name_does_not_trigger():
    from domainfinder.models import RdapInfo

    no_rdap = client_site("riverbendcu.ch", rdap=RdapInfo())
    assert "operated_for_client" not in kinds(scorer().score(no_rdap, cand("riverbendcu.ch"), set()))
    branded = client_site("zdp-events.com")
    assert "operated_for_client" not in kinds(scorer().score(branded, cand("zdp-events.com"), set()))


def test_other_control_evidence_is_not_a_client_site():
    from helpers import web

    redirecting = client_site(web=web("http://riverbendcu.org/", "https://www.zdp.com/"))
    assert "operated_for_client" not in kinds(scorer().score(redirecting, cand("riverbendcu.org"), set()))
