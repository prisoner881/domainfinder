"""Candidate CSP as evidence, and one-hop CSP discovery (the jamf.com case)."""

from helpers import cand, fp, seed_fp, web

from domainfinder import pipeline
from domainfinder.config import Settings
from domainfinder.models import Classification as C
from domainfinder.models import Fingerprint, WebInfo
from domainfinder.verify import Scorer, SeedProfile

ORG = "Automatic Data Processing, Inc."


def kinds(r):
    return {e.kind for e in r.evidence}


def scorer():
    return Scorer(SeedProfile.build(seed_fp(), [ORG], ["adp"]))


def test_csp_trusting_the_seed_and_verified_domains_is_strong():
    w = WebInfo(fetched=True, status=200, csp_domains=["adp.com", "workmarket.com", "intercom.io"])
    r = scorer().score(fp("adpcloud.com", web=w), cand("adpcloud.com"), {"workmarket.com"})
    assert "csp_trust" in kinds(r)
    assert r.classification is C.REVIEW  # one strong signal + brand: review, not owned


def test_csp_trusting_only_the_seed_depends_on_the_brand():
    w = WebInfo(fetched=True, status=200, csp_domains=["adp.com"])
    branded = scorer().score(fp("adpcloud.com", web=w), cand("adpcloud.com"), set())
    assert "csp_trust_brand" in kinds(branded) and branded.classification is C.REVIEW
    other = scorer().score(fp("customer-hr.com", web=w), cand("customer-hr.com"), set())
    assert "csp_trust_one" in kinds(other) and other.classification is C.REJECTED


def test_own_domain_in_own_csp_does_not_count():
    w = WebInfo(fetched=True, status=200, csp_domains=["adpcloud.com"])
    r = scorer().score(fp("adpcloud.com", web=w), cand("adpcloud.com"), {"adpcloud.com"})
    assert not {"csp_trust", "csp_trust_brand", "csp_trust_one"} & kinds(r)


# --- pipeline: the jamf.com shape -------------------------------------------------

JAMF_SEED = Fingerprint(domain="jamf.com", brand_label="jamf", registered=True,
                        web=WebInfo(fetched=True, chain=["https://jamf.com/"], final_url="https://jamf.com/", status=200))
JAMF = {
    "jamf.com": JAMF_SEED,
    "jamfcloud.com": fp("jamfcloud.com", web=WebInfo(
        fetched=True, status=200, chain=["https://www.jamfcloud.com/"], final_url="https://www.jamfcloud.com/",
        csp_domains=["jamf.com", "jamfsoftware.com", "jamf.io", "jamfcloud.com", "intercom.io"])),
    "jamfsoftware.com": fp("jamfsoftware.com", www_cname=["www.jamf.com"],
                           web=web("http://jamfsoftware.com/", "https://www.jamf.com/")),
    "jamf.io": fp("jamf.io"),
    "intercom.io": fp("intercom.io"),
}


async def jamf_fingerprint(domain, collectors, **kw):
    return JAMF.get(domain) or fp(domain, registered=False)


async def no_ct_org(*a, **kw):
    return []


async def test_csp_hop_finds_and_verifies_the_named_domains(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "fingerprint", jamf_fingerprint)
    monkeypatch.setattr(pipeline, "seed_org_from_ct", no_ct_org)
    monkeypatch.setattr(pipeline, "ALL_SOURCES", [])
    rep = await pipeline.run("jamf.com", Settings(cache_dir=tmp_path, use_cache=False),
                             extra_candidates=["jamfcloud.com"])
    by = {r.domain: r for r in rep.results}
    # First pass: jamfcloud.com trusts the seed and carries the brand → review;
    # its CSP is mined: jamfsoftware.com (redirects to jamf.com) becomes owned;
    # second scoring: jamfcloud.com now trusts two of ours → strong evidence.
    assert by["jamfsoftware.com"].classification is C.OWNED
    assert by["jamfsoftware.com"].sources == {"csp": "named in the CSP of jamfcloud.com"}
    assert "csp_trust" in kinds(by["jamfcloud.com"]) and by["jamfcloud.com"].classification is C.REVIEW
    assert by["jamf.io"].classification is C.REJECTED  # discovered, but no evidence
    assert "csp" in rep.sources_used and any(n.startswith("csp: ") for n in rep.notes)
    assert rep.candidates_verified == len(by)


async def test_csp_hop_can_be_turned_off(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "fingerprint", jamf_fingerprint)
    monkeypatch.setattr(pipeline, "seed_org_from_ct", no_ct_org)
    monkeypatch.setattr(pipeline, "ALL_SOURCES", [])
    rep = await pipeline.run("jamf.com", Settings(cache_dir=tmp_path, use_cache=False, csp_discovery=False),
                             extra_candidates=["jamfcloud.com"])
    assert {r.domain for r in rep.results} == {"jamfcloud.com"}
    assert rep.sources_disabled.get("csp")
