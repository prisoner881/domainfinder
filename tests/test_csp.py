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


def page(domain, **kw):
    return WebInfo(fetched=True, status=200, chain=[f"https://{domain}/"], final_url=f"https://{domain}/", **kw)


def test_csp_trusting_the_seed_and_verified_domains_is_strong():
    w = page("adpcloud.com", csp_domains=["adp.com", "workmarket.com", "intercom.io"])
    r = scorer().score(fp("adpcloud.com", web=w), cand("adpcloud.com"), {"workmarket.com"})
    assert "csp_trust" in kinds(r)
    assert r.classification is C.REVIEW  # one strong signal + brand: review, not owned


def test_csp_trusting_only_the_seed_depends_on_the_brand():
    branded = scorer().score(fp("adpcloud.com", web=page("adpcloud.com", csp_domains=["adp.com"])),
                             cand("adpcloud.com"), set())
    assert "csp_trust_brand" in kinds(branded) and branded.classification is C.REVIEW
    other = scorer().score(fp("customer-hr.com", web=page("customer-hr.com", csp_domains=["adp.com"])),
                           cand("customer-hr.com"), set())
    assert "csp_trust_one" in kinds(other) and other.classification is C.REJECTED


def test_own_domain_in_own_csp_does_not_count():
    w = page("adpcloud.com", csp_domains=["adpcloud.com"])
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


# --- 1.0.0: no double counting after a redirect ---------------------------------------

SEED_TAG = "gtm:GTM-SEED123"


def seed_with_tag():
    from helpers import seed_fp as _seed

    s = _seed()
    s.web.analytics_ids = [SEED_TAG]
    return Scorer(SeedProfile.build(s, [ORG], ["adp"]))


def test_typosquat_redirecting_to_the_seed_does_not_inherit_its_page_evidence():
    """The final page is adp.com's own: its tag and CSP are not evidence about the typo domain."""
    w = WebInfo(fetched=True, status=200, chain=["http://adpp.com/", "https://www.adp.com/"],
                final_url="https://www.adp.com/", analytics_ids=[SEED_TAG], csp_domains=["adp.com", "adp.ca"])
    r = seed_with_tag().score(fp("adpp.com", web=w), cand("adpp.com"), {"adp.ca"})
    assert "redirect" in kinds(r)
    assert not {"analytics", "csp_trust", "csp_trust_brand", "csp_trust_one"} & kinds(r)
    assert r.classification is C.REVIEW and r.score == 65  # redirect 60 + brand 5: a person decides


def test_redirect_plus_one_independent_link_is_owned():
    from helpers import rdap

    w = WebInfo(fetched=True, status=200, chain=["http://adp.ae/", "https://www.adp.com/"],
                final_url="https://www.adp.com/", analytics_ids=[SEED_TAG])
    r = seed_with_tag().score(fp("adp.ae", web=w, rdap=rdap()), cand("adp.ae"), set())
    assert r.classification is C.OWNED  # redirect 60 + same registrar and region 10 (+ brand)


def test_own_page_with_the_same_tag_still_counts():
    w = page("adpcareers.com", analytics_ids=[SEED_TAG])
    r = seed_with_tag().score(fp("adpcareers.com", web=w), cand("adpcareers.com"), set())
    assert "analytics" in kinds(r)


def test_csp_discovery_skips_redirecting_domains():
    from domainfinder.models import Result

    redirecting = fp("adpp.com", web=WebInfo(fetched=True, status=200, chain=["http://adpp.com/", "https://adp.com/"],
                                             final_url="https://adp.com/", csp_domains=["vendor-a.com"]))
    own = fp("adpcloud.com", web=page("adpcloud.com", csp_domains=["vendor-b.com"]))
    results = [Result(f.domain, 80, C.OWNED, "", [], {}, f) for f in (redirecting, own)]
    assert [c.domain for c in pipeline.csp_candidates(results, set(), "adp.com")] == ["vendor-b.com"]
