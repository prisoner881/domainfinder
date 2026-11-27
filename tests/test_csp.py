"""Candidate CSP as evidence, and one-hop CSP discovery (the mdmly.com case)."""

from helpers import cand, fp, seed_fp, web

from domainfinder import pipeline
from domainfinder.config import Settings
from domainfinder.models import Classification as C
from domainfinder.models import Fingerprint, WebInfo
from domainfinder.verify import Scorer, SeedProfile

ORG = "Zyntara Data Processing, Inc."


def kinds(r):
    return {e.kind for e in r.evidence}


def scorer():
    return Scorer(SeedProfile.build(seed_fp(), [ORG], ["zdp"]))


def page(domain, **kw):
    return WebInfo(fetched=True, status=200, chain=[f"https://{domain}/"], final_url=f"https://{domain}/", **kw)


def test_csp_trusting_the_seed_and_verified_domains_is_strong():
    w = page("zdpcloud.com", csp_domains=["zdp.com", "taskhive.com", "intercom.io"])
    r = scorer().score(fp("zdpcloud.com", web=w), cand("zdpcloud.com"), {"taskhive.com"})
    assert "csp_trust" in kinds(r)
    assert r.classification is C.REVIEW  # one strong signal + brand: review, not owned


def test_csp_trusting_only_the_seed_depends_on_the_brand():
    branded = scorer().score(fp("zdpcloud.com", web=page("zdpcloud.com", csp_domains=["zdp.com"])),
                             cand("zdpcloud.com"), set())
    assert "csp_trust_brand" in kinds(branded) and branded.classification is C.REVIEW
    other = scorer().score(fp("customer-hr.com", web=page("customer-hr.com", csp_domains=["zdp.com"])),
                           cand("customer-hr.com"), set())
    assert "csp_trust_one" in kinds(other) and other.classification is C.REJECTED


def test_own_domain_in_own_csp_does_not_count():
    w = page("zdpcloud.com", csp_domains=["zdpcloud.com"])
    r = scorer().score(fp("zdpcloud.com", web=w), cand("zdpcloud.com"), {"zdpcloud.com"})
    assert not {"csp_trust", "csp_trust_brand", "csp_trust_one"} & kinds(r)


# --- pipeline: the mdmly.com shape -------------------------------------------------

MDMLY_SEED = Fingerprint(domain="mdmly.com", brand_label="mdmly", registered=True,
                        web=WebInfo(fetched=True, chain=["https://mdmly.com/"], final_url="https://mdmly.com/", status=200))
MDMLY = {
    "mdmly.com": MDMLY_SEED,
    "mdmlycloud.com": fp("mdmlycloud.com", web=WebInfo(
        fetched=True, status=200, chain=["https://www.mdmlycloud.com/"], final_url="https://www.mdmlycloud.com/",
        csp_domains=["mdmly.com", "mdmlysoftware.com", "mdmly.io", "mdmlycloud.com", "intercom.io"])),
    "mdmlysoftware.com": fp("mdmlysoftware.com", www_cname=["www.mdmly.com"],
                           web=web("http://mdmlysoftware.com/", "https://www.mdmly.com/")),
    "mdmly.io": fp("mdmly.io"),
    "intercom.io": fp("intercom.io"),
}


async def mdmly_fingerprint(domain, collectors, **kw):
    return MDMLY.get(domain) or fp(domain, registered=False)


async def no_ct_org(*a, **kw):
    return []


async def test_csp_hop_finds_and_verifies_the_named_domains(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "fingerprint", mdmly_fingerprint)
    monkeypatch.setattr(pipeline, "seed_org_from_ct", no_ct_org)
    monkeypatch.setattr(pipeline, "ALL_SOURCES", [])
    rep = await pipeline.run("mdmly.com", Settings(cache_dir=tmp_path, use_cache=False),
                             extra_candidates=["mdmlycloud.com"])
    by = {r.domain: r for r in rep.results}
    # First pass: mdmlycloud.com trusts the seed and carries the brand → review;
    # its CSP is mined: mdmlysoftware.com (redirects to mdmly.com) becomes owned;
    # second scoring: mdmlycloud.com now trusts two of ours → strong evidence.
    assert by["mdmlysoftware.com"].classification is C.OWNED
    assert by["mdmlysoftware.com"].sources == {"csp": "named in the CSP of mdmlycloud.com"}
    assert "csp_trust" in kinds(by["mdmlycloud.com"]) and by["mdmlycloud.com"].classification is C.REVIEW
    assert by["mdmly.io"].classification is C.REJECTED  # discovered, but no evidence
    assert "csp" in rep.sources_used and any(n.startswith("second pass: ") and "from csp" in n for n in rep.notes)
    assert rep.candidates_verified == len(by)


async def test_csp_hop_can_be_turned_off(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "fingerprint", mdmly_fingerprint)
    monkeypatch.setattr(pipeline, "seed_org_from_ct", no_ct_org)
    monkeypatch.setattr(pipeline, "ALL_SOURCES", [])
    rep = await pipeline.run("mdmly.com", Settings(cache_dir=tmp_path, use_cache=False, csp_discovery=False),
                             extra_candidates=["mdmlycloud.com"])
    assert {r.domain for r in rep.results} == {"mdmlycloud.com"}
    assert rep.sources_disabled.get("csp")


# --- 1.0.0: no double counting after a redirect ---------------------------------------

SEED_TAG = "gtm:GTM-SEED123"


def seed_with_tag():
    from helpers import seed_fp as _seed

    s = _seed()
    s.web.analytics_ids = [SEED_TAG]
    return Scorer(SeedProfile.build(s, [ORG], ["zdp"]))


def test_typosquat_redirecting_to_the_seed_does_not_inherit_its_page_evidence():
    """The final page is zdp.com's own: its tag and CSP are not evidence about the typo domain."""
    w = WebInfo(fetched=True, status=200, chain=["http://zdpp.com/", "https://www.zdp.com/"],
                final_url="https://www.zdp.com/", analytics_ids=[SEED_TAG], csp_domains=["zdp.com", "zdp.ca"])
    r = seed_with_tag().score(fp("zdpp.com", web=w), cand("zdpp.com"), {"zdp.ca"})
    assert "redirect" in kinds(r)
    assert not {"analytics", "csp_trust", "csp_trust_brand", "csp_trust_one"} & kinds(r)
    assert r.classification is C.REVIEW and r.score == 65  # redirect 60 + brand 5: a person decides


def test_redirect_plus_one_independent_link_is_owned():
    from helpers import rdap

    w = WebInfo(fetched=True, status=200, chain=["http://zdp.ae/", "https://www.zdp.com/"],
                final_url="https://www.zdp.com/", analytics_ids=[SEED_TAG])
    r = seed_with_tag().score(fp("zdp.ae", web=w, rdap=rdap()), cand("zdp.ae"), set())
    assert r.classification is C.OWNED  # redirect 60 + same registrar and region 10 (+ brand)


def test_own_page_with_the_same_tag_still_counts():
    w = page("zdpcareers.com", analytics_ids=[SEED_TAG])
    r = seed_with_tag().score(fp("zdpcareers.com", web=w), cand("zdpcareers.com"), set())
    assert "analytics" in kinds(r)


def test_csp_discovery_skips_redirecting_domains():
    from domainfinder.models import Result

    redirecting = fp("zdpp.com", web=WebInfo(fetched=True, status=200, chain=["http://zdpp.com/", "https://zdp.com/"],
                                             final_url="https://zdp.com/", csp_domains=["vendor-a.com"]))
    own = fp("zdpcloud.com", web=page("zdpcloud.com", csp_domains=["vendor-b.com"]))
    results = [Result(f.domain, 80, C.OWNED, "", [], {}, f) for f in (redirecting, own)]
    assert [c.domain for c in pipeline.csp_candidates(results, set(), "zdp.com")] == ["vendor-b.com"]
