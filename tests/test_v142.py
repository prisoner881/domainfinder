"""1.4.2: a redirect plus the name is not enough; same brand-protection registrar
with the region unpublished; brand as run-together leading words of an
organization name; registrar RDAP failures are reported."""

import httpx
import respx
from helpers import cand, fp, rdap, seed_fp, web

from domainfinder.collectors.rdap import RdapClient
from domainfinder.http import Http
from domainfinder.models import Classification as C
from domainfinder.verify import Scorer, SeedProfile

ORG = "Zyntara Data Processing, Inc."
REDIRECT = web("http://zdpcanada.com/", "https://www.zdp.com/")


def scorer(seed=None, brands=("zdp",), subs=None):
    return Scorer(SeedProfile.build(seed or seed_fp(), [ORG], list(brands)), 70, 40, {}, subs or {})


def kinds(r):
    return {e.kind for e in r.evidence}


def test_redirect_and_name_alone_stay_in_review():
    # Registered last year at a consumer registrar behind a privacy service,
    # redirecting to the seed: the shape of a typosquat or a domain investor.
    squat = fp("zdpcanada.com", web=REDIRECT,
               rdap=rdap(registrar="NameCheap, Inc.", iana="1068", region="DELAWARE", org=""))
    r = scorer(subs={"zdpcanada.com": "ZDP Canada Co."}).score(squat, cand("zdpcanada.com"), set())
    assert r.score == 69 and r.classification is C.REVIEW and "redirect_only" in kinds(r)


def test_redirect_with_any_other_channel_is_owned():
    old_cert = fp("zdpcanada.com", web=REDIRECT, rdap=rdap(registrar="NameCheap, Inc.", iana="1068", region="AZ"))
    from domainfinder.sources.base import CtOrgHit

    s = Scorer(SeedProfile.build(seed_fp(), [ORG], ["zdp"]), 70, 40,
               {"zdpcanada.com": CtOrgHit(ORG, 2, "2016-01-01", False)})
    r = s.score(old_cert, cand("zdpcanada.com"), set())
    assert r.classification is C.OWNED and "redirect_only" not in kinds(r)


def test_same_brand_protection_registrar_with_region_unpublished():
    seed = seed_fp()
    seed.rdap = rdap(registrar="Safenames Ltd.", iana="447", region="", country="")
    f = fp("zdpcanada.com", web=REDIRECT, rdap=rdap(registrar="SafeNames Ltd.", iana="447", region="", country=""))
    r = scorer(seed).score(f, cand("zdpcanada.com"), set())
    assert {e.kind: e.points for e in r.evidence}["registrar_brand"] == 5
    assert r.classification is C.OWNED


def test_no_registrar_credit_when_regions_differ_or_registrar_is_mass_market():
    seed = seed_fp()  # MarkMonitor, OH
    other_region = fp("x-zdp.com", rdap=rdap(region="TX"))
    assert "registrar_brand" not in kinds(scorer(seed).score(other_region, cand("x-zdp.com"), set()))
    seed.rdap = rdap(registrar="GoDaddy.com, LLC", iana="146", region="")
    mass = fp("y-zdp.com", rdap=rdap(registrar="GoDaddy.com, LLC", iana="146", region=""))
    assert "registrar_brand" not in kinds(scorer(seed).score(mass, cand("y-zdp.com"), set()))


def test_brand_as_leading_words_of_an_organization_name_is_not_a_conflict():
    from domainfinder.models import CertInfo

    seed = seed_fp()
    seed.domain, seed.brand_label = "informadb.pt", "informadb"
    s = Scorer(SeedProfile.build(seed, ["Informa D&B Servicos de Gestao de Empresas SA"], ["informadb"]), 70, 40)
    f = fp("informadb.es", cert=CertInfo(fetched=True, subject_org="Informa D&B SA SME", has_scts=True))
    r = s.score(f, cand("informadb.es"), set())
    assert "brand_org" in kinds(r) and "different_org_cert" not in kinds(r)


def test_brand_org_matches_whole_leading_words_only():
    s = scorer(brands=("informadb",))
    assert s._brand_org("Informa D&B SA SME")
    assert s._brand_org("INFORMADB SERVICOS LDA")
    assert not s._brand_org("Informatica DB Corp")      # 'informaticadb' is not the brand
    assert not s._brand_org("Grupo Informa D&B")         # does not start with it
    assert scorer()._brand_org("ZDP France") and not scorer()._brand_org("Zone de Plaisance")


@respx.mock
async def test_registrar_rdap_failures_are_counted():
    respx.get("https://data.iana.org/rdap/dns.json").respond(
        json={"services": [[["com"], ["https://rdap.verisign.com/com/v1/"]]]})
    respx.get("https://rdap.verisign.com/com/v1/domain/x-zdp.com").respond(json={
        "objectClassName": "domain", "ldhName": "X-ZDP.COM",
        "links": [{"rel": "related", "href": "https://rdap.registrar.example/domain/X-ZDP.COM"}]})
    respx.get("https://rdap.registrar.example/domain/X-ZDP.COM").mock(return_value=httpx.Response(429))
    http = Http()
    c = RdapClient(http)
    info = await c.domain("x-zdp.com")
    assert info.available is not False and c.registrar_failures == {"rdap.registrar.example": 1}
    await http.aclose()


# --- redirect targets of owned domains become candidates ------------------------------------

def test_redirect_target_of_an_owned_domain_is_a_candidate():
    from domainfinder import pipeline
    from domainfinder.models import Result

    owned = Result("zdpexchange.com", 95, C.OWNED, "", [], {},
                   fp("zdpexchange.com", web=web("https://zdpexchange.com/", "https://www.zdpplatformone.com/")))
    review = Result("zdp-maybe.com", 65, C.REVIEW, "", [], {},
                    fp("zdp-maybe.com", web=web("https://zdp-maybe.com/", "https://elsewhere.com/")))
    out = {c.domain: c.sources for c in pipeline.hop_candidates([owned, review], set(), "zdp.com")}
    assert out == {"zdpplatformone.com": {"redirect-target": "zdpexchange.com redirects to it"}}
    assert pipeline.hop_candidates([owned], set(), "zdp.com", use_redirects=False) == []
