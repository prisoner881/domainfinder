"""Scoring rules, using ADP-shaped fingerprints from the handoff's acceptance list."""

from helpers import ADP_MX, ADP_NS, AKAMAI, ESNET, cand, fp, rdap, seed_fp, web

from domainfinder.models import Classification as C
from domainfinder.models import Netblock
from domainfinder.sources.base import CtOrgHit
from domainfinder.verify import Scorer, SeedProfile, score_all

ORG = "Automatic Data Processing, Inc."


def scorer(**kw):
    prof = SeedProfile.build(seed_fp(), [ORG], ["adp"])
    return Scorer(prof, 70, 40, **kw)


def kinds(result):
    return {e.kind for e in result.evidence}


def test_redirect_plus_registration_is_owned():
    r = scorer().score(
        fp("myadp.com", rdap=rdap(), web=web("http://myadp.com/", "https://online.adp.com/olp")),
        cand("myadp.com"), set())
    assert r.classification is C.OWNED, r.evidence
    assert {"redirect", "registrar_region", "brand_label"} <= kinds(r)
    assert r.status == "redirects to adp.com"


def test_same_ns_set_and_mail_tenant_is_owned_without_brand():
    r = scorer().score(
        fp("workforcenow.com", ns=sorted(ADP_NS), mx=ADP_MX, mail_tenants=["proofpoint:0006eb01"]),
        cand("workforcenow.com"), set())
    assert r.classification is C.OWNED
    assert {"ns_set", "mail_tenant"} <= kinds(r)
    assert "brand_label" not in kinds(r)


def test_partial_managed_dns_overlap_alone_is_not_owned():
    ns = ADP_NS[4:9] + ["a2-64.akam.net", "a3-65.akam.net"]
    r = scorer().score(fp("x-corp.com", ns=ns), cand("x-corp.com"), set())
    assert r.classification is not C.OWNED


def test_shared_hosting_nameservers_are_ignored():
    s = SeedProfile.build(seed_fp(), [ORG], ["adp"])
    s.fp.ns = ["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"]
    r = Scorer(s).score(fp("random.com", ns=["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"]),
                        cand("random.com"), set())
    assert r.classification is C.REJECTED
    assert "ns_set" not in kinds(r) and "ns_shared" in kinds(r)


def test_org_netblock_counts_but_cdn_netblock_does_not():
    good = scorer().score(fp("adpportal.com", a=["170.146.1.1"], netblocks=[ESNET], rdap=rdap()),
                          cand("adpportal.com"), set())
    assert "netblock" in kinds(good)
    cdn = scorer().score(fp("foo.com", a=["23.1.1.1"], netblocks=[AKAMAI]), cand("foo.com"), set())
    assert "netblock" not in kinds(cdn)


def test_subsidiary_netblock_name_matches_seed_org():
    nb = Netblock(handle="ADP-AU", name="ADP-AU", start="203.2.184.0", end="203.2.191.255",
                  org="Automatic Data Processing Limited", rir="apnic")
    r = scorer().score(fp("adppayroll.com.au", a=["203.2.185.1"], netblocks=[nb]), cand("adppayroll.com.au"), set())
    assert "netblock" in kinds(r)


def test_aeroports_de_paris_is_rejected():
    r = scorer().score(
        fp("adp.fr", ns=["ns1.parisaeroport.fr"], rdap=rdap(registrar="CSC", region="", country="FR",
                                                              org="Aeroports de Paris"),
           web=web("http://adp.fr/", "https://www.parisaeroport.fr/")),
        cand("adp.fr", "cctld"), set())
    assert r.classification is C.REJECTED
    assert {"different_org_rdap", "foreign_redirect"} <= kinds(r)


def test_parked_third_party_is_rejected():
    r = scorer().score(
        fp("adpworkforce.com", ns=["ns1.parkingcrew.net", "ns2.parkingcrew.net"],
           rdap=rdap(registrar="NameSilo, LLC", region="AZ", iana="1479")),
        cand("adpworkforce.com"), set())
    assert r.classification is C.REJECTED and r.status == "parked"


def test_parked_but_registered_like_seed_needs_review():
    """adpvantage.com: MarkMonitor/NJ registration, resolves to a parking service."""
    r = scorer().score(
        fp("adpvantage.com", ns=["ns1.markmonitor.com"], rdap=rdap(),
           web=web("http://adpvantage.com/", "https://www.hugedomains.com/domain_profile.cfm?d=adpvantage")),
        cand("adpvantage.com"), set())
    assert r.classification is C.REVIEW
    assert r.status == "parked"


def test_markmonitor_holding_page_with_brand_is_owned_inactive():
    r = scorer().score(
        fp("adpresearch.com", a=["15.197.70.98"], ns=["ns1.markmonitor.com", "ns2.markmonitor.com"], rdap=rdap()),
        cand("adpresearch.com"), set())
    assert r.classification is C.OWNED
    assert r.status == "held/inactive"


def test_holding_page_without_matching_registration_is_rejected():
    r = scorer().score(
        fp("adpfoundation.org", a=["15.197.70.98"], rdap=rdap(registrar="GoDaddy.com, LLC", iana="146", region="TX")),
        cand("adpfoundation.org"), set())
    assert r.classification is C.REJECTED


def test_weak_evidence_alone_never_reaches_main_list():
    r = scorer().score(fp("adpsomething.com", rdap=rdap()), cand("adpsomething.com"), set())
    assert r.classification is C.REJECTED
    assert r.score < 40


def test_ct_org_current_vs_historic():
    ct = {"broadridge.com": CtOrgHit(org=ORG, count=3, latest_not_after="2008-01-01", current=False),
          "mastertax.com": CtOrgHit(org=ORG, count=9, latest_not_after="2027-03-01", current=True)}
    s = scorer(ct_org_domains=ct)
    old = s.score(fp("broadridge.com"), cand("broadridge.com"), set())
    assert old.classification is C.REJECTED and "ct_org_historic" in kinds(old)
    cur = s.score(fp("mastertax.com", ns=sorted(ADP_NS)), cand("mastertax.com"), set())
    assert cur.classification is C.OWNED


def test_different_registrant_needs_two_infra_matches():
    # An acquisition keeps its own registrant name but runs on ADP's DNS and mail.
    r = scorer().score(
        fp("workforcesoftware.com", ns=sorted(ADP_NS), mail_tenants=["proofpoint:0006eb01"],
           rdap=rdap(org="Workforce Software, LLC", registrar="GoDaddy", region="MI", iana="146")),
        cand("workforcesoftware.com"), set())
    assert r.classification is C.OWNED
    # ...but a different registrant plus a single redirect is only worth a look.
    r2 = scorer().score(
        fp("adpreseller.com", rdap=rdap(org="Payroll Partners LLC", registrar="GoDaddy", region="FL", iana="146"),
           web=web("http://adpreseller.com/", "https://www.adp.com/")),
        cand("adpreseller.com"), set())
    assert r2.classification is C.REVIEW


def test_unregistered_is_rejected():
    r = scorer().score(fp("adpemployment.com", registered=False), cand("adpemployment.com"), set())
    assert r.classification is C.REJECTED and r.status == "unregistered"


def test_second_pass_uses_newly_verified_domains():
    s = scorer()
    items = [
        (fp("workmarket.com", ns=sorted(ADP_NS), mail_tenants=["proofpoint:0006eb01"]), cand("workmarket.com")),
        # only connection: redirects to workmarket.com, plus registration
        (fp("workmarket.net", rdap=rdap(), web=web("http://workmarket.net/", "https://www.workmarket.com/")),
         cand("workmarket.net")),
    ]
    res = {r.domain: r for r in score_all(s, items)}
    assert res["workmarket.com"].classification is C.OWNED
    assert res["workmarket.net"].classification is C.OWNED
    assert "redirect" in kinds(res["workmarket.net"])


def test_namespace_and_spf_under_seed():
    r = scorer().score(
        fp("tmbc.com", ns=["ns1.adp.com", "ns2.adp.com"], spf_includes=["_spf.adp.com"], soa_rname="hostmaster.adp.com"),
        cand("tmbc.com"), set())
    assert r.classification is C.OWNED
    assert {"namespace", "spf_seed", "soa_rname"} <= kinds(r)


def test_brand_named_registrant_is_not_a_conflict():
    # "ADP, Inc." / "ADP France" are ADP's own short names; "Groupe ADP" is not.
    r = scorer().score(
        fp("pegase-entreprises.fr", ns=sorted(ADP_NS), soa_rname="hostmaster.adp.com",
           rdap=rdap(org="ADP France", registrar="CSC", region="", country="FR")),
        cand("pegase-entreprises.fr"), set())
    assert r.classification is C.OWNED and "brand_org" in kinds(r)
    r2 = scorer().score(fp("adp-airport.fr", rdap=rdap(org="Groupe ADP", region="", country="FR")),
                        cand("adp-airport.fr"), set())
    assert "different_org_rdap" in kinds(r2) and r2.classification is C.REJECTED


def test_held_domain_with_past_seed_certificates_is_owned():
    ct = {"workscape.com": CtOrgHit(org=ORG, count=4, latest_not_after="2019-03-12", current=False)}
    r = scorer(ct_org_domains=ct).score(
        fp("workscape.com", a=["15.197.70.98"], rdap=rdap()), cand("workscape.com"), set())
    assert r.classification is C.OWNED and r.status == "held/inactive"


def test_held_brand_domain_with_other_region_goes_to_review():
    r = scorer().score(fp("adpventures.com", a=["15.197.70.98"], ns=["ns1.markmonitor.com"],
                          rdap=rdap(region="CA", org="DNStination Inc.")),
                       cand("adpventures.com"), set())
    assert r.classification is C.REVIEW and "held_brand_registrar" in kinds(r)


def test_markmonitor_zone_nameservers_mark_a_held_domain():
    r = scorer().score(fp("marcusbuckingham.com", ns=["ha1.markmonitor.zone", "ha2.markmonitor.zone"], rdap=rdap()),
                       cand("marcusbuckingham.com"), set())
    assert r.status == "held/inactive" and r.classification is C.REVIEW


def test_registrar_named_as_registrant_is_a_proxy_not_an_owner():
    # CSC writes its own name and Delaware address into the registrant fields.
    csc = dict(registrar="CSC Corporate Domains, Inc.", iana="299", region="DE",
               org="CSC Corporate Domains, Inc.")
    prof = SeedProfile.build(fp("globalpayments.com", rdap=rdap(**csc)), ["Global Payments Inc."], ["globalpayments"])
    s = Scorer(prof)
    r = s.score(fp("cscglobal.com", rdap=rdap(**csc)), cand("cscglobal.com"), set())
    assert "rdap_org" not in kinds(r) and "different_org_rdap" not in kinds(r)
    assert "proxy_registrant" in kinds(r) and "registrar_region" not in kinds(r)
    assert r.classification is C.REJECTED


def test_proxy_names_never_become_seed_org_names():
    from domainfinder.pipeline import derive_org_names

    seed = fp("globalpayments.com", rdap=rdap(registrar="CSC Corporate Domains, Inc.", org="CSC Corporate Domains, Inc."))
    assert derive_org_names(seed, ["Global Payments"], [], "globalpayments") == ["Global Payments"]


def test_branded_domain_linked_from_seed_site_goes_to_review():
    r = scorer().score(fp("adpathletics.com"), cand("adpathletics.com", "seed-links"), set())
    assert r.classification is C.REVIEW and "seed_link_brand" in kinds(r)
    r2 = scorer().score(fp("jotform.com"), cand("jotform.com", "seed-links"), set())
    assert r2.classification is C.REJECTED


def test_managed_web_host_netblock_is_not_ownership():
    from domainfinder.models import Netblock

    s = SeedProfile.build(seed_fp(), [ORG], ["adp"])
    pantheon = Netblock(handle="P", name="PANTHEON-IP4", start="23.185.0.0", end="23.185.0.255", org="Pantheon")
    s.fp.netblocks = [pantheon]
    s = SeedProfile.build(s.fp, [ORG], ["adp"])
    r = Scorer(s).score(fp("someotheruni.edu", a=["23.185.0.3"], netblocks=[pantheon]), cand("someotheruni.edu"), set())
    assert "netblock" not in kinds(r)


def test_strong_evidence_with_a_conflicting_name_goes_to_review():
    """springcm.com: current CT cert says DocuSign, the live cert says SpringCM."""
    from domainfinder.models import CertInfo

    ct = {"springcm.com": CtOrgHit(org=ORG, count=3, latest_not_after="2027-03-14", current=True)}
    r = scorer(ct_org_domains=ct).score(
        fp("springcm.com", rdap=rdap(), cert=CertInfo(fetched=True, subject_org="SpringCM, INC")),
        cand("springcm.com"), set())
    assert {"ct_org_current", "different_org_cert"} <= kinds(r)
    assert r.classification is C.REVIEW and r.score >= 40
    # Without any strong evidence, a conflicting name still means rejection.
    r2 = scorer().score(fp("liveoak.net", rdap=rdap(org="Liveoak Technologies, Inc.", region="TX")),
                        cand("liveoak.net"), set())
    assert r2.classification is C.REJECTED


def test_redirect_to_the_registrars_own_site_is_a_holding_signal():
    """arx.com: parked by MarkMonitor, redirecting to markmonitor.com."""
    r = scorer().score(
        fp("arx.com", rdap=rdap(region="CA"), web=web("http://arx.com/", "https://www.markmonitor.com/")),
        cand("arx.com"), set())
    assert "foreign_redirect" not in kinds(r) and "registrar_redirect" in kinds(r)
    assert r.status == "held/inactive"
    # A mass-market registrar's own site: neutral, but not "held".
    r2 = scorer().score(
        fp("someone.com", rdap=rdap(registrar="GoDaddy.com, LLC", iana="146", region="AZ"),
           web=web("http://someone.com/", "https://www.godaddy.com/forsale")),
        cand("someone.com"), set())
    assert "foreign_redirect" not in kinds(r2) and r2.status != "held/inactive"
    # Any other unrelated site is still a foreign redirect.
    r3 = scorer().score(fp("adp.fr", rdap=rdap(registrar="CSC Corporate Domains, Inc.", iana="299", region=""),
                           web=web("http://adp.fr/", "https://www.parisaeroport.fr/")), cand("adp.fr"), set())
    assert "foreign_redirect" in kinds(r3)
