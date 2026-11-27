"""Scoring rules, using ZDP-shaped fingerprints from the handoff's acceptance list."""

from helpers import ZDP_MX, ZDP_NS, AKAMAI, CORENET, cand, fp, rdap, seed_fp, web

from domainfinder.models import Classification as C
from domainfinder.models import Netblock
from domainfinder.sources.base import CtOrgHit
from domainfinder.verify import Scorer, SeedProfile, score_all

ORG = "Zyntara Data Processing, Inc."


def scorer(**kw):
    prof = SeedProfile.build(seed_fp(), [ORG], ["zdp"])
    return Scorer(prof, 70, 40, **kw)


def kinds(result):
    return {e.kind for e in result.evidence}


def test_redirect_plus_registration_is_owned():
    r = scorer().score(
        fp("myzdp.com", rdap=rdap(), web=web("http://myzdp.com/", "https://online.zdp.com/olp")),
        cand("myzdp.com"), set())
    assert r.classification is C.OWNED, r.evidence
    assert {"redirect", "registrar_region", "brand_label"} <= kinds(r)
    assert r.status == "redirects to zdp.com"


def test_same_ns_set_and_mail_tenant_is_owned_without_brand():
    r = scorer().score(
        fp("staffnow.com", ns=sorted(ZDP_NS), mx=ZDP_MX, mail_tenants=["proofpoint:0099aa01"]),
        cand("staffnow.com"), set())
    assert r.classification is C.OWNED
    assert {"ns_set", "mail_tenant"} <= kinds(r)
    assert "brand_label" not in kinds(r)


def test_partial_managed_dns_overlap_alone_is_not_owned():
    ns = ZDP_NS[4:9] + ["a2-64.akam.net", "a3-65.akam.net"]
    r = scorer().score(fp("x-corp.com", ns=ns), cand("x-corp.com"), set())
    assert r.classification is not C.OWNED


def test_shared_hosting_nameservers_are_ignored():
    s = SeedProfile.build(seed_fp(), [ORG], ["zdp"])
    s.fp.ns = ["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"]
    r = Scorer(s).score(fp("random.com", ns=["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"]),
                        cand("random.com"), set())
    assert r.classification is C.REJECTED
    assert "ns_set" not in kinds(r) and "ns_shared" in kinds(r)


def test_org_netblock_counts_but_cdn_netblock_does_not():
    good = scorer().score(fp("zdpportal.com", a=["198.18.1.1"], netblocks=[CORENET], rdap=rdap()),
                          cand("zdpportal.com"), set())
    assert "netblock" in kinds(good)
    cdn = scorer().score(fp("foo.com", a=["23.1.1.1"], netblocks=[AKAMAI]), cand("foo.com"), set())
    assert "netblock" not in kinds(cdn)


def test_subsidiary_netblock_name_matches_seed_org():
    nb = Netblock(handle="ZDP-AU", name="ZDP-AU", start="203.2.184.0", end="203.2.191.255",
                  org="Zyntara Data Processing Limited", rir="apnic")
    r = scorer().score(fp("zdppayroll.com.au", a=["203.2.185.1"], netblocks=[nb]), cand("zdppayroll.com.au"), set())
    assert "netblock" in kinds(r)


def test_same_initials_other_organization_is_rejected():
    r = scorer().score(
        fp("zdp.fr", ns=["ns1.plaisance-zone.fr"], rdap=rdap(registrar="CSC", region="", country="FR",
                                                              org="Zone de Plaisance"),
           web=web("http://zdp.fr/", "https://www.plaisance-zone.fr/")),
        cand("zdp.fr", "cctld"), set())
    assert r.classification is C.REJECTED
    assert {"different_org_rdap", "foreign_redirect"} <= kinds(r)


def test_parked_third_party_is_rejected():
    r = scorer().score(
        fp("zdpworkforce.com", ns=["ns1.parkingcrew.net", "ns2.parkingcrew.net"],
           rdap=rdap(registrar="NameSilo, LLC", region="AZ", iana="1479")),
        cand("zdpworkforce.com"), set())
    assert r.classification is C.REJECTED and r.status == "parked"


def test_parked_but_registered_like_seed_needs_review():
    """zdpvantage.com: MarkMonitor/OH registration, resolves to a parking service."""
    r = scorer().score(
        fp("zdpvantage.com", ns=["ns1.markmonitor.com"], rdap=rdap(),
           web=web("http://zdpvantage.com/", "https://www.hugedomains.com/domain_profile.cfm?d=zdpvantage")),
        cand("zdpvantage.com"), set())
    assert r.classification is C.REVIEW
    assert r.status == "parked"


def test_markmonitor_holding_page_with_brand_is_review_not_owned():
    # 1.3.0: registration similarity alone (registrar + region + brand) is
    # probable, not proven, so it stops at review however high it scores.
    r = scorer().score(
        fp("zdpresearch.com", a=["15.197.70.98"], ns=["ns1.markmonitor.com", "ns2.markmonitor.com"], rdap=rdap()),
        cand("zdpresearch.com"), set())
    assert r.classification is C.REVIEW and r.score == 65
    assert r.status == "held/inactive" and "registration_only" in kinds(r)


def test_holding_page_without_matching_registration_is_rejected():
    r = scorer().score(
        fp("zdpfoundation.org", a=["15.197.70.98"], rdap=rdap(registrar="GoDaddy.com, LLC", iana="146", region="TX")),
        cand("zdpfoundation.org"), set())
    assert r.classification is C.REJECTED


def test_weak_evidence_alone_never_reaches_main_list():
    r = scorer().score(fp("zdpsomething.com", rdap=rdap()), cand("zdpsomething.com"), set())
    assert r.classification is C.REJECTED
    assert r.score < 40


def test_ct_org_current_vs_historic():
    ct = {"formerunit.com": CtOrgHit(org=ORG, count=3, latest_not_after="2008-01-01", current=False),
          "taxdesk.com": CtOrgHit(org=ORG, count=9, latest_not_after="2027-03-01", current=True)}
    s = scorer(ct_org_domains=ct)
    old = s.score(fp("formerunit.com"), cand("formerunit.com"), set())
    assert old.classification is C.REJECTED and "ct_org_historic" in kinds(old)
    cur = s.score(fp("taxdesk.com", ns=sorted(ZDP_NS)), cand("taxdesk.com"), set())
    assert cur.classification is C.OWNED


def test_different_registrant_needs_two_infra_matches():
    # An acquisition keeps its own registrant name but runs on ZDP's DNS and mail.
    r = scorer().score(
        fp("shiftlanesoftware.com", ns=sorted(ZDP_NS), mail_tenants=["proofpoint:0099aa01"],
           rdap=rdap(org="Shiftlane Software, LLC", registrar="GoDaddy", region="MI", iana="146")),
        cand("shiftlanesoftware.com"), set())
    assert r.classification is C.OWNED
    # ...but a different registrant plus a single redirect is only worth a look.
    r2 = scorer().score(
        fp("zdpreseller.com", rdap=rdap(org="Payroll Partners LLC", registrar="GoDaddy", region="FL", iana="146"),
           web=web("http://zdpreseller.com/", "https://www.zdp.com/")),
        cand("zdpreseller.com"), set())
    assert r2.classification is C.REVIEW


def test_unregistered_is_rejected():
    r = scorer().score(fp("zdpemployment.com", registered=False), cand("zdpemployment.com"), set())
    assert r.classification is C.REJECTED and r.status == "unregistered"


def test_second_pass_uses_newly_verified_domains():
    s = scorer()
    items = [
        (fp("taskhive.com", ns=sorted(ZDP_NS), mail_tenants=["proofpoint:0099aa01"]), cand("taskhive.com")),
        # only connection: redirects to taskhive.com, plus registration
        (fp("taskhive.net", rdap=rdap(), web=web("http://taskhive.net/", "https://www.taskhive.com/")),
         cand("taskhive.net")),
    ]
    res = {r.domain: r for r in score_all(s, items)}
    assert res["taskhive.com"].classification is C.OWNED
    assert res["taskhive.net"].classification is C.OWNED
    assert "redirect" in kinds(res["taskhive.net"])


def test_namespace_and_spf_under_seed():
    r = scorer().score(
        fp("tlco.com", ns=["ns1.zdp.com", "ns2.zdp.com"], spf_includes=["_spf.zdp.com"], soa_rname="hostmaster.zdp.com"),
        cand("tlco.com"), set())
    assert r.classification is C.OWNED
    assert {"namespace", "spf_seed", "soa_rname"} <= kinds(r)


def test_brand_named_registrant_is_not_a_conflict():
    # "ZDP, Inc." / "ZDP France" are ZDP's own short names; "Groupe ZDP" is not.
    r = scorer().score(
        fp("rhpro-entreprises.fr", ns=sorted(ZDP_NS), soa_rname="hostmaster.zdp.com",
           rdap=rdap(org="ZDP France", registrar="CSC", region="", country="FR")),
        cand("rhpro-entreprises.fr"), set())
    assert r.classification is C.OWNED and "brand_org" in kinds(r)
    r2 = scorer().score(fp("zdp-plaisance.fr", rdap=rdap(org="Groupe ZDP", region="", country="FR")),
                        cand("zdp-plaisance.fr"), set())
    assert "different_org_rdap" in kinds(r2) and r2.classification is C.REJECTED


def test_held_domain_with_past_seed_certificates_is_review():
    # Expired certificates show past control, not present control.
    ct = {"perkscape.com": CtOrgHit(org=ORG, count=4, latest_not_after="2019-03-12", current=False)}
    r = scorer(ct_org_domains=ct).score(
        fp("perkscape.com", a=["15.197.70.98"], rdap=rdap()), cand("perkscape.com"), set())
    assert r.classification is C.REVIEW and r.status == "held/inactive"


def test_held_domain_with_a_current_seed_certificate_is_owned():
    # A certificate valid today, issued to the organization for this name: the
    # organization proved control of the domain to the CA recently.
    ct = {"shineupnow.com": CtOrgHit(org=ORG, count=2, latest_not_after="2099-03-13", current=True)}
    r = scorer(ct_org_domains=ct).score(
        fp("shineupnow.com", a=["15.197.70.98"], rdap=rdap()), cand("shineupnow.com"), set())
    assert r.classification is C.OWNED


def test_held_brand_domain_with_other_region_goes_to_review():
    r = scorer().score(fp("zdpventures.com", a=["15.197.70.98"], ns=["ns1.markmonitor.com"],
                          rdap=rdap(region="CA", org="DNStination Inc.")),
                       cand("zdpventures.com"), set())
    assert r.classification is C.REVIEW and "held_brand_registrar" in kinds(r)


def test_markmonitor_zone_nameservers_mark_a_held_domain():
    r = scorer().score(fp("thoughtleaderco.com", ns=["ha1.markmonitor.zone", "ha2.markmonitor.zone"], rdap=rdap()),
                       cand("thoughtleaderco.com"), set())
    assert r.status == "held/inactive" and r.classification is C.REVIEW


def test_registrar_named_as_registrant_is_a_proxy_not_an_owner():
    # CSC writes its own name and Delaware address into the registrant fields.
    csc = dict(registrar="CSC Corporate Domains, Inc.", iana="299", region="DE",
               org="CSC Corporate Domains, Inc.")
    prof = SeedProfile.build(fp("paynetic.com", rdap=rdap(**csc)), ["Paynetic Inc."], ["paynetic"])
    s = Scorer(prof)
    r = s.score(fp("cscglobal.com", rdap=rdap(**csc)), cand("cscglobal.com"), set())
    assert "rdap_org" not in kinds(r) and "different_org_rdap" not in kinds(r)
    assert "proxy_registrant" in kinds(r) and "registrar_region" not in kinds(r)
    assert r.classification is C.REJECTED


def test_proxy_names_never_become_seed_org_names():
    from domainfinder.pipeline import derive_org_names

    seed = fp("paynetic.com", rdap=rdap(registrar="CSC Corporate Domains, Inc.", org="CSC Corporate Domains, Inc."))
    assert derive_org_names(seed, ["Paynetic"], [], "paynetic") == ["Paynetic"]


def test_branded_domain_linked_from_seed_site_goes_to_review():
    r = scorer().score(fp("zdpathletics.com"), cand("zdpathletics.com", "seed-links"), set())
    assert r.classification is C.REVIEW and "seed_link_brand" in kinds(r)
    r2 = scorer().score(fp("jotform.com"), cand("jotform.com", "seed-links"), set())
    assert r2.classification is C.REJECTED


def test_managed_web_host_netblock_is_not_ownership():
    from domainfinder.models import Netblock

    s = SeedProfile.build(seed_fp(), [ORG], ["zdp"])
    pantheon = Netblock(handle="P", name="PANTHEON-IP4", start="23.185.0.0", end="23.185.0.255", org="Pantheon")
    s.fp.netblocks = [pantheon]
    s = SeedProfile.build(s.fp, [ORG], ["zdp"])
    r = Scorer(s).score(fp("someotheruni.edu", a=["23.185.0.3"], netblocks=[pantheon]), cand("someotheruni.edu"), set())
    assert "netblock" not in kinds(r)


def test_strong_evidence_with_a_conflicting_name_goes_to_review():
    """docflow.com: current CT cert names the parent, the live cert still says DocFlow."""
    from domainfinder.models import CertInfo

    ct = {"docflow.com": CtOrgHit(org=ORG, count=3, latest_not_after="2027-03-14", current=True)}
    r = scorer(ct_org_domains=ct).score(
        fp("docflow.com", rdap=rdap(), cert=CertInfo(fetched=True, subject_org="DocFlow, INC")),
        cand("docflow.com"), set())
    assert {"ct_org_current", "different_org_cert"} <= kinds(r)
    assert r.classification is C.REVIEW and r.score >= 40
    # Without any strong evidence, a conflicting name still means rejection.
    r2 = scorer().score(fp("oakline.net", rdap=rdap(org="Oakline Technologies, Inc.", region="TX")),
                        cand("oakline.net"), set())
    assert r2.classification is C.REJECTED


def test_redirect_to_the_registrars_own_site_is_a_holding_signal():
    """oldsig.com: parked by MarkMonitor, redirecting to markmonitor.com."""
    r = scorer().score(
        fp("oldsig.com", rdap=rdap(region="CA"), web=web("http://oldsig.com/", "https://www.markmonitor.com/")),
        cand("oldsig.com"), set())
    assert "foreign_redirect" not in kinds(r) and "registrar_redirect" in kinds(r)
    assert r.status == "held/inactive"
    # A mass-market registrar's own site: neutral, but not "held".
    r2 = scorer().score(
        fp("someone.com", rdap=rdap(registrar="GoDaddy.com, LLC", iana="146", region="AZ"),
           web=web("http://someone.com/", "https://www.godaddy.com/forsale")),
        cand("someone.com"), set())
    assert "foreign_redirect" not in kinds(r2) and r2.status != "held/inactive"
    # Any other unrelated site is still a foreign redirect.
    r3 = scorer().score(fp("zdp.fr", rdap=rdap(registrar="CSC Corporate Domains, Inc.", iana="299", region=""),
                           web=web("http://zdp.fr/", "https://www.plaisance-zone.fr/")), cand("zdp.fr"), set())
    assert "foreign_redirect" in kinds(r3)


def test_shared_nameserver_domain_gives_no_namespace_or_dedicated_ns_evidence():
    """oraclecloud.net runs a public DNS service: 'nameservers under oraclecloud.net' proves nothing."""
    s = SeedProfile.build(seed_fp(), [ORG], ["zdp"])
    s.fp.ns = ["ns1.p201.dns.oraclecloud.net", "ns2.p201.dns.oraclecloud.net"]
    cust = fp("customer.com", ns=["ns1.p201.dns.oraclecloud.net", "ns2.p201.dns.oraclecloud.net"])
    plain = Scorer(s).score(cust, cand("customer.com"), {"oraclecloud.net"})
    assert "namespace" in kinds(plain) or "ns_set" in kinds(plain)  # without the knowledge: a false link
    aware = Scorer(s, shared_ns_domains={"oraclecloud.net"}).score(cust, cand("customer.com"), {"oraclecloud.net"})
    assert not {"namespace", "ns_set"} & kinds(aware)
    assert aware.classification is C.REJECTED
