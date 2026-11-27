"""1.3.0: "owned" needs evidence of control; WHOIS/RDAP contact data points."""

from helpers import ADP_NS, cand, fp, rdap, seed_fp

from domainfinder.collectors.rdap import parse_domain, vcard_fields
from domainfinder.collectors.whois import parse_educause
from domainfinder.contacts import norm_email, norm_phone, norm_street
from domainfinder.models import Classification as C
from domainfinder.models import RdapInfo
from domainfinder.verify import CONTROL_KINDS, Scorer, SeedProfile

ORG = "Automatic Data Processing, Inc."
HELD = dict(a=["15.197.70.98"], ns=["ns1.markmonitor.com", "ns2.markmonitor.com"])


def scorer(seed=None):
    return Scorer(SeedProfile.build(seed or seed_fp(), [ORG], ["adp"]))


def kinds(r):
    return {e.kind for e in r.evidence}


# --- the control rule -----------------------------------------------------------------------

def test_registration_similarity_alone_stops_at_review():
    r = scorer().score(fp("adp.cloud", rdap=rdap(), **HELD), cand("adp.cloud"), set())
    assert r.score == 65 and r.classification is C.REVIEW and "registration_only" in kinds(r)


def test_any_control_signal_makes_the_same_domain_owned():
    # Held at MarkMonitor/NJ with the brand, plus a redirect into the seed's site.
    from helpers import web

    r = scorer().score(fp("adp.company", rdap=rdap(), web=web("http://adp.company/", "https://www.adp.com/"), **HELD),
                       cand("adp.company"), set())
    assert r.classification is C.OWNED and "registration_only" not in kinds(r)


def test_dns_zone_run_by_the_seed_is_owned_without_any_registration_data():
    r = scorer().score(fp("adp.lk", ns=sorted(ADP_NS), soa_rname="hostmaster.adp.com"), cand("adp.lk"), set())
    assert r.classification is C.OWNED


def test_control_kinds_exclude_paperwork():
    for paperwork in ("registrar_region", "held_brand", "held", "ct_org_historic", "brand_label", "subsidiary",
                      "spf_seed", "csp_trust", "whois_phone", "whois_street", "whois_email_same"):
        assert paperwork not in CONTROL_KINDS
    for control in ("ns_set", "mail_tenant", "netblock", "token", "cert_link", "cert_org", "ct_org_current",
                    "redirect", "rdap_org", "whois_org", "whois_email"):
        assert control in CONTROL_KINDS


# --- normalization ---------------------------------------------------------------------------

def test_contact_values_normalize_and_placeholders_drop():
    assert norm_email("mailto:DNS-Admin@ADP.com") == "dns-admin@adp.com"
    assert norm_email("REDACTED FOR PRIVACY") is None
    assert norm_email("https://domains.markmonitor.com/whois/contact/adp.cloud") is None
    assert norm_phone("tel:+1.973-974-5000;ext=12") == "19739745000"
    assert norm_phone("REDACTED FOR PRIVACY") is None and norm_phone("+1.555") is None
    assert norm_street(["One ADP Blvd."], "Roseland", "07068") == "one adp blvd roseland 07068"
    assert norm_street("REDACTED FOR PRIVACY", "REDACTED", "") is None
    assert norm_street("One ADP Blvd", "", "") is None  # a street alone is too vague


# --- RDAP parsing ----------------------------------------------------------------------------

def jcard(*props):
    return ["vcard", [["version", {}, "text", "4.0"], *props]]


def rdap_doc(*entities):
    return {"objectClassName": "domain", "entities": list(entities)}


REGISTRANT = {"roles": ["registrant"], "vcardArray": jcard(
    ["fn", {}, "text", "Domain Administrator"], ["org", {}, "text", ORG],
    ["adr", {"cc": "US"}, "text", ["", "", "One ADP Blvd", "Roseland", "NJ", "07068", ""]],
    ["tel", {"type": "voice"}, "uri", "tel:+1.9739745000"], ["email", {}, "text", "dnsadmin@adp.com"])}
REGISTRAR = {"roles": ["registrar"], "vcardArray": jcard(
    ["fn", {}, "text", "Markmonitor Inc."],
    ["adr", {}, "text", ["", "", "3540 E Longwing Ln", "Meridian", "ID", "83646", ""]]),
    "entities": [{"roles": ["abuse"], "vcardArray": jcard(
        ["fn", {}, "text", "Markmonitor Inc."], ["tel", {}, "uri", "tel:+1.2086851750"],
        ["email", {}, "text", "abusecomplaints@markmonitor.com"])}]}
TECH_REDACTED = {"roles": ["technical"], "vcardArray": jcard(
    ["fn", {}, "text", "REDACTED FOR PRIVACY"], ["email", {}, "text", "REDACTED FOR PRIVACY"],
    ["tel", {}, "text", "REDACTED FOR PRIVACY"])}
PROXY = {"roles": ["administrative"], "vcardArray": jcard(
    ["fn", {}, "text", "Domains By Proxy, LLC"], ["email", {}, "text", "example.com@domainsbyproxy.com"],
    ["tel", {}, "uri", "tel:+1.4806242599"])}


def test_rdap_contacts_are_collected_and_registrar_data_kept_apart():
    info = RdapInfo()
    parse_domain(rdap_doc(REGISTRANT, REGISTRAR, TECH_REDACTED, PROXY), info, "test")
    assert info.contacts == [{"role": "registrant", "email": "dnsadmin@adp.com", "phone": "19739745000",
                              "street": "one adp blvd roseland 07068"}]
    # the registrar's (and its abuse desk's) data is recorded only to be excluded
    assert "12086851750" in info.registrar_contacts and "abusecomplaints@markmonitor.com" in info.registrar_contacts
    assert info.registrant_region == "NJ"  # existing fields unaffected


def test_vcard_fields_tolerates_odd_values():
    v = vcard_fields({"vcardArray": jcard(["email", {}, "text", 42], ["tel", {}, "text", None],
                                          ["adr", {}, "text", "not a list"])})
    assert v["emails"] == [] and v["tels"] == [] and v["streets"] == []


# --- .edu WHOIS ------------------------------------------------------------------------------

EDU = """Domain Name: RMU.EDU

Registrant:
\tRobert Morris University
\t6001 University Boulevard
\tMoon Township, PA 15108
\tUSA

Administrative Contact:
\tIT Services
\tRobert Morris University
\t6001 University Boulevard
\tMoon Township, PA 15108
\tUSA
\t+1.4123973000
\tdomains@rmu.edu

Technical Contact:
\tNetwork Operations
\t+1.4123973001
\tnoc@rmu.edu
"""


def test_educause_contacts():
    info = RdapInfo()
    assert parse_educause(EDU, info)
    by_role = {c["role"]: c for c in info.contacts}
    assert by_role["registrant"]["street"] == "6001 university boulevard moon township pa 15108"
    assert by_role["administrative"] == {"role": "administrative", "email": "domains@rmu.edu", "phone": "14123973000"}
    assert by_role["technical"]["email"] == "noc@rmu.edu"


# --- scoring ---------------------------------------------------------------------------------

def with_contacts(info, *contacts, registrar_contacts=()):
    info.contacts = list(contacts)
    info.registrar_contacts = list(registrar_contacts)
    return info


def test_contact_email_at_the_seed_is_strong_control_evidence():
    held = fp("workscape.com", rdap=with_contacts(rdap(), {"role": "registrant", "email": "dnsadmin@adp.com"}), **HELD)
    r = scorer().score(held, cand("workscape.com"), set())
    assert "whois_email" in kinds(r) and r.classification is C.OWNED
    detail = next(e.detail for e in r.evidence if e.kind == "whois_email")
    assert detail == "WHOIS registrant contact email is at adp.com" and "dnsadmin" not in detail


def test_contact_email_at_a_verified_domain_counts_too():
    c = {"role": "technical", "email": "hostmaster@workmarket.com"}
    r = scorer().score(fp("wm.solutions", rdap=with_contacts(rdap(), c), **HELD), cand("wm.solutions"), {"workmarket.com"})
    assert "whois_email" in kinds(r)


def test_contact_email_at_the_domain_itself_or_the_registrar_proves_nothing():
    own = {"role": "registrant", "email": "admin@example-brand.com"}
    reg = {"role": "technical", "email": "ccops@markmonitor.com"}
    r = scorer().score(fp("example-brand.com", rdap=with_contacts(rdap(), own, reg, registrar_contacts=["ccops@markmonitor.com"])),
                       cand("example-brand.com"), set())
    assert "whois_email" not in kinds(r)


def seed_with(*contacts, registrar_contacts=()):
    s = seed_fp()
    with_contacts(s.rdap, *contacts, registrar_contacts=registrar_contacts)
    return s


SEED_REGISTRANT = {"role": "registrant", "email": "domains@adp-legal.example", "phone": "19739745000",
                   "street": "one adp blvd roseland 07068"}


def test_same_phone_and_street_as_the_seed_support_but_never_prove():
    c = {"role": "administrative", "phone": "19739745000", "street": "one adp blvd roseland 07068"}
    r = scorer(seed_with(SEED_REGISTRANT)).score(fp("vesalute.com", rdap=with_contacts(rdap(), c), **HELD),
                                                 cand("vesalute.com"), set())
    assert {"whois_phone", "whois_street"} <= kinds(r)
    assert r.classification is C.REVIEW  # medium evidence on a held domain: still no control
    assert all("19739745000" not in e.detail and "roseland" not in e.detail for e in r.evidence)


def test_same_contact_email_off_the_seed_domain_is_medium():
    c = {"role": "registrant", "email": "domains@adp-legal.example"}
    r = scorer(seed_with(SEED_REGISTRANT)).score(fp("x-brand.com", rdap=with_contacts(rdap(), c)), cand("x-brand.com"), set())
    e = next(e for e in r.evidence if e.kind == "whois_email_same")
    assert e.strength.value == "medium" and e.points == 25


def test_registrar_phone_and_technical_contacts_never_match_the_seed():
    shared = "12083895740"  # e.g. the registrar's tech desk, on every customer's record
    seed = seed_with({"role": "registrant", "phone": shared}, registrar_contacts=[shared])
    c = [{"role": "registrant", "phone": shared}, {"role": "technical", "phone": "19739745000"}]
    seed.rdap.contacts.append({"role": "technical", "phone": "19739745000"})
    r = scorer(seed).score(fp("unrelated.com", rdap=with_contacts(rdap(), *c)), cand("unrelated.com"), set())
    assert "whois_phone" not in kinds(r)
