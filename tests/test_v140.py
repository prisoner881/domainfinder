"""1.4.0: evidence channels. Repeats of one underlying fact are discounted;
independent channels add up and their agreement earns a bonus."""

from helpers import ZDP_MX, ZDP_NS, CORENET, cand, fp, rdap, seed_fp

from domainfinder.models import Classification as C
from domainfinder.models import Evidence, Strength
from domainfinder.verify import CHANNELS, Scorer, SeedProfile, channel_of

ORG = "Zyntara Data Processing, Inc."


def scorer(seed=None):
    return Scorer(SeedProfile.build(seed or seed_fp(), [ORG], ["zdp"]), 70, 40)


def pts(r):
    return {e.kind: e.points for e in r.evidence}


def test_every_kind_is_in_at_most_one_channel():
    seen = [k for kinds in CHANNELS.values() for k in kinds]
    assert len(seen) == len(set(seen))
    assert channel_of("ns_set") == "delegation" and channel_of("soa_rname") == "zone"
    assert channel_of("something_new") == "something_new"  # unknown kinds stand alone


def test_points_still_add_up_to_the_score():
    r = scorer().score(fp("x-zdp.com", ns=sorted(ZDP_NS), soa_rname="hostmaster.zdp.com"), cand("x-zdp.com"), set())
    assert r.score == sum(e.points for e in r.evidence) < 100


def test_one_mail_setup_counts_once():
    # The seed's small, dedicated mail host also serves its other customers:
    # the shared MX and the host's SPF include are one fact, not two.
    seed = seed_fp()
    seed.mx, seed.mail_tenants, seed.spf_includes = ["mx1.smallmailhost-example.net"], [], ["_spf.smallmailhost-example.net"]
    other = fp("zdpartners-example.com", mx=["mx1.smallmailhost-example.net"],
               spf_includes=["_spf.smallmailhost-example.net"])
    r = scorer(seed).score(other, cand("zdpartners-example.com"), set())
    p = pts(r)
    assert p["mx_host"] == 45 and p["spf_shared"] == 10  # 20, half counted
    assert "more mail evidence: 50% counted" in next(e.detail for e in r.evidence if e.kind == "spf_shared")
    assert r.score == 60 and r.classification is C.REVIEW  # was 70 and owned when the points simply added up


def test_one_whois_record_counts_once():
    held = rdap(org=ORG)
    held.contacts = [{"role": "registrant", "phone": "15555550123", "street": "one zdp blvd riverton 08077"}]
    seed = seed_fp()
    seed.rdap.contacts = [{"role": "registrant", "phone": "15555550123", "street": "one zdp blvd riverton 08077"}]
    r = scorer(seed).score(fp("zdp-example.com", rdap=held), cand("zdp-example.com"), set())
    p = pts(r)
    assert p["rdap_org"] == 60
    assert sorted([p["whois_phone"], p["whois_street"], p["registrar_region"]]) == [2, 6, 12]


def test_independent_channels_agree_and_earn_a_bonus():
    r = scorer().score(fp("acquired-example.com", ns=sorted(ZDP_NS), mail_tenants=["proofpoint:0099aa01"],
                          a=["198.18.1.1"], netblocks=[CORENET]), cand("acquired-example.com"), set())
    bonus = next(e for e in r.evidence if e.kind == "corroboration")
    assert bonus.points == 10 and "(delegation, hosting, mail)" in bonus.detail
    assert r.classification is C.OWNED


def test_one_channel_or_the_name_alone_earns_no_bonus():
    r = scorer().score(fp("zdp-example.com", ns=sorted(ZDP_NS)), cand("zdp-example.com"), set())
    assert "corroboration" not in pts(r)


def test_bonus_is_capped():
    r = scorer().score(fp("x-example.com", ns=sorted(ZDP_NS), mail_tenants=["proofpoint:0099aa01"],
                          a=["198.18.1.1"], netblocks=[CORENET], verification_tokens=["MS=ms12345678"],
                          soa_rname="hostmaster.zdp.com", rdap=rdap(org=ORG)), cand("x-example.com"), set())
    assert pts(r)["corroboration"] == 15


def test_namespace_evidence_is_split_by_record():
    r = scorer().score(fp("y-example.com", ns=["ns1.zdp.com", "ns2.zdp.com"], mx=["mail.zdp.com"],
                          www_cname=["www.zdp.com"]), cand("y-example.com"), set())
    p = pts(r)
    assert {"namespace", "namespace_mx", "namespace_www"} <= set(p)
    assert p["namespace"] == p["namespace_mx"] == p["namespace_www"] == 50  # three channels, none discounted


def test_two_matches_in_one_channel_do_not_override_another_registrant():
    # The mail tenant and an MX host under the seed are one mail setup: not the
    # two independent infrastructure matches that excuse a different registrant.
    other = fp("z-example.com", mx=["mail.zdp.com", *ZDP_MX], mail_tenants=["proofpoint:0099aa01"],
               rdap=rdap(org="Payroll Partners LLC", registrar="GoDaddy", region="FL", iana="146"))
    r = scorer().score(other, cand("z-example.com"), set())
    assert {"mail_tenant", "namespace_mx"} <= set(pts(r)) and r.classification is C.REVIEW


def test_source_hints_are_not_discounted_twice_across_rounds():
    hint = Evidence("whois_org", Strength.STRONG, 60, "WhoisXML: registrant organization " + ORG)
    c = cand("w-example.com")
    c.hints = [hint]
    s = scorer()
    f = fp("w-example.com", rdap=rdap(org=ORG))
    first, second = s.score(f, c, set()), s.score(f, c, set())
    assert hint.points == 60 and first.score == second.score
