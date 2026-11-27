"""1.6.0: registrars that rate limit are left alone (across runs); registrar
lookups only where they can change a result; failures say why; WHOIS
fallback; attested domains."""

import json
import time

import httpx
import respx
from helpers import cand, fp, rdap, seed_fp, web

from domainfinder import pipeline
from domainfinder.cache import CACHE_FILE, Cache
from domainfinder.collectors.rdap import RdapClient, retry_after_seconds
from domainfinder.collectors.whois import parse_icann_whois, registrar_whois
from domainfinder.config import Settings
from domainfinder.http import Http, Response
from domainfinder.models import Classification as C
from domainfinder.models import Evidence, Fingerprint, RdapInfo, Result, Strength, WebInfo
from domainfinder.verify import Scorer, SeedProfile, score_all

ORG = "Zyntara Data Processing, Inc."
REG = "https://rdap.registrar.example/domain/"
FULL = lambda d: {"objectClassName": "domain", "ldhName": d.upper(), "entities": [  # noqa: E731
    {"roles": ["registrant"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                                         ["email", {}, "text", "dns@zdp.com"]]]}]}
LIMITED = {"errorCode": "429", "description": ["Too many requests! Please retry after 24 hours!"]}


def registry(domains):
    respx.get("https://data.iana.org/rdap/dns.json").respond(
        json={"services": [[["com"], ["https://rdap.verisign.com/com/v1/"]]]})
    for d in domains:
        respx.get(f"https://rdap.verisign.com/com/v1/domain/{d}").respond(json={
            "objectClassName": "domain", "ldhName": d.upper(),
            "links": [{"rel": "related", "href": REG + d.upper()}]})


# --- back off when a registrar says stop ---------------------------------------------------

def test_retry_after_parsing():
    assert retry_after_seconds(Response(429, "u", headers={"retry-after": "120"})) == 120
    assert retry_after_seconds(Response(429, "u", text=json.dumps(LIMITED))) == 86400
    assert retry_after_seconds(Response(429, "u")) == 3600
    assert retry_after_seconds(Response(429, "u", headers={"retry-after": "5"})) == 60  # at least a minute


@respx.mock
async def test_a_429_stops_all_lookups_at_that_registrar_and_is_remembered(tmp_path):
    registry(["a-zdp.com", "b-zdp.com", "c-zdp.com"])
    route = respx.get(url__startswith=REG).respond(429, json=LIMITED)
    cache = Cache(tmp_path / CACHE_FILE, 3600)
    http = Http(cache=cache)
    c = RdapClient(http)
    for d in ("a-zdp.com", "b-zdp.com", "c-zdp.com"):
        await c.domain(d)
    assert route.call_count == 1  # the first 429 ends the asking
    assert c.failure_reasons[("rdap.registrar.example", "HTTP 429 (rate limited)")] == 1
    assert c.failure_reasons[("rdap.registrar.example", "backing off (rate limited)")] == 2
    until = c.cooldowns()["rdap.registrar.example"]
    assert 86000 < until - time.time() <= 86400
    assert await c.retry_failed(spacing=0) == 0 and route.call_count == 1  # no second try while backing off
    # A later run (new client, same cache file) does not ask either.
    c2 = RdapClient(Http(cache=cache))
    await c2.domain("a-zdp.com")
    assert route.call_count == 1 and "rdap.registrar.example" in c2.cooldowns()
    await http.aclose()


@respx.mock
async def test_while_backing_off_a_cached_registrar_answer_is_still_used(tmp_path):
    registry(["a-zdp.com"])
    cache = Cache(tmp_path / CACHE_FILE, 3600)
    cache.set("GET " + REG + "A-ZDP.COM", {"status": 200, "url": REG + "A-ZDP.COM", "text": json.dumps(FULL("a-zdp.com")),
                                         "headers": {}})
    cache.set("registrar-cooldown rdap.registrar.example", {"until": time.time() + 3600})
    route = respx.get(url__startswith=REG).respond(200, json=FULL("x"))
    c = RdapClient(Http(cache=cache))
    info = await c.domain("a-zdp.com")
    assert info.contacts == [{"role": "registrant", "email": "dns@zdp.com"}] and route.call_count == 0


@respx.mock
async def test_whois_fallback_completes_what_the_registrar_refused(tmp_path, monkeypatch):
    registry(["a-zdp.com"])
    respx.get(url__startswith=REG).respond(429, json=LIMITED)

    async def fake_whois(domain, cache):
        info = RdapInfo(available=True)
        parse_icann_whois("Registrant Organization: Zyntara Data Processing, Inc.\n"
                          "Registrant Email: hostmaster@zdp.com\n", info, "whois.registrar.example")
        return info

    import domainfinder.collectors.whois as whois_mod

    monkeypatch.setattr(whois_mod, "registrar_whois", fake_whois)
    c = RdapClient(Http(cache=Cache(tmp_path / CACHE_FILE, 3600)))
    c.whois_fallback = True
    info = await c.domain("a-zdp.com")
    assert info.registrant_org == ""
    assert await c.retry_failed(spacing=0) == 1
    assert info.registrant_org == ORG and info.contacts[0]["email"] == "hostmaster@zdp.com"
    assert c.whois_recovered == 1 and not c.registrar_failures


# --- fewer registrar lookups ------------------------------------------------------------------

@respx.mock
async def test_deferred_registrar_lookups_are_made_only_on_request(tmp_path):
    registry(["a-zdp.com", "b-zdp.com"])
    route = respx.get(url__startswith=REG).mock(side_effect=lambda req: httpx.Response(200, json=FULL("x")))
    c = RdapClient(Http(cache=Cache(tmp_path / CACHE_FILE, 3600)))
    c.defer_registrar = True
    a, b = await c.domain("a-zdp.com"), await c.domain("b-zdp.com")
    assert route.call_count == 0 and c.deferred() == {"a-zdp.com", "b-zdp.com"}
    assert await c.fetch_deferred({"a-zdp.com"}, spacing=0) == 1
    assert route.call_count == 1 and a.contacts and not b.contacts and c.deferred() == {"b-zdp.com"}


def res(domain, cls, kinds_strengths, status="active (HTTP 200)"):
    ev = [Evidence(k, s, 50 if s is Strength.STRONG else 5, k) for k, s in kinds_strengths]
    return Result(domain, 0, cls, status, ev, {}, None)


def test_which_domains_need_the_registrar():
    S, W = Strength.STRONG, Strength.WEAK
    settled = res("a.com", C.OWNED, [("ns_set", S), ("mail_tenant", S)])
    name_only = res("b.com", C.REJECTED, [("brand_label", W)])
    redirect = res("c.com", C.REVIEW, [("redirect", S), ("brand_label", W)])
    held = res("d.com", C.REJECTED, [("brand_label", W)], status="held/inactive")
    one_channel = res("e.com", C.OWNED, [("ns_set", S), ("soa_rname", Strength.MEDIUM)])
    assert [pipeline.needs_registrar(r) for r in (settled, name_only, redirect, held, one_channel)] == \
        [False, False, True, True, True]


def test_registrar_note_says_why_and_until_when():
    c = RdapClient(Http())
    c.registrar_lookups = 12
    c.failure_reasons[("rdap.registrar.example", "HTTP 429 (rate limited)")] = 1
    c.failure_reasons[("rdap.registrar.example", "backing off (rate limited)")] = 4
    c._cool["rdap.registrar.example"] = time.time() + 3600
    c._deferred = {"x.com": ("u", RdapInfo())}
    note = pipeline.registrar_note(c)
    assert note.startswith("rdap: 12 registrar lookup(s) made, 1 not needed")
    assert "rdap.registrar.example (backing off (rate limited) ×4, HTTP 429 (rate limited) ×1)" in note
    assert "backing off: rdap.registrar.example until " in note


# --- WHOIS ----------------------------------------------------------------------------------

REGISTRAR_WHOIS = """Domain Name: A-ZDP.COM
Registrar WHOIS Server: whois.registrar.example
Registrar: Example Registrar, LLC
Registrant Organization: Zyntara Data Processing, Inc.
Registrant Street: 1 Main St
Registrant City: Springfield
Registrant State/Province: OH
Registrant Postal Code: 45501
Registrant Country: US
Registrant Phone: +1.5555550123
Registrant Email: domains@zdp.com
Admin Organization: REDACTED FOR PRIVACY
Admin Email: REDACTED FOR PRIVACY
Tech Organization: Domains By Proxy, LLC
Tech Email: a-zdp.com@domainsbyproxy.com
Registrar Abuse Contact Email: abuse@registrar.example
Registrar Abuse Contact Phone: +1.5555550199
"""


def test_icann_whois_parsing():
    info = RdapInfo()
    assert parse_icann_whois(REGISTRAR_WHOIS, info, "whois.registrar.example")
    assert (info.registrant_org, info.registrant_region, info.registrant_country) == (ORG, "OH", "US")
    assert info.contacts == [{"role": "registrant", "email": "domains@zdp.com", "phone": "15555550123",
                              "street": "1 main st springfield 45501"}]  # redacted admin, proxy tech skipped
    assert "abuse@registrar.example" in info.registrar_contacts and "15555550199" in info.registrar_contacts
    assert not parse_icann_whois("No match for domain", RdapInfo(), "x")


async def test_registrar_whois_follows_the_registry_to_the_registrar(monkeypatch, tmp_path):
    import domainfinder.collectors.whois as whois_mod

    asked = []

    async def fake_query(server, query, cache, ttl=0, **kw):
        asked.append((server, query))
        if server == "whois.verisign-grs.com":
            return "Domain Name: A-ZDP.COM\nRegistrar WHOIS Server: whois.registrar.example\nRegistrar: Example Registrar\n"
        return REGISTRAR_WHOIS if server == "whois.registrar.example" else None

    monkeypatch.setattr(whois_mod, "whois_query", fake_query)
    info = await registrar_whois("a-zdp.com", Cache(tmp_path / CACHE_FILE, 3600))
    assert asked == [("whois.verisign-grs.com", "a-zdp.com"), ("whois.registrar.example", "a-zdp.com")]
    assert info.registrant_org == ORG and info.contacts[0]["email"] == "domains@zdp.com"


# --- attested domains -------------------------------------------------------------------------

def scorer(attested=(), anchors=()):
    s = Scorer(SeedProfile.build(seed_fp(), [ORG], ["zdp"]), 70, 40)
    s.attested, s.anchors = set(attested), list(anchors)
    return s


def kinds(r):
    return [e.kind for e in r.evidence]


def test_attested_domain_is_owned_whatever_the_evidence():
    r = scorer({"quiet-example.com"}).score(fp("quiet-example.com"), cand("quiet-example.com", "attested"), set())
    assert (r.classification, r.score) == (C.OWNED, 100) and kinds(r)[0] == "attested"
    assert "attested_warning" not in kinds(r)


def test_contradictions_become_warnings_not_reclassification():
    s = scorer({"gone-example.com", "sale-example.com", "other-example.com"})
    gone = s.score(fp("gone-example.com", registered=False), cand("gone-example.com"), set())
    sale = s.score(fp("sale-example.com", ns=["ns1.afternic.com"]), cand("sale-example.com"), set())
    other = s.score(fp("other-example.com", rdap=rdap(org="Unrelated Holdings LLC", registrar="GoDaddy", iana="146")),
                    cand("other-example.com"), set())
    for r, words in ((gone, "not registered"), (sale, "parked or offered for sale"), (other, "Unrelated Holdings LLC")):
        assert r.classification is C.OWNED
        assert any(e.kind == "attested_warning" and words in e.detail for e in r.evidence), r.evidence


def test_attested_domains_are_reference_points():
    acq = fp("acquired-example.com", ns=["ns1.acqdns-example.net", "ns2.acqdns-example.net"],
             mail_tenants=["proofpoint:00777a01"], verification_tokens=["MS=ms77777777"])
    sister = fp("sister-example.com", ns=["ns1.acqdns-example.net", "ns2.acqdns-example.net"],
                mail_tenants=["proofpoint:00777a01"])
    r = scorer({"acquired-example.com"}, [acq]).score(sister, cand("sister-example.com"), {"acquired-example.com"})
    details = [e.detail for e in r.evidence]
    assert any(d.startswith("same dedicated nameservers") and d.endswith("as attested acquired-example.com")
               for d in details)
    assert "same mail tenant proofpoint:00777a01 as attested acquired-example.com" in details
    assert r.classification is C.OWNED
    # Without the attested anchor, nothing links it.
    assert scorer().score(sister, cand("sister-example.com"), set()).classification is C.REJECTED


def test_links_to_attested_domains_count_from_the_first_round():
    s = scorer({"acquired-example.com"}, [fp("acquired-example.com")])
    items = [(fp("acquired-example.com"), cand("acquired-example.com", "attested")),
             (fp("old-brand-example.com", web=web("http://old-brand-example.com/", "https://acquired-example.com/"),
                 rdap=rdap()), cand("old-brand-example.com"))]
    by = {r.domain: r for r in score_all(s, items)}
    assert by["acquired-example.com"].classification is C.OWNED
    assert "redirects to acquired-example.com" in [e.detail for e in by["old-brand-example.com"].evidence]
    assert by["old-brand-example.com"].classification is C.OWNED


# --- pipeline end to end ----------------------------------------------------------------------

ACQ_NS = ["ns1.acqdns-example.net", "ns2.acqdns-example.net"]
FPS = {
    "zdp.com": seed_fp(),
    "acquired-example.com": Fingerprint(domain="acquired-example.com", brand_label="acquired-example", registered=True,
                                        ns=ACQ_NS, mail_tenants=["proofpoint:00777a01"],
                                        rdap=rdap(org="Acquired Example Corp", registrar="GoDaddy", iana="146"),
                                        web=WebInfo(fetched=True, status=200, chain=["https://acquired-example.com/"],
                                                    final_url="https://acquired-example.com/",
                                                    csp_domains=["vendor-cdn-example.net"])),
    "sister-example.com": fp("sister-example.com", ns=ACQ_NS, mail_tenants=["proofpoint:00777a01"]),
    "vendor-cdn-example.net": fp("vendor-cdn-example.net"),
}


async def fake_fp(domain, collectors, **kw):
    return FPS.get(domain) or fp(domain, registered=False)


async def no_org(*a, **kw):
    return []


async def test_pipeline_attested_end_to_end(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "fingerprint", fake_fp)
    monkeypatch.setattr(pipeline, "seed_org_from_ct", no_org)
    monkeypatch.setattr(pipeline, "ALL_SOURCES", [])
    rep = await pipeline.run("zdp.com", Settings(cache_dir=tmp_path, use_cache=False),
                             extra_candidates=["sister-example.com"],
                             attested=[("acquired-example.com", "attested.txt"), ("zdp.com", "attested.txt")])
    by = {r.domain: r for r in rep.results}
    assert by["acquired-example.com"].classification is C.OWNED
    assert by["acquired-example.com"].sources == {"attested": "attested by the organization (attested.txt)"}
    assert by["sister-example.com"].classification is C.OWNED  # through the attested domain's DNS and mail
    assert "vendor-cdn-example.net" not in by  # no discovery from attested-only domains
    assert any(n.startswith("attested: 1 domain(s)") and "Acquired Example Corp" in n for n in rep.notes)

    from domainfinder import report

    out = report.to_csv(rep)
    row = next(line for line in out.splitlines() if line.startswith("acquired-example.com,"))
    assert "attested by the organization" in row
