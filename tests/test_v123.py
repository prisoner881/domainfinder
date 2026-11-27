"""1.2.3: nameserver sets read from the domain's own nameservers when a resolver's answer only partly matches."""

import dns.flags
import dns.message
import dns.rrset
import pytest
from helpers import ADP_NS, cand, fp, rdap, seed_fp

from domainfinder import pipeline
from domainfinder.dns import DnsAnswer, Resolver
from domainfinder.verify import Scorer, SeedProfile

ORG = "Automatic Data Processing, Inc."
AKAMAI_ONLY = sorted(h for h in ADP_NS if h.endswith("akam.net"))  # what a registry's delegation may list


def test_partial_overlap_is_what_triggers_a_second_look():
    assert pipeline.ns_partial(AKAMAI_ONLY, ADP_NS)
    assert not pipeline.ns_partial(sorted(ADP_NS), ADP_NS)  # already the full set
    assert not pipeline.ns_partial(["ns1.other.net"], ADP_NS)  # nothing in common: not ours to fix
    assert not pipeline.ns_partial([], ADP_NS)


class FakeResolver:
    def __init__(self, answer):
        self.answer = answer
        self.asked = []

    async def authoritative_ns(self, domain, nameservers):
        self.asked.append((domain, list(nameservers)))
        return self.answer


async def test_authoritative_answer_replaces_a_partial_one():
    f = fp("adp.lk", ns=list(AKAMAI_ONLY))
    stats = {}
    r = FakeResolver(DnsAnswer("ok", list(ADP_NS)))
    await pipeline.refresh_ns(f, r, stats)
    assert f.ns == sorted(ADP_NS) and stats == {"checked": 1, "changed": 1}
    assert r.asked == [("adp.lk", AKAMAI_ONLY)]  # asked the domain's own nameservers


async def test_failed_second_look_keeps_what_the_resolver_said():
    f = fp("adp.lk", ns=list(AKAMAI_ONLY))
    stats = {}
    await pipeline.refresh_ns(f, FakeResolver(DnsAnswer("error", error="port 53 blocked")), stats)
    assert f.ns == AKAMAI_ONLY and stats == {"checked": 1}

    class Broken:
        async def authoritative_ns(self, *a):
            raise RuntimeError("boom")

    await pipeline.refresh_ns(f, Broken())  # never breaks the fingerprint
    await pipeline.refresh_ns(f, object())  # a resolver without the method is fine too
    assert f.ns == AKAMAI_ONLY


async def test_full_set_after_the_second_look_scores_as_the_same_set():
    scorer = Scorer(SeedProfile.build(seed_fp(), [ORG], ["adp"]))
    partial = fp("adpservices.cl", ns=list(AKAMAI_ONLY), soa_rname="hostmaster.adp.com", rdap=rdap())
    before = scorer.score(partial, cand("adpservices.cl"), set())
    await pipeline.refresh_ns(partial, FakeResolver(DnsAnswer("ok", list(ADP_NS))))
    after = scorer.score(partial, cand("adpservices.cl"), set())
    assert after.score > before.score
    assert any("10/10 hosts" in e.detail for e in after.evidence)


# --- the authoritative query itself --------------------------------------------------------------

def _response(domain, hosts, authoritative=True):
    q = dns.message.make_query(domain, "NS")
    resp = dns.message.make_response(q)
    resp.answer.append(dns.rrset.from_text(domain + ".", 300, "IN", "NS", *(h + "." for h in hosts)))
    if authoritative:
        resp.flags |= dns.flags.AA
    else:
        resp.flags &= ~dns.flags.AA
    return resp


@pytest.fixture
def resolver(monkeypatch):
    r = Resolver(http=None)

    async def fake_query(name, rtype):
        assert rtype == "A"
        return DnsAnswer("ok", {"a1-199.akam.net": ["193.108.91.199"], "a5-66.akam.net": ["95.100.168.66"]}
                         .get(name, []))

    monkeypatch.setattr(r, "query", fake_query)
    return r


async def test_authoritative_ns_accepts_only_authoritative_answers(resolver, monkeypatch):
    import dns.asyncquery

    sent = []

    async def fake_udp(q, ip, timeout=None):
        sent.append(ip)
        if ip == "193.108.91.199":
            return _response("adp.lk", AKAMAI_ONLY, authoritative=False), False  # a referral, not the zone
        return _response("adp.lk", ADP_NS), False

    monkeypatch.setattr(dns.asyncquery, "udp_with_fallback", fake_udp)
    ans = await resolver.authoritative_ns("adp.lk", ["a1-199.akam.net", "a5-66.akam.net"])
    assert ans.status == "ok" and ans.records == sorted(ADP_NS)
    assert sent == ["193.108.91.199", "95.100.168.66"]


async def test_authoritative_ns_reports_failure_when_no_server_answers(resolver, monkeypatch):
    import dns.asyncquery
    import dns.exception

    async def timeout(q, ip, timeout=None):
        raise dns.exception.Timeout()

    monkeypatch.setattr(dns.asyncquery, "udp_with_fallback", timeout)
    ans = await resolver.authoritative_ns("adp.lk", ["a1-199.akam.net", "nohost.example"])
    assert ans.status == "error" and "Timeout" in ans.error


async def test_authoritative_lookups_stop_when_direct_dns_is_blocked(resolver, monkeypatch):
    import dns.asyncquery

    calls = []

    async def blocked(q, ip, timeout=None):
        calls.append(ip)
        raise OSError("network unreachable")

    monkeypatch.setattr(dns.asyncquery, "udp_with_fallback", blocked)
    for i in range(8):
        await resolver.authoritative_ns(f"d{i}.lk", ["a1-199.akam.net"])
    assert len(calls) == 5  # five failures in a row, then no more waiting
