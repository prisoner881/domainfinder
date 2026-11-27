"""1.5.2: registrar RDAP lookups that fail (rate limits) get a slower second
try before scoring; RDAP hosts get gentler default pacing; 3000 candidates."""

import httpx
import respx

from domainfinder.collectors.rdap import RdapClient
from domainfinder.http import RDAP_LIMIT, Http

REGISTRANT = {"objectClassName": "domain", "ldhName": "X-ZDP.COM", "entities": [
    {"roles": ["registrant"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                                         ["email", {}, "text", "dns@zdp.com"]]]}]}


@respx.mock
async def test_failed_registrar_lookup_is_retried_and_completes_the_same_record():
    respx.get("https://data.iana.org/rdap/dns.json").respond(
        json={"services": [[["com"], ["https://rdap.verisign.com/com/v1/"]]]})
    respx.get("https://rdap.verisign.com/com/v1/domain/x-zdp.com").respond(json={
        "objectClassName": "domain", "ldhName": "X-ZDP.COM",
        "links": [{"rel": "related", "href": "https://rdap.registrar.example/domain/X-ZDP.COM"}]})
    reg = respx.get("https://rdap.registrar.example/domain/X-ZDP.COM").mock(
        side_effect=[httpx.Response(503), httpx.Response(200, json=REGISTRANT)])
    http = Http(retries=1)
    c = RdapClient(http)
    info = await c.domain("x-zdp.com")
    assert info.contacts == [] and c.registrar_failures == {"rdap.registrar.example": 1}
    assert await c.retry_failed(spacing=0) == 1
    assert info.contacts == [{"role": "registrant", "email": "dns@zdp.com"}]  # the fingerprint's own object
    assert not c.registrar_failures and reg.call_count == 2
    assert await c.retry_failed(spacing=0) == 0  # nothing left to retry
    await http.aclose()


def test_rdap_hosts_get_gentler_pacing_and_the_candidate_cap_is_3000():
    import inspect

    from domainfinder import pipeline

    gate = Http()._gate("rdap.registrar.example")
    assert (gate.sem._value, gate.interval) == RDAP_LIMIT
    assert inspect.signature(pipeline.run).parameters["max_candidates"].default == 3000


def test_review_notes_appear_in_csv_and_table():
    from helpers import cand, fp, rdap, seed_fp

    from domainfinder.models import CertInfo
    from domainfinder.verify import Scorer, SeedProfile

    seed = seed_fp()
    seed.spf_includes = ["_spf.zdp.com"]
    s = Scorer(SeedProfile.build(seed, ["Zyntara Data Processing, Inc."], ["zdp"]), 70, 40)
    client = fp("riverbendcu.org", spf_includes=["_spf.zdp.com"],
                cert=CertInfo(fetched=True, subject_org="Zyntara Data Processing, Inc.", has_scts=True),
                rdap=rdap(registrar="GoDaddy.com, LLC", iana="146", region="ARIZONA"))
    r = s.score(client, cand("riverbendcu.org"), set())
    from domainfinder.models import CAP_NOTES

    note = next(e.detail for e in r.evidence if e.kind in CAP_NOTES)
    assert r.summary().startswith(note)

    import csv
    import io

    from domainfinder import report

    class Rep:  # the minimum RunReport surface report.to_csv uses
        seed, root_check, results = "zdp.com", None, [r]

        def by_class(self, cls):
            return [x for x in self.results if x.classification is cls]

        def parent_warning(self):
            return ""

    out = report.to_csv(Rep(), include_rejected=True)
    row = next(x for x in csv.DictReader(io.StringIO(out.lstrip("\\ufeff"))) if x["domain"] == "riverbendcu.org")
    assert row["evidence"].endswith("review: " + note)
