"""End to end with fingerprinting and sources faked: no network."""

import json

from helpers import ZDP_NS, cand, fp, rdap, seed_fp, web

from domainfinder import pipeline
from domainfinder.config import Settings
from domainfinder.models import Candidate, Classification
from domainfinder.report import to_csv, to_json
from domainfinder.sources.base import Source

FPS = {
    "zdp.com": seed_fp(),
    "myzdp.com": fp("myzdp.com", rdap=rdap(), web=web("http://myzdp.com/", "https://online.zdp.com/")),
    "staffnow.com": fp("staffnow.com", ns=sorted(ZDP_NS), mail_tenants=["proofpoint:0099aa01"]),
    "zdp.fr": fp("zdp.fr", rdap=rdap(org="Zone de Plaisance", registrar="CSC", region="", country="FR"),
                 web=web("http://zdp.fr/", "https://www.plaisance-zone.fr/")),
    "zdpvantage.com": fp("zdpvantage.com", rdap=rdap(), ns=["ns1.parkingcrew.net"]),
    "zdp.xn--vuq861b": fp("zdp.xn--vuq861b", ns=sorted(ZDP_NS), www_cname=["www.zdp.com"]),
}


class FakeSource(Source):
    name = "fake"

    async def candidates(self, ctx):
        return [Candidate(d, {"fake": ""}) for d in FPS if d != "zdp.com"]


async def fake_fingerprint(domain, collectors, **kw):
    return FPS.get(domain) or fp(domain, registered=False)


async def fake_ct_org(*a, **kw):
    return ["Zyntara Data Processing, Inc."]


async def test_run_end_to_end(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "fingerprint", fake_fingerprint)
    monkeypatch.setattr(pipeline, "seed_org_from_ct", fake_ct_org)
    monkeypatch.setattr(pipeline, "ALL_SOURCES", [FakeSource])
    s = Settings(cache_dir=tmp_path, use_cache=False)
    rep = await pipeline.run("www.zdp.com", s, extra_candidates=["zdpemployment.com"])
    assert rep.seed == "zdp.com"
    assert rep.org_names == ["Zyntara Data Processing, Inc."]
    owned = [r.domain for r in rep.by_class(Classification.OWNED)]
    review = [r.domain for r in rep.by_class(Classification.REVIEW)]
    rejected = [r.domain for r in rep.by_class(Classification.REJECTED)]
    assert sorted(owned) == ["myzdp.com", "staffnow.com", "zdp.xn--vuq861b"]
    assert review == ["zdpvantage.com"]
    assert sorted(rejected) == ["zdp.fr", "zdpemployment.com"]

    doc = json.loads(to_json(rep))
    assert [r["domain"] for r in doc["needs_review"]] == ["zdpvantage.com"]
    assert all(r["evidence"] for r in doc["owned"])
    csv_text = to_csv(rep)
    assert csv_text.splitlines()[0] == "domain,classification,score,status,sources,evidence,domain_ascii,domain_unicode,root_warning"
    assert "zdp.fr" not in csv_text  # rejected rows only with --verbose


async def test_idn_output_forms(monkeypatch, tmp_path):
    import csv
    import io

    monkeypatch.setattr(pipeline, "fingerprint", fake_fingerprint)
    monkeypatch.setattr(pipeline, "seed_org_from_ct", fake_ct_org)
    monkeypatch.setattr(pipeline, "ALL_SOURCES", [FakeSource])
    rep = await pipeline.run("zdp.com", Settings(cache_dir=tmp_path, use_cache=False))

    rows = {r["domain_ascii"]: r for r in csv.DictReader(io.StringIO(to_csv(rep)))}
    idn = rows["zdp.xn--vuq861b"]
    assert idn["domain"] == "zdp.信息" and idn["domain_unicode"] == "zdp.信息"
    rows_p = {r["domain_ascii"]: r for r in csv.DictReader(io.StringIO(to_csv(rep, idn="punycode")))}
    assert rows_p["zdp.xn--vuq861b"]["domain"] == "zdp.xn--vuq861b"
    assert rows_p["zdp.xn--vuq861b"]["domain_unicode"] == "zdp.信息"

    doc = json.loads(to_json(rep))
    entry = next(r for r in doc["owned"] if r["domain_ascii"] == "zdp.xn--vuq861b")
    assert entry["domain"] == "zdp.信息" and doc["idn_format"] == "unicode"
