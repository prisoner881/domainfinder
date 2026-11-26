"""End to end with fingerprinting and sources faked: no network."""

import json

from helpers import ADP_NS, cand, fp, rdap, seed_fp, web

from domainfinder import pipeline
from domainfinder.config import Settings
from domainfinder.models import Candidate, Classification
from domainfinder.report import to_csv, to_json
from domainfinder.sources.base import Source

FPS = {
    "adp.com": seed_fp(),
    "myadp.com": fp("myadp.com", rdap=rdap(), web=web("http://myadp.com/", "https://online.adp.com/")),
    "workforcenow.com": fp("workforcenow.com", ns=sorted(ADP_NS), mail_tenants=["proofpoint:0006eb01"]),
    "adp.fr": fp("adp.fr", rdap=rdap(org="Aeroports de Paris", registrar="CSC", region="", country="FR"),
                 web=web("http://adp.fr/", "https://www.parisaeroport.fr/")),
    "adpvantage.com": fp("adpvantage.com", rdap=rdap(), ns=["ns1.parkingcrew.net"]),
}


class FakeSource(Source):
    name = "fake"

    async def candidates(self, ctx):
        return [Candidate(d, {"fake": ""}) for d in FPS if d != "adp.com"]


async def fake_fingerprint(domain, collectors, **kw):
    return FPS.get(domain) or fp(domain, registered=False)


async def fake_ct_org(*a, **kw):
    return ["Automatic Data Processing, Inc."]


async def test_run_end_to_end(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "fingerprint", fake_fingerprint)
    monkeypatch.setattr(pipeline, "seed_org_from_ct", fake_ct_org)
    monkeypatch.setattr(pipeline, "ALL_SOURCES", [FakeSource])
    s = Settings(cache_dir=tmp_path, use_cache=False)
    rep = await pipeline.run("www.adp.com", s, extra_candidates=["adpemployment.com"])
    assert rep.seed == "adp.com"
    assert rep.org_names == ["Automatic Data Processing, Inc."]
    owned = [r.domain for r in rep.by_class(Classification.OWNED)]
    review = [r.domain for r in rep.by_class(Classification.REVIEW)]
    rejected = [r.domain for r in rep.by_class(Classification.REJECTED)]
    assert sorted(owned) == ["myadp.com", "workforcenow.com"]
    assert review == ["adpvantage.com"]
    assert sorted(rejected) == ["adp.fr", "adpemployment.com"]

    doc = json.loads(to_json(rep))
    assert [r["domain"] for r in doc["needs_review"]] == ["adpvantage.com"]
    assert all(r["evidence"] for r in doc["owned"])
    csv_text = to_csv(rep)
    assert csv_text.splitlines()[0] == "domain,classification,score,status,sources,evidence"
    assert "adp.fr" not in csv_text  # rejected rows only with --verbose
