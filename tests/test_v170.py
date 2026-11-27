"""1.7.0: GLEIF. The seed's legal entity (one exact match only), its
consolidated subsidiaries' names count as the organization's, and a seed
organization that is itself a subsidiary is flagged loudly."""

import csv
import io
import json

import respx
from helpers import ZDP_NS, fp, rdap, seed_fp

from domainfinder import pipeline, report
from domainfinder.collectors.gleif import API, Entity, Family, find_entity, seed_family
from domainfinder.config import Settings
from domainfinder.http import Http
from domainfinder.models import Classification as C

ORG = "Zyntara Data Processing, Inc."


def rec(lei, name, country="US", status="ISSUED", others=()):
    return {"type": "lei-records", "attributes": {
        "lei": lei, "registration": {"status": status},
        "entity": {"legalName": {"name": name}, "legalAddress": {"country": country},
                   "otherNames": [{"name": o} for o in others]}}}


def search(name, *records):
    respx.get(f"{API}/lei-records", params={"filter[entity.legalName]": name}).respond(
        json={"data": list(records), "meta": {"pagination": {"total": len(records)}}})


def family_routes(lei, children=(), parent=None, direct=None):
    for rel, p in (("ultimate-parent", parent), ("direct-parent", direct or parent)):
        if p:
            respx.get(f"{API}/lei-records/{lei}/{rel}").respond(json={"data": p})
        else:
            respx.get(f"{API}/lei-records/{lei}/{rel}").respond(404, json={"errors": [{"status": "404"}]})
    respx.get(f"{API}/lei-records/{lei}/ultimate-children").respond(
        json={"data": list(children), "meta": {"pagination": {"lastPage": 1}}})


# --- finding the seed's entity ------------------------------------------------------------------

@respx.mock
async def test_only_an_exact_name_match_counts_and_suffixes_break_ties():
    search(ORG, rec("L1", "ZYNTARA DATA PROCESSING LIMITED", "GB"), rec("L2", "ZYNTARA DATA PROCESSING, INC."),
           rec("L3", "Zyntara Data Processing Inc. Pension Plan"), rec("L4", "INC Group Inc.", "CA"))
    http = Http()
    ent, why = await find_entity(http, ORG)
    assert ent.lei == "L2" and why == ""
    await http.aclose()


@respx.mock
async def test_country_breaks_a_tie_and_ambiguity_means_none():
    search("Zyntara Data Processing", rec("L1", "Zyntara Data Processing", "GB"), rec("L2", "Zyntara Data Processing", "US"))
    http = Http()
    assert (await find_entity(http, "Zyntara Data Processing", "US"))[0].lei == "L2"
    ent, why = await find_entity(http, "Zyntara Data Processing")
    assert ent is None and "2 entities" in why
    await http.aclose()


@respx.mock
async def test_retired_records_and_near_misses_are_ignored():
    search(ORG, rec("L1", "ZYNTARA DATA PROCESSING, INC.", status="RETIRED"), rec("L2", "Zyntara Data Processing Group"))
    http = Http()
    ent, why = await find_entity(http, ORG)
    assert ent is None and "no entity named exactly" in why
    await http.aclose()


def test_family_names_include_other_names_and_skip_unusable_ones():
    fam = Family(Entity("L", "ZYNTARA DATA PROCESSING, INC.", ["ZDP Payroll"]),
                 children=[Entity("C1", "Shiftlane Software, LLC"), Entity("C2", "環匯亞太(香港)有限公司"),
                           Entity("C3", "SHIFTLANE SOFTWARE LLC")])
    assert fam.names() == ["ZYNTARA DATA PROCESSING, INC.", "ZDP Payroll", "Shiftlane Software, LLC"]


@respx.mock
async def test_seed_family_loads_children_and_parents():
    search(ORG, rec("L2", "ZYNTARA DATA PROCESSING, INC."))
    family_routes("L2", children=[rec("C1", "Shiftlane Software, LLC")], parent=rec("P1", "Megacorp Holdings plc", "GB"))
    http = Http()
    fam, note = await seed_family(http, [ORG], "US")
    assert fam.entity.lei == "L2" and [c.legal_name for c in fam.children] == ["Shiftlane Software, LLC"]
    assert fam.parent().legal_name == "Megacorp Holdings plc" and note == ""
    await http.aclose()


# --- the pipeline --------------------------------------------------------------------------------

SUB = fp("shiftlane-example.com", ns=sorted(ZDP_NS),
         rdap=rdap(org="Shiftlane Software, LLC", registrar="GoDaddy", region="MI", iana="146"))


async def fake_fp(domain, collectors, **kw):
    if domain == "zdp.com":
        s = seed_fp()
        s.cert.subject_org = ORG
        return s
    return SUB if domain == "shiftlane-example.com" else fp(domain, registered=False)


async def no_org(*a, **kw):
    return []


def run(monkeypatch, tmp_path, **settings):
    monkeypatch.setattr(pipeline, "fingerprint", fake_fp)
    monkeypatch.setattr(pipeline, "seed_org_from_ct", no_org)
    monkeypatch.setattr(pipeline, "ALL_SOURCES", [])
    return pipeline.run("zdp.com", Settings(cache_dir=tmp_path, use_cache=False, **settings),
                        extra_candidates=["shiftlane-example.com"])


@respx.mock
async def test_a_subsidiarys_registration_is_the_organizations_not_a_conflict(monkeypatch, tmp_path):
    search(ORG, rec("L2", "ZYNTARA DATA PROCESSING, INC."))
    family_routes("L2", children=[rec("C1", "Shiftlane Software, LLC")])
    rep = await run(monkeypatch, tmp_path)
    r = next(x for x in rep.results if x.domain == "shiftlane-example.com")
    assert "rdap_org" in [e.kind for e in r.evidence] and not any(e.kind.startswith("different_org") for e in r.evidence)
    assert any(n.startswith("gleif: ZYNTARA DATA PROCESSING, INC. (LEI L2); 1 consolidated subsidiary") for n in rep.notes)
    assert rep.parent_warning() == ""


@respx.mock
async def test_without_gleif_the_same_registration_is_a_conflict(monkeypatch, tmp_path):
    rep = await run(monkeypatch, tmp_path, gleif=False)
    r = next(x for x in rep.results if x.domain == "shiftlane-example.com")
    assert "different_org_rdap" in [e.kind for e in r.evidence] or any("likely subsidiary" in e.detail for e in r.evidence)


@respx.mock
async def test_a_seed_organization_that_is_a_subsidiary_is_flagged_everywhere(monkeypatch, tmp_path):
    search(ORG, rec("L2", "ZYNTARA DATA PROCESSING, INC."))
    family_routes("L2", parent=rec("P1", "Megacorp Holdings plc", "GB"), direct=rec("P2", "Megacorp US Inc."))
    rep = await run(monkeypatch, tmp_path)
    warn = rep.parent_warning()
    assert "is a subsidiary of Megacorp Holdings plc (GB, LEI P1) (directly owned by Megacorp US Inc.)" in warn
    assert "not the parent or the parent's other subsidiaries" in warn
    rows = list(csv.DictReader(io.StringIO(report.to_csv(rep).lstrip("﻿"))))
    assert rows[0]["domain"] == "zdp.com" and rows[0]["classification"] == "seed"
    assert all("PARENT ORGANIZATION: " in r["root_warning"] and "Megacorp Holdings plc" in r["root_warning"]
               for r in rows)
    doc = json.loads(report.to_json(rep))
    assert doc["gleif"]["ultimate_parent"]["lei"] == "P1" and "Megacorp" in doc["parent_warning"]
    from rich.console import Console

    con = Console(record=True, width=200)
    report.print_table(rep, con)
    text = con.export_text()
    assert text.count("BELONGS TO A SUBSIDIARY OF MEGACORP HOLDINGS PLC") == 2  # top and bottom


@respx.mock
async def test_gleif_failure_never_sinks_the_run(monkeypatch, tmp_path):
    respx.get(url__startswith=API).respond(503)
    rep = await run(monkeypatch, tmp_path)
    assert any(n.startswith("gleif: not used") for n in rep.notes) and rep.gleif is None
    assert any(r.domain == "shiftlane-example.com" for r in rep.results)
