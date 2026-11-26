import json

import pytest

from domainfinder import pipeline
from domainfinder.candidates_io import parse_domain_list, read_domain_file
from domainfinder.cli import main
from domainfinder.config import Settings
from domainfinder.models import Classification


def test_comma_and_newline_separated_lists():
    res = parse_domain_list("a.com, b.org,c.net\nd.co.uk\n\n e.io ,", "t")
    assert res.domains == ["a.com", "b.org", "c.net", "d.co.uk", "e.io"]
    assert res.entries == 5 and not res.invalid


def test_entries_are_normalized_deduplicated_and_validated():
    text = '''# found by the asset inventory
"https://www.Example.co.uk/login", mail.example.co.uk, EXAMPLE.CO.UK
adp.信息, not a domain, localhost, 10.0.0.1  # trailing comment
'''
    res = parse_domain_list(text, "inv.csv")
    assert res.domains == ["example.co.uk", "adp.xn--vuq861b"]
    assert res.invalid == ["not a domain", "localhost", "10.0.0.1"]
    assert res.reduced == 2  # the URL and the mail host
    s = res.summary()
    assert "2 candidate domain(s) from 7 entries" in s and "2 duplicate(s) merged" in s
    assert "3 skipped as not a domain" in s


def test_read_file_with_bom(tmp_path):
    f = tmp_path / "c.csv"
    f.write_text("﻿domain\nadp.ca\nmyadp.com\n", encoding="utf-8")
    res = read_domain_file(str(f))
    assert res.domains == ["adp.ca", "myadp.com"]
    assert res.invalid == ["domain"]  # a header line is reported, not imported


def test_missing_import_file_is_a_clean_error(capsys):
    assert main(["adp.com", "--import", "/nonexistent/list.csv"]) == 2
    assert "cannot read /nonexistent/list.csv" in capsys.readouterr().err


async def test_imported_candidates_are_verified_like_any_other(monkeypatch, tmp_path):
    from test_pipeline import FPS, FakeSource, fake_ct_org, fake_fingerprint

    monkeypatch.setattr(pipeline, "fingerprint", fake_fingerprint)
    monkeypatch.setattr(pipeline, "seed_org_from_ct", fake_ct_org)
    monkeypatch.setattr(pipeline, "ALL_SOURCES", [])  # only the imported list
    res = parse_domain_list("myadp.com, adp.fr, adp.com, adpemployment.com", "list.csv")
    rep = await pipeline.run(
        "adp.com", Settings(cache_dir=tmp_path, use_cache=False),
        imported_candidates=[(d, res.source) for d in res.domains], import_notes=[res.summary()],
    )
    by = {r.domain: r for r in rep.results}
    assert set(by) == {"myadp.com", "adp.fr", "adpemployment.com"}  # the seed itself is dropped
    assert by["myadp.com"].classification is Classification.OWNED
    assert by["adp.fr"].classification is Classification.REJECTED
    assert by["adpemployment.com"].status == "unregistered"
    assert by["myadp.com"].sources == {"import": "imported from list.csv"}
    assert rep.notes[0].startswith("import list.csv:")


async def test_imported_candidates_survive_the_max_candidates_cap(monkeypatch, tmp_path):
    from domainfinder.models import Candidate
    from domainfinder.sources.base import Source
    from test_pipeline import fake_ct_org, fake_fingerprint

    class Many(Source):
        name = "many"

        async def candidates(self, ctx):
            return [Candidate(f"found{i}.com", {"many": ""}) for i in range(10)]

    monkeypatch.setattr(pipeline, "fingerprint", fake_fingerprint)
    monkeypatch.setattr(pipeline, "seed_org_from_ct", fake_ct_org)
    monkeypatch.setattr(pipeline, "ALL_SOURCES", [Many])
    rep = await pipeline.run("adp.com", Settings(cache_dir=tmp_path, use_cache=False), max_candidates=3,
                             imported_candidates=[("myadp.com", "x"), ("adp.fr", "x")])
    doms = {r.domain for r in rep.results}
    assert {"myadp.com", "adp.fr"} <= doms and len(doms) == 3
