import csv
import json

from helpers import fp, rdap, web

from domainfinder import pipeline
from domainfinder.cli import main
from domainfinder.collectors.web import extract_canonical
from domainfinder.models import CertInfo, WebInfo
from domainfinder.rootcheck import check_root


def test_redirect_to_another_domain_means_wrong_root():
    f = fp("adpcorp.com", web=web("http://adpcorp.com/", "https://www.adp.com/"))
    rc = check_root("adpcorp.com", f)
    assert rc.status == "wrong" and rc.suggested == "adp.com"
    assert "redirects to adp.com" in rc.reasons[0]
    assert "same brand in both names" in rc.corroboration
    assert "LOOKS WRONG" in rc.headline() and "Suggested real root: adp.com" in rc.headline()


def test_redirect_within_the_same_domain_is_fine():
    rc = check_root("adp.com", fp("adp.com", web=web("http://adp.com/", "https://www.adp.com/home")))
    assert rc.status == "ok" and not rc.headline()


def test_unregistered_parked_and_held():
    assert check_root("nope.com", fp("nope.com", registered=False)).status == "wrong"
    parked = check_root("adpx.com", fp("adpx.com", ns=["ns1.parkingcrew.net"]))
    assert parked.status == "wrong" and "parked" in parked.reasons[0] and not parked.suggested
    held = check_root("adpv.com", fp("adpv.com", a=["15.197.70.98"], ns=["ns1.markmonitor.com"]))
    assert held.status == "wrong" and "holding page" in held.reasons[0]
    via_registrar = check_root("arx.com", fp("arx.com", rdap=rdap(),
                                             web=web("http://arx.com/", "https://www.markmonitor.com/")))
    assert "holding page" in via_registrar.reasons[0] and not via_registrar.suggested


def test_canonical_address_elsewhere():
    w = WebInfo(fetched=True, status=200, chain=["https://old-brand.com/"], final_url="https://old-brand.com/",
                canonical_url="https://www.newbrand.com/")
    rc = check_root("old-brand.com", fp("old-brand.com", web=w))
    assert rc.status == "wrong" and rc.suggested == "newbrand.com"
    # A canonical that agrees with the redirect only corroborates it.
    w2 = web("http://a.com/", "https://b.com/", canonical_url="https://b.com/")
    rc2 = check_root("a.com", fp("a.com", web=w2))
    assert rc2.suggested == "b.com" and len(rc2.reasons) == 1
    assert any("canonical" in c for c in rc2.corroboration)


def test_uncorroborated_suggestion_says_so():
    rc = check_root("portal-x.com", fp("portal-x.com", web=web("http://portal-x.com/", "https://login.okta.com/")))
    assert rc.suggested == "okta.com" and not rc.corroboration
    assert "not corroborated" in rc.headline()


def test_advisory_when_dns_and_mail_run_from_a_parent():
    f = fp("tmbc.com", ns=["ns1.adp.com", "ns2.adp.com"], mx=["mail.adp.com"],
           web=WebInfo(fetched=True, status=200, chain=["https://tmbc.com/"], final_url="https://tmbc.com/"))
    rc = check_root("tmbc.com", f)
    assert rc.status == "advisory" and rc.suggested == "adp.com"
    assert "nameservers and mail servers are run from adp.com" in rc.advisories[0]
    # Mail at a small provider alone is not worth a hint.
    f2 = fp("shop.com", mx=["mx.smallmailhost.net"],
            web=WebInfo(fetched=True, status=200, chain=["https://shop.com/"], final_url="https://shop.com/"))
    assert check_root("shop.com", f2).status == "ok"


def test_no_web_no_mail_and_input_normalization():
    rc = check_root("WWW.Quiet.com", fp("quiet.com"))
    assert rc.status == "advisory" and "no website and no mail" in rc.advisories[0]
    assert rc.normalized.startswith("supplied 'WWW.Quiet.com'")


def test_extract_canonical():
    base = "https://www.example.com/x"
    assert extract_canonical('<link href="https://a.com/" rel="canonical">', base) == "https://a.com/"
    assert extract_canonical("<link rel='alternate' href='/fr'><link rel=canonical href=/home>", base) == \
        "https://www.example.com/home"
    assert extract_canonical('<meta property="og:url" content="https://b.com/">', base) == "https://b.com/"
    assert extract_canonical("<p>nothing</p>", base) == ""


# --- end to end: flagged, not interrupted ------------------------------------------

FPS = {
    "adpcorp.com": fp("adpcorp.com", web=web("http://adpcorp.com/", "https://www.adp.com/")),
    "adp.com": fp("adp.com", web=web("https://www.adp.com/")),
}


async def fake_fp(domain, collectors, **kw):
    return FPS.get(domain) or fp(domain, registered=False)


async def no_org(*a, **kw):
    return []


def test_cli_flags_a_wrong_root_everywhere_and_finishes(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(pipeline, "fingerprint", fake_fp)
    monkeypatch.setattr(pipeline, "seed_org_from_ct", no_org)
    monkeypatch.setattr(pipeline, "ALL_SOURCES", [])
    out_csv = tmp_path / "r.csv"
    code = main(["adpcorp.com", "--no-cache", "-o", str(out_csv)])
    assert code == 3  # finished, but flagged
    out, err = capsys.readouterr()
    assert out.count("LOOKS WRONG") == 2  # banner at the top and the bottom of the table
    assert "Suggested real root" in out and "domainfinder adp.com" in out
    assert "LOOKS WRONG" in err  # and on stderr, because a file was written
    rows = list(csv.DictReader(open(out_csv, encoding="utf-8-sig")))
    assert rows and all("LOOKS WRONG" in r["root_warning"] for r in rows)
    assert rows[0]["domain"] == "adpcorp.com" and rows[0]["classification"] == "seed"
    assert rows[0]["sources"] == "suggested real root: adp.com"
    # The suggested root was added as a candidate and verified like any other.
    code = main(["adpcorp.com", "--no-cache", "-v", "-o", str(out_csv)])
    rows = list(csv.DictReader(open(out_csv, encoding="utf-8-sig")))
    assert any(r["domain"] == "adp.com" and "root-check" in r["sources"] for r in rows)
    capsys.readouterr()

    code = main(["adpcorp.com", "--no-cache", "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert code == 3 and doc["root_check"]["status"] == "wrong" and doc["root_check"]["suggested"] == "adp.com"


def test_correct_root_exits_zero(monkeypatch, capsys):
    monkeypatch.setattr(pipeline, "fingerprint", fake_fp)
    monkeypatch.setattr(pipeline, "seed_org_from_ct", no_org)
    monkeypatch.setattr(pipeline, "ALL_SOURCES", [])
    assert main(["adp.com", "--no-cache"]) == 0
    assert "LOOKS WRONG" not in capsys.readouterr().out
