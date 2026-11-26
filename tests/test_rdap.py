import json
from pathlib import Path

import httpx
import pytest
import respx

from domainfinder.collectors.rdap import RdapClient, parse_domain, parse_ip, vcard_fields
from domainfinder.http import Http
from domainfinder.models import RdapInfo

FIX = Path(__file__).parent / "fixtures"


def load(name):
    return json.loads((FIX / name).read_text())


@pytest.mark.parametrize("bad", [
    {},
    {"vcardArray": None},
    {"vcardArray": ["vcard"]},
    {"vcardArray": ["vcard", [["fn"]]]},
    {"vcardArray": ["vcard", [["adr", {}, "text", ["", ""]]]]},
    {"vcardArray": ["vcard", [["adr", "notadict", "text", None], 5, None]]},
])
def test_vcard_is_defensive(bad):
    v = vcard_fields(bad)
    assert v["fn"] == "" and v["region"] == ""


def test_parse_registry_then_registrar():
    info = RdapInfo()
    parse_domain(load("rdap_markmonitor_adp.json"), info, "rdap.markmonitor.com")
    parse_domain(load("rdap_verisign_adp.json"), info, "rdap.verisign.com")
    assert info.registrar == "Markmonitor Inc."
    assert info.registrar_iana_id == "292"
    assert info.registrant_region == "NJ" and info.registrant_country == "US"
    assert info.region_key() == "NJ, US"
    assert info.registrant_org == ""
    assert info.created == "1991-06-24"


def test_parse_ip_arin():
    nb = parse_ip(load("rdap_arin_170.json"), "rdap.arin.net")
    assert nb.name == "ADP-ESNET" and nb.cidr == "170.146.0.0/16"
    assert nb.org == "Automatic Data Processing, Inc."
    assert nb.rir == "arin"
    assert nb.contains("170.146.93.56") and not nb.contains("170.147.0.1")


@respx.mock
async def test_client_follows_related_link_and_caches_networks():
    respx.get("https://data.iana.org/rdap/dns.json").respond(
        json={"services": [[["com", "net"], ["https://rdap.verisign.com/com/v1/"]]]})
    respx.get("https://data.iana.org/rdap/ipv4.json").respond(
        json={"services": [[["170.0.0.0/8"], ["https://rdap.arin.net/registry/"]]]})
    respx.get("https://data.iana.org/rdap/ipv6.json").respond(json={"services": []})
    respx.get("https://rdap.verisign.com/com/v1/domain/adp.com").respond(json=load("rdap_verisign_adp.json"))
    respx.get("https://rdap.markmonitor.com/rdap/domain/ADP.COM").respond(json=load("rdap_markmonitor_adp.json"))
    ip_route = respx.get("https://rdap.arin.net/registry/ip/170.146.93.56").respond(json=load("rdap_arin_170.json"))
    http = Http()
    c = RdapClient(http)
    info = await c.domain("adp.com")
    assert info.region_key() == "NJ, US"
    assert info.sources == ["rdap.markmonitor.com", "rdap.verisign.com"]
    nb = await c.ip("170.146.93.56")
    nb2 = await c.ip("170.146.1.1")  # same /16: answered from memory
    assert nb.name == nb2.name == "ADP-ESNET"
    assert ip_route.call_count == 1
    await http.aclose()


@respx.mock
async def test_client_reports_missing_rdap():
    respx.get("https://data.iana.org/rdap/dns.json").respond(json={"services": []})
    respx.get("https://rdap.org/domain/adp.de").respond(status_code=404)
    http = Http()
    info = await RdapClient(http).domain("adp.de")
    assert not info.available and "not found" in info.error
    await http.aclose()
