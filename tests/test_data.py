from domainfinder import data


def test_shared_and_selectable_dns():
    d = data.load()
    assert d.is_shared_dns("ns01.domaincontrol.com")
    assert d.is_shared_dns("ns-123.awsdns-45.com")
    assert d.is_shared_dns("ada.ns.cloudflare.com")
    assert not d.is_shared_dns("a1-199.akam.net")
    assert d.is_selectable_dns("a1-199.akam.net")
    assert d.is_selectable_dns("dns1.p01.nsone.net")
    assert not d.is_shared_dns("ns1.zdp.com")


def test_parking_and_hosting_lists():
    d = data.load()
    assert d.is_parking_host("ns1.parkingcrew.net")
    assert d.is_parking_host("www.hugedomains.com")
    assert d.is_shared_hosting_org("Akamai Technologies, Inc.")
    assert d.is_shared_hosting_org("Amazon.com, Inc.")
    assert not d.is_shared_hosting_org("Zyntara Data Processing, Inc.")
    # word-boundary match: "aws" must not hit "Lawson"
    assert not d.is_shared_hosting_org("Lawson Software")
    assert "com.br" in d.cctlds and "co.uk" in d.cctlds
    assert "15.197.70.98" in d.holding_ips


def test_privacy_and_registrars():
    d = data.load()
    assert d.is_privacy_proxy("DNStination Inc.")
    assert d.is_privacy_proxy("REDACTED FOR PRIVACY")
    assert not d.is_privacy_proxy("Zyntara Data Processing, Inc.")
    assert d.is_brand_registrar("MarkMonitor Inc.")
    assert not d.is_brand_registrar("GoDaddy.com, LLC")
    assert d.has_parking_marker("<h1>This domain is for sale!</h1>")
