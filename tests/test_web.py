from domainfinder.collectors.web import chain_domains, extract_analytics, extract_csp_domains, extract_links
from domainfinder.models import WebInfo

HTML = """
<html><head><title>ZDP</title>
<script src="https://www.googletagmanager.com/gtm.js?id=GTM-ABC1234"></script>
<script>gtag('config', 'G-ABCD1234EF'); ga('create', 'UA-123456-1');</script>
<script src="https://assets.adobedtm.com/launch-0123456789abcdef.min.js"></script>
</head><body>
<a href="https://www.shiftlanesoftware.com/about">SLS</a>
<a href="/careers">rel</a><a href="mailto:x@zdp.com">m</a>
<a href="https://linkedin.com/company/zdp">li</a>
</body></html>
"""


def test_extract_analytics():
    ids = extract_analytics(HTML)
    assert "gtm:GTM-ABC1234" in ids
    assert "ga4:G-ABCD1234EF" in ids
    assert "ua:UA-123456-1" in ids
    assert any(i.startswith("adobe-launch:") for i in ids)


def test_extract_links_and_csp():
    links = extract_links(HTML, "https://www.zdp.com/")
    assert "shiftlanesoftware.com" in links and "zdp.com" in links and "linkedin.com" in links
    csp = "frame-ancestors 'self' https://*.zdp.com http://*.zdp.ca https://connect.shiftlanesoftware.com"
    assert extract_csp_domains(csp) == ["zdp.com", "zdp.ca", "shiftlanesoftware.com"]


def test_chain_domains():
    w = WebInfo(chain=["http://myzdp.com/", "https://my.zdp.com/", "https://online.zdp.com/x"])
    assert chain_domains(w) == ["myzdp.com", "zdp.com"]
