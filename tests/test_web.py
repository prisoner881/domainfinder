from domainfinder.collectors.web import chain_domains, extract_analytics, extract_csp_domains, extract_links
from domainfinder.models import WebInfo

HTML = """
<html><head><title>ADP</title>
<script src="https://www.googletagmanager.com/gtm.js?id=GTM-MMKNHG5"></script>
<script>gtag('config', 'G-ABCD1234EF'); ga('create', 'UA-123456-1');</script>
<script src="https://assets.adobedtm.com/launch-0123456789abcdef.min.js"></script>
</head><body>
<a href="https://www.workforcesoftware.com/about">WFS</a>
<a href="/careers">rel</a><a href="mailto:x@adp.com">m</a>
<a href="https://linkedin.com/company/adp">li</a>
</body></html>
"""


def test_extract_analytics():
    ids = extract_analytics(HTML)
    assert "gtm:GTM-MMKNHG5" in ids
    assert "ga4:G-ABCD1234EF" in ids
    assert "ua:UA-123456-1" in ids
    assert any(i.startswith("adobe-launch:") for i in ids)


def test_extract_links_and_csp():
    links = extract_links(HTML, "https://www.adp.com/")
    assert "workforcesoftware.com" in links and "adp.com" in links and "linkedin.com" in links
    csp = "frame-ancestors 'self' https://*.adp.com http://*.adp.ca https://connect.workforcesoftware.com"
    assert extract_csp_domains(csp) == ["adp.com", "adp.ca", "workforcesoftware.com"]


def test_chain_domains():
    w = WebInfo(chain=["http://myadp.com/", "https://my.adp.com/", "https://online.adp.com/x"])
    assert chain_domains(w) == ["myadp.com", "adp.com"]
