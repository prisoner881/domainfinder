from domainfinder.collectors.dnsinfo import mail_tenant, parse_spf_includes, parse_tokens, rname_domain


def test_mail_tenant_patterns():
    assert mail_tenant("mxa-0006eb01.gslb.pphosted.com") == "proofpoint:0006eb01"
    assert mail_tenant("mxb-0006eb01.gslb.pphosted.com.") == "proofpoint:0006eb01"
    assert mail_tenant("mx1.hc1234-56.iphmx.com") == "cisco-ironport:hc1234-56"
    assert mail_tenant("aspmx.l.google.com") is None
    assert mail_tenant("adp-com.mail.protection.outlook.com") is None


def test_spf_includes_skip_macros():
    txt = ["v=spf1 include:_spf.adp.com include:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all", "other"]
    assert parse_spf_includes(txt) == ["_spf.adp.com"]
    assert parse_spf_includes(["v=spf1 redirect=_spf.example.com"]) == ["_spf.example.com"]


def test_verification_tokens():
    txt = ["MS=ms96397460", "google-site-verification=abcdefghijklmnop", "v=spf1 -all", "MS=x"]
    assert parse_tokens(txt) == ["MS=ms96397460", "google-site-verification=abcdefghijklmnop"]


def test_rname_domain():
    assert rname_domain("hostmaster.adp.com") == "adp.com"
    assert rname_domain("") is None
