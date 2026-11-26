from domainfinder.domains import clean, label, registrable


def test_registrable_handles_second_level_suffixes():
    assert registrable("www.adp.co.uk") == "adp.co.uk"
    assert registrable("adppayroll.com.au") == "adppayroll.com.au"
    assert registrable("*.foo.adp.com") == "adp.com"
    assert registrable("https://Online.ADP.com/path?x=1") == "adp.com"


def test_registrable_rejects_junk():
    assert registrable("") is None
    assert registrable("com") is None
    assert registrable("not a domain") is None
    assert registrable("localhost") is None


def test_label_and_clean():
    assert label("adp.co.uk") == "adp"
    assert clean("mailto:someone@adp.com") == "adp.com"


def test_punycode_names_get_a_readable_form():
    from domainfinder.domains import display, to_unicode

    assert to_unicode("adp.xn--vuq861b") == "adp.信息"
    assert display("adp.xn--vuq861b") == "adp.xn--vuq861b (adp.信息)"
    assert display("adp.com") == "adp.com"
    assert to_unicode("xn--broken-.com") == "xn--broken-.com"  # undecodable: unchanged
