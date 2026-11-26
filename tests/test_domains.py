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
    from domainfinder.domains import display, humanize, to_ascii, to_unicode

    assert to_unicode("adp.xn--vuq861b") == "adp.信息"
    assert to_ascii("adp.信息") == "adp.xn--vuq861b"
    assert to_ascii("adp.com") == "adp.com"
    assert display("adp.xn--vuq861b") == "adp.信息"
    assert display("adp.xn--vuq861b", "punycode") == "adp.xn--vuq861b"
    assert display("adp.信息", "punycode") == "adp.xn--vuq861b"
    assert display("adp.com") == "adp.com"
    assert to_unicode("xn--broken-.com") == "xn--broken-.com"  # undecodable: unchanged


def test_humanize_rewrites_names_inside_text():
    from domainfinder.domains import humanize

    text = "www CNAME to adp.com; redirects to www.adp.xn--vuq861b/path"
    assert humanize(text) == "www CNAME to adp.com; redirects to www.adp.信息/path"
    assert humanize(text, "punycode") == text
    assert humanize("nothing to change") == "nothing to change"


def test_unicode_input_is_accepted():
    assert registrable("www.ADP.信息") == "adp.xn--vuq861b"
