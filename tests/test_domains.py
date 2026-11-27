from domainfinder.domains import clean, label, registrable


def test_registrable_handles_second_level_suffixes():
    assert registrable("www.zdp.co.uk") == "zdp.co.uk"
    assert registrable("zdppayroll.com.au") == "zdppayroll.com.au"
    assert registrable("*.foo.zdp.com") == "zdp.com"
    assert registrable("https://Online.ZDP.com/path?x=1") == "zdp.com"


def test_registrable_rejects_junk():
    assert registrable("") is None
    assert registrable("com") is None
    assert registrable("not a domain") is None
    assert registrable("localhost") is None


def test_label_and_clean():
    assert label("zdp.co.uk") == "zdp"
    assert clean("mailto:someone@zdp.com") == "zdp.com"


def test_punycode_names_get_a_readable_form():
    from domainfinder.domains import display, humanize, to_ascii, to_unicode

    assert to_unicode("zdp.xn--vuq861b") == "zdp.信息"
    assert to_ascii("zdp.信息") == "zdp.xn--vuq861b"
    assert to_ascii("zdp.com") == "zdp.com"
    assert display("zdp.xn--vuq861b") == "zdp.信息"
    assert display("zdp.xn--vuq861b", "punycode") == "zdp.xn--vuq861b"
    assert display("zdp.信息", "punycode") == "zdp.xn--vuq861b"
    assert display("zdp.com") == "zdp.com"
    assert to_unicode("xn--broken-.com") == "xn--broken-.com"  # undecodable: unchanged


def test_humanize_rewrites_names_inside_text():
    from domainfinder.domains import humanize

    text = "www CNAME to zdp.com; redirects to www.zdp.xn--vuq861b/path"
    assert humanize(text) == "www CNAME to zdp.com; redirects to www.zdp.信息/path"
    assert humanize(text, "punycode") == text
    assert humanize("nothing to change") == "nothing to change"


def test_unicode_input_is_accepted():
    assert registrable("www.ZDP.信息") == "zdp.xn--vuq861b"
