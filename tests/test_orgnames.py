from domainfinder.orgnames import normalize, same_org


def test_normalize_strips_legal_suffixes_and_punctuation():
    assert normalize("Zyntara Data Processing, Inc.") == "zyntara data processing"
    assert normalize("Zyntara Data Processing Inc,") == "zyntara data processing"
    assert normalize("The Foo & Bar Company, LLC") == "foo and bar"
    assert normalize("Zone de Plaisance SA") == "zone de plaisance"


def test_same_org_variants():
    assert same_org("Zyntara Data Processing, Inc.", "ZYNTARA DATA PROCESSING INC")
    assert same_org("Zyntara Data Processing Limited", "Zyntara Data Processing, Inc.")
    assert same_org("ZDP, Inc.", "ZDP, LLC")


def test_short_acronym_does_not_match_longer_names():
    assert not same_org("ZDP", "ZDP GSI France")
    assert not same_org("ZDP", "Zone de Plaisance")
    assert not same_org("Groupe ZDP", "Zyntara Data Processing, Inc.")
    assert not same_org("American Dental Partners Foundation", "Zyntara Data Processing")


def test_empty_names_never_match():
    assert not same_org("", "")
    assert not same_org("Inc.", "LLC")
