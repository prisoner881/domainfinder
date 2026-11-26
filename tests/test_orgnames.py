from domainfinder.orgnames import normalize, same_org


def test_normalize_strips_legal_suffixes_and_punctuation():
    assert normalize("Automatic Data Processing, Inc.") == "automatic data processing"
    assert normalize("Automatic Data Processing Inc,") == "automatic data processing"
    assert normalize("The Foo & Bar Company, LLC") == "foo and bar"
    assert normalize("Aéroports de Paris SA") == "aeroports de paris"


def test_same_org_variants():
    assert same_org("Automatic Data Processing, Inc.", "AUTOMATIC DATA PROCESSING INC")
    assert same_org("Automatic Data Processing Limited", "Automatic Data Processing, Inc.")
    assert same_org("ADP, Inc.", "ADP, LLC")


def test_short_acronym_does_not_match_longer_names():
    assert not same_org("ADP", "ADP GSI France")
    assert not same_org("ADP", "Aéroports de Paris")
    assert not same_org("Groupe ADP", "Automatic Data Processing, Inc.")
    assert not same_org("American Dental Partners Foundation", "Automatic Data Processing")


def test_empty_names_never_match():
    assert not same_org("", "")
    assert not same_org("Inc.", "LLC")
