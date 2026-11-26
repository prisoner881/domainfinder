from pathlib import Path

from domainfinder.cache import Cache
from domainfinder.collectors.whois import parse_educause, whois_lookup
from domainfinder.models import RdapInfo

FIX = Path(__file__).parent / "fixtures"


def test_parse_educause_registrant_block():
    info = RdapInfo()
    assert parse_educause((FIX / "whois_educause_example.txt").read_text(), info)
    assert info.registrant_org == "Example University"
    assert info.region_key() == "PA, US"
    assert info.registrar == "EDUCAUSE" and info.available


def test_parse_educause_without_registrant():
    assert not parse_educause("No Match", RdapInfo())


async def test_whois_lookup_only_for_known_registries_and_never_raises():
    assert await whois_lookup("example.com", Cache.memory()) is None  # no server listed
    # The test guard makes every socket fail: the lookup must just give up.
    assert await whois_lookup("exampleu.edu", Cache.memory(), timeout=1) is None
