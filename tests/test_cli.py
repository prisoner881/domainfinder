import pytest

from domainfinder import BANNER, __version__
from domainfinder.cli import main


def test_version_is_0_9():
    assert __version__ == "0.9"
    assert BANNER == "domainfinder 0.9"


def test_every_run_announces_name_and_version_on_stderr(capsys):
    assert main(["--list-sources"]) == 0
    out, err = capsys.readouterr()
    assert err.splitlines()[0] == "domainfinder 0.9"
    assert "domainfinder 0.9" not in out  # stdout stays clean (matters for --json)


def test_version_flag(capsys):
    with pytest.raises(SystemExit):
        main(["--version"])
    assert capsys.readouterr().out.strip() == "domainfinder 0.9"
