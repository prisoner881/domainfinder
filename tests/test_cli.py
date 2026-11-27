import pytest

from domainfinder import BANNER, __version__
from domainfinder.cli import main


def test_version_is_0_9_9():
    assert __version__ == "0.9.9"
    assert BANNER == "domainfinder 0.9.9"


def test_every_run_announces_name_and_version_on_stderr(capsys):
    assert main(["--list-sources"]) == 0
    out, err = capsys.readouterr()
    assert err.splitlines()[0] == "domainfinder 0.9.9"
    assert "domainfinder 0.9.9" not in out  # stdout stays clean (matters for --json)


def test_version_flag(capsys):
    with pytest.raises(SystemExit):
        main(["--version"])
    assert capsys.readouterr().out.strip() == "domainfinder 0.9.9"


def test_banner_on_a_terminal_is_framed_and_names_the_tool():
    import io

    from rich.console import Console

    from domainfinder.banner import render

    buf = io.StringIO()
    render(Console(file=buf, force_terminal=True, width=100, color_system="truecolor"))
    out = buf.getvalue()
    assert "domainfinder" in out and "v0.9.9" in out
    assert "Finds the other domains an organization owns" in out and "passive, public lookups only" in out
    assert "╭" in out and "\x1b[" in out  # framed and coloured


def test_banner_off_a_terminal_is_the_plain_line():
    import io

    from rich.console import Console

    from domainfinder.banner import render

    buf = io.StringIO()
    render(Console(file=buf, force_terminal=False))
    assert buf.getvalue() == "domainfinder 0.9.9\n"
