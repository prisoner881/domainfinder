import pytest

from domainfinder import BANNER, __version__
from domainfinder.cli import main


def test_version_is_1_2_2():
    assert __version__ == "1.2.2"
    assert BANNER == "domainfinder 1.2.2"


def test_every_run_announces_name_and_version_on_stderr(capsys):
    assert main(["--list-sources"]) == 0
    out, err = capsys.readouterr()
    assert err.splitlines()[0] == "domainfinder 1.2.2"
    assert "domainfinder 1.2.2" not in out  # stdout stays clean (matters for --json)


def test_version_flag(capsys):
    with pytest.raises(SystemExit):
        main(["--version"])
    assert capsys.readouterr().out.strip() == "domainfinder 1.2.2"


def test_banner_on_a_terminal_is_framed_and_names_the_tool():
    import io

    from rich.console import Console

    from domainfinder.banner import render

    buf = io.StringIO()
    render(Console(file=buf, force_terminal=True, width=100, color_system="truecolor"))
    out = buf.getvalue()
    assert "domainfinder" in out and "v1.2.2" in out
    assert "Finds the other domains an organization owns" in out and "passive, public lookups only" in out
    assert "╭" in out and "\x1b[" in out  # framed and coloured


def test_banner_off_a_terminal_is_the_plain_line():
    import io

    from rich.console import Console

    from domainfinder.banner import render

    buf = io.StringIO()
    render(Console(file=buf, force_terminal=False))
    assert buf.getvalue() == "domainfinder 1.2.2\n"


def test_root_banner_is_copied_to_stderr_only_when_not_already_visible():
    from domainfinder.cli import banner_to_stderr

    assert banner_to_stderr(json_output=True, stdout_is_terminal=True)  # JSON has no banner
    assert banner_to_stderr(json_output=False, stdout_is_terminal=False)  # table into a file/pipe
    assert not banner_to_stderr(json_output=False, stdout_is_terminal=True)  # table on screen: once
