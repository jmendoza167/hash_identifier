"""Smoke tests for the hashident command-line interface."""

import pytest

from hashident import __version__
from hashident.cli import main


def test_version_prints_package_version_and_exits_zero(capsys):
    # argparse's "version" action prints and then raises SystemExit(0).
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])

    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert out.strip() == f"hashident {__version__}"


def test_no_arguments_prints_help_and_returns_zero(capsys):
    # Pass [] explicitly: None would make argparse read pytest's own sys.argv.
    assert main([]) == 0

    out = capsys.readouterr().out
    assert out.startswith("usage: hashident")
    assert "--version" in out
