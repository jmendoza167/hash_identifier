"""Tests for the startup banner."""

from hashident import __version__
from hashident.banner import banner
from hashident.signatures import SIGNATURES
from hashident.style import ANSI, strip_ansi


def test_banner_is_ascii_art_within_80_columns():
    text = banner()
    lines = text.splitlines()

    assert text.isascii()
    assert len(lines) >= 6  # the art, then the line naming the tool
    assert all(len(line) <= 80 for line in lines)
    assert not text.endswith("\n")


def test_banner_names_the_tool_and_its_version():
    assert f"hashident v{__version__}" in banner().splitlines()[-1]


def test_banner_says_how_many_formats_are_known():
    assert f"{len(SIGNATURES)} formats" in banner().splitlines()[-1]


def test_banner_carries_no_credits_or_links_from_other_tools():
    text = banner().casefold()

    for foreign in ("http", "www", "zion", "blackploit", " by "):
        assert foreign not in text


def test_colored_banner_is_the_plain_banner_plus_codes():
    colored = banner(ANSI)

    assert "\x1b[" in colored
    assert strip_ansi(colored) == banner()
