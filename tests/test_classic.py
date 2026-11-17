"""Tests for the classic view: one block per hash, formats in two tiers."""

import pytest

from hashident.classic import format_classic
from hashident.engine import identify
from hashident.models import Category, Context, Signature, Strength, Tier
from hashident.signatures import BCRYPT, MD5, MYSQL41, NTLM, SIGNATURES
from hashident.style import ANSI, strip_ansi


def _fake(name, *, tier=Tier.POSSIBLE, summary="", hashcat_mode=None, john_format=None):
    return Signature(
        name=name,
        category=Category.RAW,
        tier=tier,
        pattern=r"x+",
        summary=summary,
        strength=Strength.WEAK,
        strength_note="test",
        example="xxx",
        hashcat_mode=hashcat_mode,
        john_format=john_format,
    )


PAIR = (MD5, NTLM)
"""Layout tests use fixed formats, so they do not move with the registry."""


def lines_of(result, **options):
    return format_classic(result, **options).splitlines()


# --- Layout ----------------------------------------------------------------------


def test_md5_block_lists_possible_formats_best_first():
    assert lines_of(identify(MD5.example, signatures=PAIR)) == [
        "HASH: 8743b52063cd84097a65d1633f5c74f5",
        "",
        "Possible Hashes:",
        "[+] MD5",
        "[+] NTLM",
    ]


def test_least_possible_formats_get_their_own_section(tiered_signatures):
    result = identify(MD5.example, signatures=tiered_signatures)

    assert lines_of(result) == [
        "HASH: 8743b52063cd84097a65d1633f5c74f5",
        "",
        "Possible Hashes:",
        "[+] MD5",
        "[+] NTLM",
        "",
        "Least Possible Hashes:",
        "[+] Rare-128",
    ]


def test_block_has_no_trailing_newline():
    assert not format_classic(identify(MD5.example)).endswith("\n")


def test_summary_follows_the_name():
    lines = lines_of(identify(MYSQL41.example))

    assert lines[3:] == ["[+] MySQL 4.1+ - MySQL5, SHA-1(SHA-1($pass))"]


def test_context_hint_reorders_the_possible_section():
    lines = lines_of(identify(MD5.example, Context.WINDOWS, signatures=PAIR))

    assert lines[3:] == ["[+] NTLM", "[+] MD5"]


def test_input_line_can_be_left_out():
    # In interactive mode the prompt line already shows the hash.
    assert lines_of(identify(MD5.example, signatures=PAIR), show_input=False) == [
        "Possible Hashes:",
        "[+] MD5",
        "[+] NTLM",
    ]


# --- Tool modes ------------------------------------------------------------------


def test_modes_are_shown_in_an_aligned_column(tiered_signatures):
    result = identify(MD5.example, signatures=tiered_signatures)

    assert lines_of(result, show_modes=True)[2:] == [
        "Possible Hashes:",
        "[+] MD5       (hashcat 0 | john raw-md5)",
        "[+] NTLM      (hashcat 1000 | john nt)",
        "",
        "Least Possible Hashes:",
        "[+] Rare-128  (hashcat 99999 | john rare-128)",
    ]


def test_modes_are_hidden_by_default():
    assert "hashcat" not in format_classic(identify(BCRYPT.example))


def test_modes_show_only_the_tools_that_support_the_format():
    sigs = [
        _fake("Both", hashcat_mode=1, john_format="both"),
        _fake("Cat", hashcat_mode=2),
        _fake("John", john_format="john-only"),
        _fake("None"),
    ]

    assert lines_of(identify("xxx", signatures=sigs), show_modes=True)[3:] == [
        "[+] Both  (hashcat 1 | john both)",
        "[+] Cat   (hashcat 2)",
        "[+] John  (john john-only)",
        "[+] None",
    ]


def test_modes_move_to_their_own_line_when_the_label_is_too_long():
    summary = "a summary long enough to leave no room beside it for the modes"
    sigs = [
        _fake("Long", summary=summary, hashcat_mode=12345, john_format="long-format"),
        _fake("Short", hashcat_mode=1),
    ]

    lines = lines_of(identify("xxx", signatures=sigs), show_modes=True)[3:]

    assert lines == [
        f"[+] Long - {summary}",
        "    (hashcat 12345 | john long-format)",
        "[+] Short  (hashcat 1)",
    ]
    assert all(len(line) <= 80 for line in lines)


# --- No match, odd input ---------------------------------------------------------


def test_no_match_says_so_clearly_and_gives_a_hint():
    text = format_classic(identify("hello world"))
    lines = text.splitlines()

    assert lines[:3] == ["HASH: hello world", "", "[-] No known hash format matched this input."]
    assert "Possible Hashes:" not in text
    joined = " ".join(text.split())
    assert "Hint: check for extra characters" in joined
    assert "single quotes" in joined


def test_no_match_hint_can_leave_out_shell_quoting():
    # Nothing typed at the interactive prompt goes through a shell.
    joined = " ".join(format_classic(identify("zz"), shell_hint=False).split())

    assert "Hint: check for extra characters" in joined
    assert "single quotes" not in joined


def test_empty_input_is_shown_as_empty():
    lines = lines_of(identify("   "))

    assert lines[0] == "HASH: (empty)"
    assert "[-] No known hash format matched this input." in lines


def test_whitespace_inside_the_input_is_reported():
    lines = lines_of(identify("8743b52063cd8409 7a65d1633f5c74f5", signatures=PAIR))

    assert lines[:4] == [
        "HASH: 8743b52063cd84097a65d1633f5c74f5",
        "",
        "[*] Whitespace inside the input was ignored.",
        "",
    ]
    assert lines[4:] == ["Possible Hashes:", "[+] MD5", "[+] NTLM"]


def test_long_input_is_shortened_to_fit_80_columns():
    lines = lines_of(identify("ab" * 100))

    assert len(lines[0]) == 80
    assert lines[0].startswith("HASH: abab") and "..." in lines[0]


def test_control_characters_in_the_input_are_escaped():
    text = format_classic(identify("\x1b[31mred\x07"), style=ANSI)

    assert "\x1b[31mred" not in text
    assert "\\x1b[31mred\\x07" in text


# --- Every format ------------------------------------------------------------------


@pytest.mark.parametrize("sig", SIGNATURES, ids=lambda s: s.name)
@pytest.mark.parametrize("show_modes", [False, True], ids=["plain", "modes"])
def test_every_format_renders_as_ascii_within_80_columns(sig, show_modes):
    text = format_classic(identify(sig.example), show_modes=show_modes)

    assert text.isascii()
    assert all(len(line) <= 80 for line in text.splitlines())
    assert f"[+] {sig.name}" in text


# --- Color -------------------------------------------------------------------------


@pytest.mark.parametrize("raw", [MD5.example, MYSQL41.example, "hello world", ""])
@pytest.mark.parametrize("show_modes", [False, True], ids=["plain", "modes"])
def test_stripping_ansi_gives_the_plain_block(raw, show_modes, tiered_signatures):
    result = identify(raw, signatures=tiered_signatures)

    colored = format_classic(result, style=ANSI, show_modes=show_modes)

    assert strip_ansi(colored) == format_classic(result, show_modes=show_modes)


def test_color_scheme(tiered_signatures):
    result = identify(MD5.example, signatures=tiered_signatures)

    text = format_classic(result, style=ANSI, show_modes=True)

    assert "\x1b[1mPossible Hashes:\x1b[0m" in text  # headings bold
    assert "\x1b[32m[+]\x1b[0m \x1b[1mMD5\x1b[0m" in text  # possible: green marker, bold name
    assert "\x1b[2m[+]\x1b[0m Rare-128" in text  # least possible: dim marker, plain name
    assert "\x1b[2m(hashcat 0 | john raw-md5)\x1b[0m" in text  # modes dim
    assert "\x1b[33m[-] No known hash format" in format_classic(identify("zz"), style=ANSI)


# --- Checksums -----------------------------------------------------------------------


def _checksum(name, summary=""):
    return Signature(
        name=name,
        category=Category.CHECKSUM,
        tier=Tier.POSSIBLE,
        pattern=r"x+",
        summary=summary,
        strength=Strength.WEAK,
        strength_note="test",
        example="xxx",
        hashcat_mode=7,
    )


def test_checksums_are_labelled_as_checksums():
    sigs = [_checksum("Sum-A"), _checksum("Sum-B", summary="used by zlib"), _fake("Digest")]

    assert lines_of(identify("xxx", signatures=sigs))[3:] == [
        "[+] Digest",
        "[+] Sum-A - checksum",
        "[+] Sum-B - checksum, used by zlib",
    ]


def test_checksum_label_sits_before_the_modes():
    lines = lines_of(identify("xxx", signatures=[_checksum("Sum-A")]), show_modes=True)

    assert lines[3:] == ["[+] Sum-A - checksum  (hashcat 7)"]


@pytest.mark.parametrize("sig", SIGNATURES, ids=lambda s: s.name)
def test_every_checksum_in_the_registry_is_labelled(sig):
    line = next(
        line
        for line in lines_of(identify(sig.example))
        if line == f"[+] {sig.name}" or line.startswith(f"[+] {sig.name} - ")
    )

    assert ("checksum" in line) == (sig.category is Category.CHECKSUM)


# --- The real registry -----------------------------------------------------------------


def test_md5_hash_shows_both_tiers_with_the_registry():
    lines = lines_of(identify(MD5.example))

    assert lines[2:5] == ["Possible Hashes:", "[+] MD5", "[+] NTLM"]
    assert lines[5:7] == ["", "Least Possible Hashes:"]
    assert lines[7] == "[+] LM - LAN Manager"
    assert "[+] RIPEMD-128" in lines


def test_eight_hex_characters_are_reported_as_checksums():
    lines = lines_of(identify("c762de4a"))

    assert lines[2:6] == [
        "Possible Hashes:",
        "[+] CRC-32B - checksum, zlib, PNG, PHP crc32b",
        "[+] CRC-32 - checksum, CRC-32/BZIP2",
        "[+] Adler-32 - checksum, zlib",
    ]
