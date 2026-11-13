"""Tests for plain-text output."""

import pytest

from hashident.commands import crack_commands, tool_notes
from hashident.engine import identify
from hashident.models import Result
from hashident.output import MAX_INPUT_CHARS, WIDTH, format_result
from hashident.signatures import BCRYPT, MD5, MYSQL41, SIGNATURES


def render(raw):
    return format_result(identify(raw))


def table_rows(text):
    """The table's data rows: lines after the dashed rule, up to a blank line."""
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("-  ")) + 1
    rows = []
    for line in lines[start:]:
        if not line:
            break
        rows.append(line.split())
    return rows


def test_md5_table_lists_md5_then_ntlm():
    rows = table_rows(render(MD5.example))

    assert rows == [
        ["1", "MD5", "MEDIUM", "0", "raw-md5"],
        ["2", "NTLM", "LOW", "1000", "nt"],
    ]


def test_md5_has_detail_block_only_for_medium_and_above():
    text = render(MD5.example)

    assert "1. MD5 - medium confidence" in text
    assert "2. NTLM" not in text
    assert "hashcat -m 0 -a 0 hash.txt wordlist.txt" in text
    assert "john --format=raw-md5 --wordlist=wordlist.txt hash.txt" in text
    assert "hashcat -m 1000" not in text
    assert "Low-confidence candidates are shown in the table only." in text


def test_bcrypt_shows_single_high_candidate_with_command():
    text = render(BCRYPT.example)

    assert table_rows(text) == [["1", "bcrypt", "HIGH", "3200", "bcrypt"]]
    assert "1. bcrypt - high confidence" in text
    assert "hashcat -m 3200 -a 0 hash.txt wordlist.txt" in text
    assert "Strength: STRONG" in text
    assert "Low-confidence" not in text


def test_detail_block_tells_user_to_save_hash_first():
    assert "Crack it (save the hash to hash.txt first):" in render(MD5.example)


def test_mysql_with_asterisk_notes_stripping_it_for_hashcat():
    text = render(MYSQL41.example)

    assert "hashcat -m 300 -a 0 hash.txt wordlist.txt" in text
    joined = " ".join(text.split())  # undo line wrapping
    assert "For hashcat, save the hash without the leading '*'" in joined


def test_bare_mysql_note_tells_john_users_to_add_asterisk():
    (note,) = tool_notes(MYSQL41, MYSQL41.example[1:])
    assert "For john, add a leading '*'" in note


def test_other_formats_need_no_tool_notes():
    assert all(tool_notes(sig, sig.example) == () for sig in SIGNATURES if sig is not MYSQL41)


def test_every_signature_has_both_commands():
    for sig in SIGNATURES:
        assert len(crack_commands(sig)) == 2, sig.name


@pytest.mark.parametrize("raw", ["hello world", "", "   "])
def test_no_match_prints_helpful_message(raw):
    text = render(raw)

    assert "No known hash format matched this input." in text
    assert "Hint:" in text
    assert "single quotes" in text
    assert "#  Format" not in text


def test_empty_input_header():
    assert render("").startswith("Input:   (empty)")


def test_header_shows_normalized_input_and_length():
    lines = render(f"  {MD5.example}\n").splitlines()

    assert lines[:2] == [f"Input:   {MD5.example}", "Length:  32 characters"]


def test_long_input_is_truncated_in_the_middle():
    raw = "a" * 50 + "b" * 200 + "c" * 50
    shown = render(raw).splitlines()[0][len("Input:   ") :]

    keep = MAX_INPUT_CHARS - len("...")
    head, tail = (keep + 1) // 2, keep // 2
    assert len(shown) == MAX_INPUT_CHARS
    assert shown == "a" * head + "..." + "c" * tail
    assert "Length:  300 characters" in render(raw)


def test_non_ascii_and_control_characters_are_escaped():
    text = render("café\x1b[31m")

    assert text.isascii()
    assert "caf\\xe9\\x1b[31m" in text


@pytest.mark.parametrize("sig", SIGNATURES, ids=lambda s: s.name)
@pytest.mark.parametrize("context", [None, "windows", "linux", "web", "db"])
def test_output_fits_80_columns_and_is_ascii(sig, context):
    text = format_result(identify(sig.example, context=context))

    assert text.isascii()
    for line in text.splitlines():
        assert len(line) <= WIDTH, line


def test_no_match_and_long_input_fit_80_columns():
    for raw in ("hello world", "x" * 1000, "$" * 500):
        for line in render(raw).splitlines():
            assert len(line) <= WIDTH, line


def test_format_result_accepts_result_without_engine():
    assert "No known hash format matched" in format_result(Result(raw="zzz"))


# --- Step 9: context header, tips, wrapping ----------------------------------


def test_header_shows_context_when_given():
    lines = format_result(identify(MD5.example, context="windows")).splitlines()

    assert lines[:3] == [f"Input:   {MD5.example}", "Length:  32 characters", "Context: windows"]


def test_header_has_no_context_line_without_hint():
    assert "Context:" not in render(MD5.example)


def test_tip_line_format():
    from hashident.tips import context_tips

    result = identify(MD5.example)
    text = format_result(result, tips=context_tips(result))

    assert text.splitlines()[-1] == (
        "Tip: hash from a Windows system? Re-run with --from windows (NTLM ranks first)"
    )


def test_wrapped_strength_line_aligns_under_note_text():
    lines = render(BCRYPT.example).splitlines()
    prefix = "   Strength: STRONG - "
    i = next(i for i, line in enumerate(lines) if line.startswith(prefix))

    assert lines[i] == prefix + "Salted and deliberately slow, with a tunable cost factor"
    assert lines[i + 1] == " " * len(prefix) + "per guess."


def test_wrapped_note_aligns_under_note_text():
    lines = render(MYSQL41.example).splitlines()
    i = next(i for i, line in enumerate(lines) if line.startswith("   Note: "))

    assert lines[i + 1].startswith(" " * len("   Note: "))
    assert lines[i + 1][len("   Note: ")] != " "
