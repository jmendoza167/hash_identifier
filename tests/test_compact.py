"""Tests for the compact multi-value view and the exit status."""

import io
import sys

import pytest

from hashident.cli import main
from hashident.engine import identify
from hashident.inputs import ARGUMENT_SOURCE, InputItem
from hashident.models import Context
from hashident.output import WIDTH, CompactTable, Positions, format_result
from hashident.signatures import (
    BCRYPT,
    MD5,
    MYSQL41,
    NTLM,
    SHA1,
    SHA256,
    SHA512CRYPT,
    SIGNATURES,
)
from hashident.style import ANSI, strip_ansi, visible_len
from hashident.tips import ContextTip, context_tips

NOTE = "Run hashident on a single value to see its full report and crack commands."


class FakeStdin(io.TextIOWrapper):
    def __init__(self, data: bytes):
        super().__init__(io.BytesIO(data), encoding="utf-8")

    def isatty(self) -> bool:
        return False


def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def rows(out):
    """Data rows of the compact table, each split on runs of 2+ spaces."""
    lines = out.splitlines()
    start = 2  # header line, then the dashed rule
    end = lines.index("")
    return [[cell for cell in line.split("  ") if cell] for line in lines[start:end]]


def cells(row):
    return [cell.strip() for cell in row]


@pytest.fixture(autouse=True)
def no_color_env(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)


# --- Table ---------------------------------------------------------------------


def test_several_values_print_compact_table_and_summary(capsys):
    code, out, _ = run(capsys, MD5.example, BCRYPT.example, "hello world")

    lines = out.splitlines()
    assert lines[0].split() == ["Arg", "Value", "Format", "Conf", "Hashcat"]
    assert set(lines[1].replace(" ", "")) == {"-"}
    assert [cells(r) for r in rows(out)] == [
        ["1", MD5.example, "MD5", "MEDIUM", "0"],
        # 60 characters shortened to the 42-column Value cell, middle elided.
        ["2", "$2a$05$LhayLxezLhK1L...pEmm134uzrQlFvQJLF6", "bcrypt", "HIGH", "3200"],
        ["3", "hello world", "no match", "-", "-"],
    ]
    assert "3 values: 1 MD5, 1 bcrypt, 1 no match" in lines
    assert lines[-1] == NOTE
    assert code == 3


def test_compact_view_has_no_detail_blocks(capsys):
    _, out, _ = run(capsys, MD5.example, BCRYPT.example)

    assert "Reasons:" not in out
    assert "hashcat -m" not in out
    assert "Input:" not in out


def test_columns_line_up_with_the_header(capsys):
    _, out, _ = run(capsys, MD5.example, "hello world", BCRYPT.example)

    header, _rule, *body = out.splitlines()
    for name in ("Value", "Format", "Conf", "Hashcat"):
        column = header.index(name)
        for line in body[:3]:
            assert line[column - 2 : column] == "  ", (name, line)
            assert line[column] != " ", (name, line)


@pytest.mark.parametrize("positions", [Positions.ARGUMENT, Positions.LINE])
@pytest.mark.parametrize("sig", [SHA1, MYSQL41], ids=lambda s: s.name)
def test_sha1_and_mysql_fit_unshortened(positions, sig):
    # 40 and 41 characters: the longest common hashes that should show in full.
    table = CompactTable(positions)

    row = table.row(InputItem(sig.example, "hashes.txt", 999_999), identify(sig.example))

    assert row.split("  ")[1].strip() == sig.example
    assert len(row) <= WIDTH


def test_long_value_is_shortened_in_the_middle():
    value = "a" * 40 + "MIDDLE" + "b" * 40
    table = CompactTable(Positions.ARGUMENT)

    row = table.row(InputItem(value, ARGUMENT_SOURCE, 1), identify(value))

    shown = row.split()[1]
    assert shown.startswith("aaaa") and shown.endswith("bbbb")
    assert "..." in shown and "MIDDLE" not in shown
    assert len(row) <= WIDTH


def test_empty_and_control_characters_are_shown_safely(capsys):
    _, out, _ = run(capsys, "", "\x1b[31mred", "--color", "always")

    assert "(empty)" in out
    assert "\x1b[31mred" not in out
    assert "\\x1b[31mred" in out


# --- Positions -------------------------------------------------------------------


def test_file_rows_show_line_numbers(capsys, tmp_path):
    path = tmp_path / "hashes.txt"
    path.write_bytes(f"# header\n{MD5.example}\n\n{BCRYPT.example}\n".encode())

    _, out, _ = run(capsys, "-f", str(path))

    assert out.splitlines()[0].startswith("Line  ")
    assert [r[0].strip() for r in rows(out)] == ["2", "4"]


def test_piped_stdin_rows_show_line_numbers(capsys, monkeypatch):
    monkeypatch.setattr(sys, "stdin", FakeStdin(f"{MD5.example}\n{SHA1.example}\n".encode()))

    _, out, _ = run(capsys)

    assert out.splitlines()[0].startswith("Line  ")
    assert [r[0].strip() for r in rows(out)] == ["1", "2"]


def test_arguments_and_file_lines_together_are_labelled(capsys, tmp_path):
    path = tmp_path / "hashes.txt"
    path.write_bytes(f"\n{BCRYPT.example}\n".encode())

    _, out, _ = run(capsys, MD5.example, "-f", str(path))

    assert out.splitlines()[0].startswith("Pos  ")
    assert [r[0].strip() for r in rows(out)] == ["arg 1", "line 2"]


def test_huge_line_number_still_fits_80_columns():
    table = CompactTable(Positions.MIXED)
    item = InputItem(BCRYPT.example, "big.txt", 123_456_789)

    row = table.row(item, identify(BCRYPT.example))

    assert row.startswith("line 123456789  ")
    assert "bcrypt" in row
    assert len(row) <= WIDTH


# --- Summary ---------------------------------------------------------------------


def test_summary_orders_formats_by_count_with_no_match_last(capsys):
    _, out, _ = run(capsys, "nope", BCRYPT.example, MD5.example, NTLM.example, "x")

    # NTLM.example looks like MD5 too, and MD5 ranks first for it.
    assert "5 values: 2 MD5, 1 bcrypt, 2 no match" in out.splitlines()


def test_summary_ties_keep_first_appearance_order(capsys):
    _, out, _ = run(capsys, SHA256.example, BCRYPT.example)

    assert "2 values: 1 SHA-256, 1 bcrypt" in out.splitlines()


def test_long_summary_wraps_without_splitting_a_format_name():
    table = CompactTable(Positions.ARGUMENT)
    for sig in SIGNATURES:
        value = sig.example
        table.row(InputItem(value, ARGUMENT_SOURCE, 1), identify(value, Context.DB))
    for n in range(20):
        table.row(InputItem(f"x{n}", ARGUMENT_SOURCE, 1), identify(f"x{n}"))

    footer = table.footer()

    summary = footer[1 : footer.index(NOTE)]
    assert len(summary) > 1
    assert summary[0].startswith("30 values: 2 MD5, 1 SHA-1, ")
    assert all(len(line) <= WIDTH for line in summary)
    assert summary[1].startswith(" " * len("30 values: "))
    joined = " ".join(line.strip() for line in summary)
    assert "MySQL 4.1+" in joined
    assert joined.endswith("20 no match")


# --- Tip ---------------------------------------------------------------------------


def test_one_combined_tip_when_a_context_changes_a_top_format(capsys):
    _, out, _ = run(capsys, MD5.example, BCRYPT.example, NTLM.example)

    tips = [line for line in out.splitlines() if line.startswith("Tip:")]
    assert tips == ["Tip: --from windows would change the top format for 2 of 3 values."]


def test_no_tip_when_from_is_given(capsys):
    _, out, _ = run(capsys, "--from", "web", MD5.example, BCRYPT.example)

    assert "Tip:" not in out


def test_no_tip_when_no_context_changes_anything(capsys):
    _, out, _ = run(capsys, BCRYPT.example, SHA512CRYPT.example)

    assert "Tip:" not in out


@pytest.mark.parametrize(
    ("contexts", "expected"),
    [
        ([Context.DB, Context.WINDOWS], "--from windows or db"),
        ([Context.WEB, Context.LINUX, Context.WINDOWS], "--from windows, linux or web"),
    ],
)
def test_tip_combines_contexts_in_a_fixed_order(contexts, expected):
    table = CompactTable(Positions.ARGUMENT)
    result = identify(MD5.example)
    tips = [ContextTip(context=c, top=NTLM) for c in contexts]
    table.row(InputItem(MD5.example, ARGUMENT_SOURCE, 1), result, tips)
    table.row(InputItem(BCRYPT.example, ARGUMENT_SOURCE, 2), identify(BCRYPT.example))

    tip_lines = [line for line in table.footer() if line.startswith("Tip:")]

    assert tip_lines == [f"Tip: {expected} would change the top format for 1 of 2 values."]


# --- Exit status ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        ([MD5.example], 0),
        (["hello world"], 1),
        ([MD5.example, BCRYPT.example], 0),
        (["hello", "world"], 1),
        ([MD5.example, "hello world"], 3),
        (["hello world", BCRYPT.example, SHA1.example], 3),
        (["--from", "nowhere", MD5.example], 2),
    ],
)
def test_exit_status(capsys, argv, expected):
    if expected == 2:
        with pytest.raises(SystemExit) as exc_info:
            main(argv)
        assert exc_info.value.code == 2
    else:
        assert main(argv) == expected


def test_empty_input_still_exits_2(capsys, tmp_path):
    path = tmp_path / "comments.txt"
    path.write_bytes(b"# nothing\n\n")

    code, out, err = run(capsys, "-f", str(path))

    assert code == 2
    assert out == ""
    assert "no hashes found" in err


def test_missing_file_exits_2(capsys, tmp_path):
    code, out, err = run(capsys, "-f", str(tmp_path / "nope.txt"))

    assert (code, out) == (2, "")
    assert err.startswith("hashident: error: cannot read ")


def test_help_documents_exit_status(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])

    lines = capsys.readouterr().out.splitlines()
    start = lines.index("Exit status:")
    assert lines[start + 1 : start + 5] == [
        "  0  every hash matched a known format",
        "  1  none did",
        "  3  some did and some did not",
        "  2  invalid arguments, or input that cannot be read or has no hashes",
    ]


# --- Single value unchanged ------------------------------------------------------------


@pytest.mark.parametrize("value", [MD5.example, BCRYPT.example, "hello world", ""])
def test_single_value_still_prints_the_full_report(capsys, value):
    _, out, _ = run(capsys, value)

    result = identify(value)
    assert out == format_result(result, tips=context_tips(result)) + "\n"


# --- Width and color ---------------------------------------------------------------------

ALL_VALUES = [sig.example for sig in SIGNATURES] + [
    "hello world",
    "",
    "x" * 300,
    "\x1b[31m" + "e" * 100,
    "é" * 50,
]


@pytest.mark.parametrize("context", [None, *(c.value for c in Context)])
@pytest.mark.parametrize("color", ["never", "always"])
def test_compact_lines_fit_80_visible_columns(capsys, tmp_path, context, color):
    path = tmp_path / "hashes.txt"
    path.write_text("\n".join(ALL_VALUES * 3), encoding="utf-8")
    argv = ["--color", color, MD5.example, "-f", str(path)]
    if context:
        argv[:0] = ["--from", context]

    _, out, _ = run(capsys, *argv)

    assert ("\x1b[" in out) == (color == "always")
    for line in out.splitlines():
        assert visible_len(line) <= WIDTH, strip_ansi(line)
    assert strip_ansi(out).isascii()


def test_stripping_ansi_gives_plain_compact_output(capsys):
    argv = [MD5.example, BCRYPT.example, "hello world", NTLM.example]

    _, colored, _ = run(capsys, "--color", "always", *argv)
    _, plain, _ = run(capsys, *argv)

    assert strip_ansi(colored) == plain


def test_compact_color_scheme(capsys):
    _, out, _ = run(capsys, "--color", "always", MD5.example, BCRYPT.example, "nope")

    assert "\x1b[1mMD5\x1b[0m" in out  # format name bold
    assert "\x1b[33mMEDIUM\x1b[0m" in out  # MEDIUM yellow
    assert "\x1b[32mHIGH\x1b[0m" in out  # HIGH green
    assert "\x1b[33mno match\x1b[0m" in out  # no match yellow, like the full report
    assert f"\x1b[2m{NOTE}\x1b[0m" in out  # note muted
