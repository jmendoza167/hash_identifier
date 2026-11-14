"""Tests for -v/--verbose: full reports, including low-confidence details."""

import pytest

from hashident.cli import main
from hashident.engine import identify
from hashident.models import Context
from hashident.output import WIDTH, format_result
from hashident.signatures import BCRYPT, MD5, SHA1, SIGNATURES
from hashident.style import strip_ansi, visible_len
from hashident.tips import context_tips


def run(capsys, *argv):
    code = main(list(argv))
    return code, capsys.readouterr().out


def full(value, context=None, show_low=True):
    result = identify(value, context)
    return format_result(result, tips=context_tips(result), show_low=show_low)


@pytest.fixture(autouse=True)
def no_color_env(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)


# --- One value -----------------------------------------------------------------------


@pytest.mark.parametrize("flag", ["-v", "--verbose"])
def test_one_value_shows_low_confidence_detail_block(capsys, flag):
    _, out = run(capsys, flag, MD5.example)

    assert "2. NTLM - low confidence" in out
    assert "hashcat -m 1000 -a 0 hash.txt wordlist.txt" in out
    assert "john --format=nt --wordlist=wordlist.txt hash.txt" in out
    assert "Low-confidence candidates are shown in the table only." not in out
    assert out == full(MD5.example) + "\n"


def test_one_value_without_low_candidates_is_the_same_as_default(capsys):
    _, verbose = run(capsys, "-v", BCRYPT.example)
    _, default = run(capsys, BCRYPT.example)

    assert verbose == default


def test_default_one_value_still_hides_low_detail_blocks(capsys):
    _, out = run(capsys, MD5.example)

    assert "2. NTLM" not in out
    assert "Low-confidence candidates are shown in the table only." in out
    assert out == full(MD5.example, show_low=False) + "\n"


# --- Several values ---------------------------------------------------------------------


def test_several_values_show_a_full_report_each(capsys):
    values = [MD5.example, BCRYPT.example, "hello world"]

    _, out = run(capsys, "-v", *values)

    assert "Conf" not in out.splitlines()[0]  # no compact table
    for value in values:
        assert full(value) in out
    assert out.count("Reasons:") == 3  # MD5, NTLM (low), bcrypt


def test_reports_are_separated_by_labelled_rules(capsys):
    _, out = run(capsys, "-v", MD5.example, BCRYPT.example)

    lines = out.splitlines()
    rules = [line for line in lines if line.startswith("== ")]
    assert rules == [
        "== arg 1 " + "=" * (WIDTH - len("== arg 1 ")),
        "== arg 2 " + "=" * (WIDTH - len("== arg 2 ")),
    ]
    assert lines[0] == rules[0]
    second = lines.index(rules[1])
    assert lines[second - 1] == ""  # blank line before each later rule
    assert lines[second + 1].startswith("Input:")


def test_separator_rules_use_line_numbers_for_files(capsys, tmp_path):
    path = tmp_path / "hashes.txt"
    path.write_bytes(f"# header\n{MD5.example}\n\n{SHA1.example}\n".encode())

    _, out = run(capsys, "-v", BCRYPT.example, "-f", str(path))

    labels = [line.split()[1:3] for line in out.splitlines() if line.startswith("== ")]
    assert labels == [["arg", "1"], ["line", "2"], ["line", "4"]]


def test_no_summary_or_compact_note_in_verbose_mode(capsys):
    _, out = run(capsys, "-v", MD5.example, BCRYPT.example)

    assert "2 values:" not in out
    assert "Run hashident on a single value" not in out


def test_default_several_values_still_use_compact_table(capsys):
    _, out = run(capsys, MD5.example, BCRYPT.example)

    assert out.splitlines()[0].split() == ["Arg", "Value", "Format", "Conf", "Hashcat"]


# --- Exit codes and layout ----------------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        [MD5.example],
        ["nope"],
        [MD5.example, BCRYPT.example],
        ["hello", "world"],
        [MD5.example, "hello world"],
    ],
)
def test_exit_codes_match_default_mode(capsys, argv):
    default_code, _ = run(capsys, *argv)
    verbose_code, _ = run(capsys, "-v", *argv)

    assert verbose_code == default_code


@pytest.mark.parametrize("context", [None, *(c.value for c in Context)])
@pytest.mark.parametrize("color", ["never", "always"])
def test_verbose_lines_fit_80_columns(capsys, context, color):
    argv = ["-v", "--color", color, *(s.example for s in SIGNATURES), "hello world"]
    if context:
        argv[:0] = ["--from", context]

    _, out = run(capsys, *argv)

    assert ("\x1b[" in out) == (color == "always")
    for line in out.splitlines():
        assert visible_len(line) <= WIDTH, strip_ansi(line)


def test_help_documents_verbose(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])

    text = " ".join(capsys.readouterr().out.split())
    assert "-v, --verbose" in text
    assert "low-confidence" in text
