"""Tests for choosing a view: classic (default), -v report, --table, and the banner."""

import io
import json
import sys

import pytest

from hashident import __version__
from hashident.classic import format_classic
from hashident.cli import main
from hashident.engine import identify
from hashident.output import format_result
from hashident.signatures import BCRYPT, MD5
from hashident.tips import context_tips

BANNER_LINE = f"hashident v{__version__}"


@pytest.fixture(autouse=True)
def no_color_env(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)


def run(capsys, *argv):
    code = main(list(argv))
    return code, capsys.readouterr().out


# --- Classic is the default --------------------------------------------------------


def test_one_value_prints_the_classic_block(capsys):
    code, out = run(capsys, MD5.example)

    assert code == 0
    assert out == format_classic(identify(MD5.example)) + "\n"
    assert out.startswith(f"HASH: {MD5.example}\n\nPossible Hashes:\n[+] MD5\n[+] NTLM\n")


def test_several_values_print_one_block_each_under_a_rule(capsys):
    _, out = run(capsys, MD5.example, BCRYPT.example, "not-a-hash")

    lines = out.splitlines()
    rules = [i for i, line in enumerate(lines) if line.startswith("== ")]
    assert [lines[i].split()[:3] for i in rules] == [
        ["==", "arg", "1"],
        ["==", "arg", "2"],
        ["==", "arg", "3"],
    ]
    assert rules[0] == 0
    for index in rules[1:]:
        assert lines[index - 1] == ""  # blank line before each later rule
    assert all(lines[i + 1].startswith("HASH: ") for i in rules)
    assert format_classic(identify(BCRYPT.example)) in out
    assert out.count("Possible Hashes:") == 2
    assert out.count("[-] No known hash format matched this input.") == 1


def test_file_lines_are_named_by_line_number(capsys, tmp_path):
    path = tmp_path / "hashes.txt"
    path.write_text(f"# comment\n{MD5.example}\n\n{BCRYPT.example}\n", encoding="utf-8")

    _, out = run(capsys, "-f", str(path))

    assert [line.split()[:3] for line in out.splitlines() if line.startswith("== ")] == [
        ["==", "line", "2"],
        ["==", "line", "4"],
    ]


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        ([MD5.example], 0),
        (["not-a-hash"], 1),
        ([MD5.example, "not-a-hash"], 3),
    ],
    ids=["matched", "unmatched", "mixed"],
)
def test_exit_status_is_unchanged(capsys, argv, expected):
    code, _ = run(capsys, *argv)

    assert code == expected


def test_show_modes_adds_hashcat_and_john(capsys):
    _, out = run(capsys, "--show-modes", MD5.example)

    assert "[+] MD5   (hashcat 0 | john raw-md5)\n[+] NTLM  (hashcat 1000 | john nt)\n" in out


# --- --possible-only ---------------------------------------------------------------


def test_least_possible_section_is_shown_by_default(capsys, tiered_cli):
    _, out = run(capsys, MD5.example)

    assert "Least Possible Hashes:\n[+] Rare-128\n" in out


def test_possible_only_hides_the_least_possible_section(capsys, tiered_cli):
    code, out = run(capsys, "--possible-only", MD5.example)

    assert code == 0
    assert "[+] NTLM" in out
    assert "Least Possible" not in out
    assert "Rare-128" not in out


def test_possible_only_also_trims_the_detailed_report(capsys, tiered_cli):
    _, out = run(capsys, "-v", "--possible-only", MD5.example)

    assert "2  NTLM" in out
    assert "3  Rare-128" not in out
    assert "Low-confidence" not in out


def test_possible_only_does_not_filter_json(capsys, tiered_cli):
    _, out = run(capsys, "--json", "--possible-only", MD5.example)

    assert [c["format"] for c in json.loads(out)["candidates"]] == ["MD5", "NTLM", "Rare-128"]


# --- -v: the detailed report -------------------------------------------------------


@pytest.mark.parametrize("flag", ["-v", "--verbose"])
def test_verbose_prints_the_detailed_report(capsys, flag):
    _, out = run(capsys, flag, MD5.example)

    result = identify(MD5.example)
    assert out == format_result(result, tips=context_tips(result)) + "\n"
    assert "Reasons:" in out
    assert "hashcat -m 0 -a 0 hash.txt wordlist.txt" in out


def test_verbose_keeps_least_possible_formats_in_the_table_only(capsys, tiered_cli):
    _, out = run(capsys, "-v", MD5.example)

    assert "3  Rare-128  LOW" in out
    assert "3. Rare-128" not in out
    assert "Low-confidence candidates are shown in the table only." in out


def test_double_verbose_adds_details_for_least_possible_formats(capsys, tiered_cli):
    _, out = run(capsys, "-vv", MD5.example)

    assert "3. Rare-128 - low confidence" in out
    assert "hashcat -m 99999 -a 0 hash.txt wordlist.txt" in out
    assert "Low-confidence candidates are shown in the table only." not in out


# --- --table: one row per value ----------------------------------------------------


def test_table_prints_one_row_per_value(capsys):
    _, out = run(capsys, "--table", MD5.example, BCRYPT.example)

    lines = out.splitlines()
    assert lines[0].split() == ["Arg", "Value", "Format", "Conf", "Hashcat"]
    assert lines[2].split() == ["1", MD5.example, "MD5", "MEDIUM", "0"]
    assert "2 values: 1 MD5, 1 bcrypt" in out
    assert "Possible Hashes:" not in out


def test_table_works_for_a_single_value(capsys):
    _, out = run(capsys, "--table", MD5.example)

    assert out.splitlines()[0].split() == ["Arg", "Value", "Format", "Conf", "Hashcat"]
    assert "1 value: 1 MD5" in out


def test_table_note_points_at_the_detailed_report(capsys):
    _, out = run(capsys, "--table", MD5.example)

    assert out.splitlines()[-1] == (
        "Run hashident -v on a value to see its reasons and crack commands."
    )


def test_table_and_verbose_cannot_be_combined(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["-v", "--table", MD5.example])

    assert exc_info.value.code == 2
    assert "not allowed with" in capsys.readouterr().err


# --- Banner ------------------------------------------------------------------------


class _Terminal(io.StringIO):
    def isatty(self):
        return True


@pytest.fixture
def on_terminal(monkeypatch):
    """Run the command line with a terminal for stdout; returns what it printed."""

    def run_on_terminal(*argv):
        stream = _Terminal()
        # Patched here, not during fixture setup: pytest's own capture puts
        # its stream back in sys.stdout when the test body starts.
        with monkeypatch.context() as patch:
            patch.setattr(sys, "stdout", stream)
            main(list(argv))
        return stream.getvalue()

    return run_on_terminal


@pytest.mark.parametrize("view", [[], ["-v"], ["--table"]], ids=["classic", "report", "table"])
def test_banner_comes_first_on_a_terminal(on_terminal, view):
    out = on_terminal("--no-color", *view, MD5.example)

    lines = out.splitlines()
    index = next(i for i, line in enumerate(lines) if BANNER_LINE in line)
    assert lines[index + 1] == ""
    assert out.count(BANNER_LINE) == 1
    assert out.index(BANNER_LINE) < out.index("MD5")


def test_banner_is_printed_once_for_several_values(on_terminal):
    out = on_terminal("--no-color", MD5.example, BCRYPT.example)

    assert out.count(BANNER_LINE) == 1


def test_no_banner_hides_it_on_a_terminal(on_terminal):
    out = on_terminal("--no-color", "--no-banner", MD5.example)

    assert out == format_classic(identify(MD5.example)) + "\n"


def test_banner_is_left_out_of_piped_output(capsys):
    _, out = run(capsys, MD5.example)

    assert BANNER_LINE not in out


def test_json_never_has_a_banner(on_terminal):
    out = on_terminal("--json", MD5.example)

    assert json.loads(out)["matched"] is True


# --- Help --------------------------------------------------------------------------


def test_help_documents_the_views_and_new_flags(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])

    out = capsys.readouterr().out
    text = " ".join(out.split())
    for flag in ("--no-banner", "--possible-only", "--show-modes", "--table", "-v, --verbose"):
        assert flag in out, flag
    assert "Possible Hashes" in text
    assert "-vv" in text
    assert "interactive" in text.casefold()
    assert all(len(line) <= 80 for line in out.splitlines())
