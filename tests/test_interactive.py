"""Tests for interactive mode: no input on a terminal starts a HASH: prompt."""

import io
import sys

import pytest

from hashident import __version__
from hashident.cli import main
from hashident.signatures import BCRYPT, MD5

BANNER_LINE = f"hashident v{__version__}"


class _Terminal(io.StringIO):
    def isatty(self):
        return True


@pytest.fixture(autouse=True)
def terminal_stdin(monkeypatch):
    monkeypatch.setattr(sys, "stdin", _Terminal())
    monkeypatch.delenv("NO_COLOR", raising=False)


@pytest.fixture
def typed(monkeypatch):
    """Feed lines to the prompt; an exception instance in the list is raised."""
    prompts = []

    def feed(*entries):
        pending = list(entries)

        def fake_input(prompt=""):
            prompts.append(prompt)
            entry = pending.pop(0)
            if isinstance(entry, BaseException):
                raise entry
            return entry

        monkeypatch.setattr("builtins.input", fake_input)
        return prompts

    return feed


def run(capsys, *argv):
    code = main(list(argv))
    return code, capsys.readouterr().out


def test_no_arguments_on_a_terminal_starts_the_prompt(capsys, typed):
    prompts = typed(MD5.example, "")

    code, out = run(capsys)

    assert code == 0
    assert prompts == ["HASH: ", "HASH: "]
    assert BANNER_LINE in out
    assert "Possible Hashes:\n[+] MD5\n[+] NTLM\n" in out
    assert out.endswith("Bye!\n")


def test_prompt_loops_until_an_empty_line(capsys, typed):
    prompts = typed(MD5.example, BCRYPT.example, "not-a-hash", "   ", MD5.example)

    _, out = run(capsys)

    assert len(prompts) == 4  # the whitespace-only line ends the session
    assert out.count("Possible Hashes:") == 2
    assert "[+] bcrypt" in out
    assert "[-] No known hash format matched this input." in out


@pytest.mark.parametrize("stop", [KeyboardInterrupt(), EOFError()], ids=["ctrl-c", "eof"])
def test_ctrl_c_and_end_of_input_say_bye(capsys, typed, stop):
    typed(MD5.example, stop)

    code, out = run(capsys)

    assert code == 0
    assert "[+] MD5" in out
    # The interrupted prompt line is finished before the goodbye.
    assert out.endswith("\nBye!\n")


def test_results_do_not_repeat_the_hash_the_prompt_already_shows(capsys, typed):
    typed(MD5.example, "")

    _, out = run(capsys)

    assert MD5.example not in out


def test_banner_is_followed_by_how_to_quit(capsys, typed):
    typed("")

    _, out = run(capsys)

    assert "empty line or Ctrl+C" in out
    assert out.index(BANNER_LINE) < out.index("empty line or Ctrl+C")


def test_no_banner_hides_the_banner_but_keeps_the_prompt(capsys, typed):
    prompts = typed(MD5.example, "")

    _, out = run(capsys, "--no-banner")

    assert BANNER_LINE not in out
    assert prompts == ["HASH: ", "HASH: "]
    assert "[+] MD5" in out
    assert out.endswith("Bye!\n")


def test_no_match_hint_does_not_mention_shell_quoting(capsys, typed):
    typed("zz", "")

    _, out = run(capsys)

    assert "Hint: check for extra characters" in out
    assert "single quotes" not in out


def test_options_apply_to_every_result(capsys, typed):
    typed(MD5.example, "")

    _, out = run(capsys, "--from", "windows", "--show-modes")

    assert "[+] NTLM  (hashcat 1000 | john nt)\n[+] MD5   (hashcat 0 | john raw-md5)\n" in out


def test_verbose_gives_the_detailed_report_at_the_prompt(capsys, typed):
    typed(MD5.example, "")

    _, out = run(capsys, "-v")

    assert "1. MD5 - medium confidence" in out
    assert "hashcat -m 0 -a 0 hash.txt wordlist.txt" in out


def test_output_is_ascii_within_80_columns(capsys, typed):
    typed(MD5.example, "zz", "")

    _, out = run(capsys)

    assert out.isascii()
    assert all(len(line) <= 80 for line in out.splitlines())


@pytest.mark.parametrize("flag", ["--json", "--table"])
def test_script_formats_show_help_instead_of_a_prompt(capsys, typed, flag):
    prompts = typed("")

    code, out = run(capsys, flag)

    assert code == 0
    assert out.startswith("usage: hashident")
    assert prompts == []
