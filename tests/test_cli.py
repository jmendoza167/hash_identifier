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


def test_md5_hash_prints_ranked_table_and_returns_zero(capsys):
    assert main(["8743b52063cd84097a65d1633f5c74f5"]) == 0

    out = capsys.readouterr().out
    assert "1  MD5" in out
    assert "2  NTLM" in out
    assert "hashcat -m 0 -a 0 hash.txt wordlist.txt" in out


def test_bcrypt_hash_prints_high_candidate(capsys):
    assert main(["$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6"]) == 0

    out = capsys.readouterr().out
    assert "1  bcrypt  HIGH" in out
    assert "hashcat -m 3200 -a 0 hash.txt wordlist.txt" in out


def test_mysql_hash_prints_asterisk_note(capsys):
    assert main(["*FCF7C1B8749CF99D88E5F34271D636178FB5D130"]) == 0

    out = " ".join(capsys.readouterr().out.split())
    assert "save the hash without the leading '*'" in out


def test_garbage_prints_no_match_and_returns_one(capsys):
    assert main(["hello world"]) == 1

    assert "No known hash format matched this input." in capsys.readouterr().out


def test_help_explains_quoting_hashes_with_dollar_signs(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])

    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert "single quotes" in out
    assert "PowerShell and bash" in out
    assert "hashident '$2a$05$" in out
    assert all(len(line) <= 80 for line in out.splitlines())
