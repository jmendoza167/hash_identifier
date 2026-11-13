"""Tests for reading input values: arguments, files and stdin."""

import codecs
import io
import sys

import pytest

from hashident.cli import main
from hashident.engine import identify
from hashident.inputs import InputError, InputItem, gather
from hashident.output import format_result
from hashident.tips import context_tips

MD5_HASH = "8743b52063cd84097a65d1633f5c74f5"
SHA1_HASH = "b89eaac7e61417341b710b727768294d0e6a277b"
BCRYPT_HASH = "$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6"


class FakeStdin(io.TextIOWrapper):
    """A stand-in for sys.stdin: real bytes underneath, configurable isatty()."""

    def __init__(self, data: bytes = b"", tty: bool = False):
        super().__init__(io.BytesIO(data), encoding="utf-8")
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def _report(value: str) -> str:
    """What the CLI printed for a single value before multiple inputs existed."""
    result = identify(value, context=None)
    return format_result(result, tips=context_tips(result)) + "\n"


# --- gather(): positional arguments -------------------------------------------


def test_positional_arguments_keep_order_and_index():
    items = list(gather([MD5_HASH, BCRYPT_HASH]))

    assert items == [
        InputItem(MD5_HASH, "argument", 1),
        InputItem(BCRYPT_HASH, "argument", 2),
    ]


def test_positional_arguments_are_not_filtered_or_stripped():
    # Only lines read from a file or stdin are cleaned up; arguments are the
    # user's exact words (and a single one must behave exactly as before).
    items = list(gather(["", "#x", " a "]))

    assert [item.value for item in items] == ["", "#x", " a "]


# --- gather(): files ----------------------------------------------------------


def test_file_skips_blanks_and_comments_and_handles_crlf_and_utf8_bom(tmp_path):
    path = tmp_path / "hashes.txt"
    path.write_bytes(
        codecs.BOM_UTF8
        + b"# leading comment\r\n"
        + MD5_HASH.encode()
        + b"\r\n"
        + b"\r\n"
        + b"   \r\n"
        + b"  # indented comment\r\n"
        + b"  "
        + BCRYPT_HASH.encode()
        + b" \t\r\n"
    )

    items = list(gather([], str(path)))

    assert items == [
        InputItem(MD5_HASH, str(path), 2),
        InputItem(BCRYPT_HASH, str(path), 6),
    ]


def test_utf8_bom_does_not_hide_a_comment_on_the_first_line(tmp_path):
    path = tmp_path / "hashes.txt"
    path.write_bytes(codecs.BOM_UTF8 + b"#comment\n" + MD5_HASH.encode() + b"\n")

    assert [item.value for item in gather([], str(path))] == [MD5_HASH]


def test_utf16le_file_with_bom(tmp_path):
    # What `... > hashes.txt` produces in Windows PowerShell 5.1.
    path = tmp_path / "hashes.txt"
    text = f"# comment\r\n{MD5_HASH}\r\n\r\n{BCRYPT_HASH}\r\n"
    path.write_bytes(codecs.BOM_UTF16_LE + text.encode("utf-16-le"))

    items = list(gather([], str(path)))

    assert items == [
        InputItem(MD5_HASH, str(path), 2),
        InputItem(BCRYPT_HASH, str(path), 4),
    ]


def test_utf16be_file_with_bom(tmp_path):
    path = tmp_path / "hashes.txt"
    path.write_bytes(codecs.BOM_UTF16_BE + f"{MD5_HASH}\n".encode("utf-16-be"))

    assert [item.value for item in gather([], str(path))] == [MD5_HASH]


def test_last_line_without_newline_is_read(tmp_path):
    path = tmp_path / "hashes.txt"
    path.write_bytes(MD5_HASH.encode() + b"\n" + SHA1_HASH.encode())

    items = list(gather([], str(path)))

    assert items == [InputItem(MD5_HASH, str(path), 1), InputItem(SHA1_HASH, str(path), 2)]


def test_invalid_bytes_are_replaced_not_fatal(tmp_path):
    path = tmp_path / "hashes.txt"
    path.write_bytes(b"ab\xff\xfecd\n" + MD5_HASH.encode() + b"\n")

    values = [item.value for item in gather([], str(path))]

    assert values == ["ab��cd", MD5_HASH]


def test_truncated_utf16_does_not_crash(tmp_path):
    path = tmp_path / "hashes.txt"
    path.write_bytes(codecs.BOM_UTF16_LE + "abc".encode("utf-16-le") + b"d")

    values = [item.value for item in gather([], str(path))]

    assert values == ["abc�"]


def test_empty_file_yields_nothing(tmp_path):
    path = tmp_path / "empty.txt"
    path.write_bytes(b"")

    assert list(gather([], str(path))) == []


def test_file_is_read_lazily_line_by_line(tmp_path):
    # Taking the first item must not need the whole file: a big file is
    # consumed in chunks, so only part of it has been read at that point.
    path = tmp_path / "big.txt"
    path.write_bytes((MD5_HASH.encode() + b"\n") * 200_000)

    items = gather([], str(path))
    first = next(items)
    second = next(items)
    items.close()

    assert (first.position, second.position) == (1, 2)


def test_arguments_come_before_file_lines(tmp_path):
    path = tmp_path / "hashes.txt"
    path.write_bytes(SHA1_HASH.encode() + b"\n")

    items = list(gather([MD5_HASH], str(path)))

    assert items == [
        InputItem(MD5_HASH, "argument", 1),
        InputItem(SHA1_HASH, str(path), 1),
    ]


def test_missing_file_raises_input_error_before_any_item(tmp_path):
    missing = tmp_path / "nope.txt"

    # Raised by gather() itself, not on first iteration, so the CLI can fail
    # before printing reports for the positional arguments.
    with pytest.raises(InputError) as exc_info:
        gather([MD5_HASH], str(missing))

    assert "nope.txt" in str(exc_info.value)


def test_directory_raises_input_error(tmp_path):
    with pytest.raises(InputError):
        list(gather([], str(tmp_path)))


# --- gather(): stdin ----------------------------------------------------------


def test_no_arguments_reads_piped_stdin(monkeypatch):
    data = f"# comment\n{MD5_HASH}\r\n\n{BCRYPT_HASH}\n".encode()
    monkeypatch.setattr(sys, "stdin", FakeStdin(data))

    items = list(gather([]))

    assert items == [
        InputItem(MD5_HASH, "<stdin>", 2),
        InputItem(BCRYPT_HASH, "<stdin>", 4),
    ]


def test_no_arguments_on_a_terminal_means_no_input(monkeypatch):
    monkeypatch.setattr(sys, "stdin", FakeStdin(b"ignored\n", tty=True))

    assert gather([]) is None


def test_no_arguments_without_any_stdin_means_no_input(monkeypatch):
    # pythonw.exe and some service launchers start Python with no stdin at all.
    monkeypatch.setattr(sys, "stdin", None)

    assert gather([]) is None


def test_arguments_do_not_read_stdin(monkeypatch):
    monkeypatch.setattr(sys, "stdin", FakeStdin(SHA1_HASH.encode() + b"\n"))

    assert [item.value for item in gather([MD5_HASH])] == [MD5_HASH]


def test_dash_file_reads_stdin_even_on_a_terminal(monkeypatch):
    monkeypatch.setattr(sys, "stdin", FakeStdin(MD5_HASH.encode() + b"\n", tty=True))

    assert list(gather([], "-")) == [InputItem(MD5_HASH, "<stdin>", 1)]


def test_stdin_utf16le_with_bom(monkeypatch):
    # cmd.exe `type hashes.txt | hashident` passes the file's bytes through.
    data = codecs.BOM_UTF16_LE + f"{MD5_HASH}\r\n".encode("utf-16-le")
    monkeypatch.setattr(sys, "stdin", FakeStdin(data))

    assert [item.value for item in gather([])] == [MD5_HASH]


def test_text_only_stdin_replacement_is_supported(monkeypatch):
    # io.StringIO has no .buffer; it is what tests and embedders often use.
    monkeypatch.setattr(sys, "stdin", io.StringIO(f"﻿#c\n{MD5_HASH}\n"))

    assert list(gather([])) == [InputItem(MD5_HASH, "<stdin>", 2)]


# --- CLI ----------------------------------------------------------------------


def test_single_value_output_is_unchanged(capsys):
    assert main([MD5_HASH]) == 0

    assert capsys.readouterr().out == _report(MD5_HASH)


def test_single_unmatched_value_still_returns_one(capsys):
    assert main(["hello world"]) == 1

    assert capsys.readouterr().out == _report("hello world")


def test_several_arguments_print_reports_separated_by_a_blank_line(capsys):
    assert main([MD5_HASH, BCRYPT_HASH]) == 0

    assert capsys.readouterr().out == _report(MD5_HASH) + "\n" + _report(BCRYPT_HASH)


def test_exit_status_is_one_if_any_value_is_unmatched(capsys):
    assert main([MD5_HASH, "hello world", BCRYPT_HASH]) == 1

    out = capsys.readouterr().out
    assert out == "\n".join(_report(v) for v in (MD5_HASH, "hello world", BCRYPT_HASH))


def test_cli_reads_file_option(capsys, tmp_path):
    path = tmp_path / "hashes.txt"
    path.write_bytes(f"# two hashes\r\n{MD5_HASH}\r\n\r\n{BCRYPT_HASH}\r\n".encode())

    for flag in ("-f", "--file"):
        assert main([flag, str(path)]) == 0
        assert capsys.readouterr().out == _report(MD5_HASH) + "\n" + _report(BCRYPT_HASH)


def test_cli_reads_piped_stdin(capsys, monkeypatch):
    monkeypatch.setattr(sys, "stdin", FakeStdin(f"{MD5_HASH}\n{BCRYPT_HASH}\n".encode()))

    assert main([]) == 0

    assert capsys.readouterr().out == _report(MD5_HASH) + "\n" + _report(BCRYPT_HASH)


def test_cli_dash_file_reads_stdin(capsys, monkeypatch):
    monkeypatch.setattr(sys, "stdin", FakeStdin(MD5_HASH.encode() + b"\n"))

    assert main(["-f", "-"]) == 0

    assert capsys.readouterr().out == _report(MD5_HASH)


def test_cli_no_arguments_on_a_terminal_prints_help(capsys, monkeypatch):
    monkeypatch.setattr(sys, "stdin", FakeStdin(tty=True))

    assert main([]) == 0

    out = capsys.readouterr().out
    assert out.startswith("usage: hashident")
    assert "--file" in out


def test_cli_missing_file_exits_2_with_short_error(capsys, tmp_path):
    missing = tmp_path / "nope.txt"

    assert main([MD5_HASH, "-f", str(missing)]) == 2

    captured = capsys.readouterr()
    assert captured.out == ""  # fails before reporting the positional argument
    assert captured.err.startswith("hashident: error: ")
    assert "nope.txt" in captured.err
    assert "Traceback" not in captured.err
    assert len(captured.err.splitlines()) == 1


def test_cli_input_without_any_values_exits_2(capsys, tmp_path):
    path = tmp_path / "comments.txt"
    path.write_bytes(b"# nothing here\n\n")

    assert main(["-f", str(path)]) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("hashident: error: ")
    assert "Traceback" not in captured.err


def test_help_stays_within_80_columns(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])

    out = capsys.readouterr().out
    assert "--file PATH" in out  # 3.13+ prints "-f, --file PATH"
    assert all(len(line) <= 80 for line in out.splitlines())
