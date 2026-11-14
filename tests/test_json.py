"""Tests for --json output (schema version 1)."""

import io
import json
import sys

import pytest

from hashident import terminal
from hashident.cli import main
from hashident.commands import crack_commands, tool_notes
from hashident.json_output import SCHEMA_VERSION
from hashident.models import Context
from hashident.signatures import BCRYPT, MD5, MYSQL41, NTLM, SIGNATURES

TOP_KEYS = ["schema_version", "input", "source", "position", "context", "matched", "candidates", "tips"]
CANDIDATE_KEYS = [
    "rank",
    "format",
    "score",
    "confidence",
    "hashcat_mode",
    "john_format",
    "strength",
    "strength_note",
    "reasons",
    "commands",
    "notes",
]
TIP_KEYS = ["context", "top_format"]


class FakeStdin(io.TextIOWrapper):
    def __init__(self, data: bytes):
        super().__init__(io.BytesIO(data), encoding="utf-8")

    def isatty(self) -> bool:
        return False


def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def records(out):
    """Parse JSON Lines: every line must be one complete JSON object."""
    assert out.endswith("\n")
    return [json.loads(line) for line in out.splitlines()]


@pytest.fixture(autouse=True)
def no_color_env(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)


# --- Shape -------------------------------------------------------------------------


def test_one_value_is_a_single_json_object(capsys):
    code, out, err = run(capsys, "--json", MD5.example)

    assert (code, err) == (0, "")
    assert out.count("\n") == 1  # one line: also valid JSON Lines
    record = json.loads(out)
    assert isinstance(record, dict)
    assert list(record) == TOP_KEYS
    assert record["schema_version"] == SCHEMA_VERSION == 1


def test_several_values_are_one_object_per_line(capsys):
    _, out, _ = run(capsys, "--json", MD5.example, BCRYPT.example, "hello world")

    recs = records(out)
    assert [r["input"] for r in recs] == [MD5.example, BCRYPT.example, "hello world"]
    assert [(r["source"], r["position"]) for r in recs] == [("argument", n) for n in (1, 2, 3)]
    assert all(list(r) == TOP_KEYS for r in recs)


def test_file_records_carry_path_and_line_number(capsys, tmp_path):
    path = tmp_path / "hashes.txt"
    path.write_bytes(f"# header\n{MD5.example}\n\n{BCRYPT.example}\n".encode())

    _, out, _ = run(capsys, "--json", "-f", str(path))

    assert [(r["source"], r["position"]) for r in records(out)] == [(str(path), 2), (str(path), 4)]


def test_stdin_records_use_stdin_source(capsys, monkeypatch):
    monkeypatch.setattr(sys, "stdin", FakeStdin(f"{MD5.example}\n{NTLM.example}\n".encode()))

    _, out, _ = run(capsys, "--json")

    assert [(r["source"], r["position"]) for r in records(out)] == [("<stdin>", 1), ("<stdin>", 2)]


# --- Keys and types ---------------------------------------------------------------------


def test_md5_record_keys_and_types(capsys):
    _, out, _ = run(capsys, "--json", MD5.example)

    record = json.loads(out)
    assert record["input"] == MD5.example
    assert record["context"] is None
    assert record["matched"] is True
    assert [c["format"] for c in record["candidates"]] == ["MD5", "NTLM"]

    for rank, cand in enumerate(record["candidates"], start=1):
        assert list(cand) == CANDIDATE_KEYS
        assert cand["rank"] == rank
        assert isinstance(cand["score"], float)
        assert cand["confidence"] in {"high", "medium", "low"}
        assert isinstance(cand["hashcat_mode"], int)
        assert isinstance(cand["john_format"], str)
        assert cand["strength"] in {"weak", "moderate", "strong"}
        assert isinstance(cand["strength_note"], str) and cand["strength_note"]
        for key in ("reasons", "commands", "notes"):
            assert isinstance(cand[key], list)
            assert all(isinstance(s, str) for s in cand[key])

    md5, ntlm = record["candidates"]
    assert (md5["confidence"], ntlm["confidence"]) == ("medium", "low")
    assert md5["score"] > ntlm["score"]
    assert (md5["hashcat_mode"], md5["john_format"]) == (0, "raw-md5")


@pytest.mark.parametrize("sig", SIGNATURES, ids=lambda s: s.name)
def test_commands_and_notes_come_from_commands_module(capsys, sig):
    _, out, _ = run(capsys, "--json", sig.example)

    by_name = {s.name: s for s in SIGNATURES}
    for cand in json.loads(out)["candidates"]:
        listed = by_name[cand["format"]]
        assert cand["commands"] == list(crack_commands(listed))
        assert cand["notes"] == list(tool_notes(listed, sig.example))
        assert cand["hashcat_mode"] == listed.hashcat_mode
        assert cand["john_format"] == listed.john_format


def test_mysql_record_includes_tool_note(capsys):
    _, out, _ = run(capsys, "--json", MYSQL41.example)

    (cand,) = json.loads(out)["candidates"]
    assert cand["notes"] and "leading '*'" in cand["notes"][0]


def test_no_match_record(capsys):
    code, out, _ = run(capsys, "--json", "hello world")

    record = json.loads(out)
    assert code == 1
    assert (record["matched"], record["candidates"], record["tips"]) == (False, [], [])


def test_tips_are_included_as_data(capsys):
    _, out, _ = run(capsys, "--json", MD5.example)

    tips = json.loads(out)["tips"]
    assert tips == [{"context": "windows", "top_format": "NTLM"}]
    assert all(list(t) == TIP_KEYS for t in tips)


def test_from_sets_context_and_removes_tips(capsys):
    _, out, _ = run(capsys, "--json", "--from", "Windows", MD5.example)

    record = json.loads(out)
    assert record["context"] == "windows"
    assert record["tips"] == []
    assert record["candidates"][0]["format"] == "NTLM"


@pytest.mark.parametrize("context", [c.value for c in Context])
def test_every_context_value_round_trips(capsys, context):
    _, out, _ = run(capsys, "--json", "--from", context, BCRYPT.example)

    assert json.loads(out)["context"] == context


def test_input_is_the_value_as_received(capsys):
    _, out, _ = run(capsys, "--json", f"  {MD5.example}  ", "x")

    first = records(out)[0]
    assert first["input"] == f"  {MD5.example}  "
    assert first["matched"] is True


# --- No color, safe characters -------------------------------------------------------------


def test_json_is_never_colored(capsys, monkeypatch):
    monkeypatch.setattr(terminal, "_isatty", lambda stream: True)
    monkeypatch.setattr(terminal, "enable_windows_ansi", lambda stream: True)

    _, out, _ = run(capsys, "--json", "--color", "always", MD5.example, "hello world")

    assert "\x1b" not in out
    records(out)


def test_control_characters_and_non_ascii_are_escaped(capsys):
    _, out, _ = run(capsys, "--json", "\x1b[31mred", "café")

    assert "\x1b" not in out
    assert out.isascii()
    assert [r["input"] for r in records(out)] == ["\x1b[31mred", "café"]


# --- -v and exit codes ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv", [[MD5.example], [MD5.example, BCRYPT.example, "nope"], ["--from", "db", MD5.example]]
)
def test_verbose_does_not_change_json(capsys, argv):
    _, plain, _ = run(capsys, "--json", *argv)
    _, verbose, _ = run(capsys, "--json", "-v", *argv)

    assert verbose == plain


@pytest.mark.parametrize(
    "argv",
    [
        [MD5.example],
        ["hello world"],
        [MD5.example, BCRYPT.example],
        ["hello", "world"],
        [MD5.example, "hello world"],
    ],
)
def test_exit_codes_match_text_mode(capsys, argv):
    text_code, _, _ = run(capsys, *argv)
    json_code, _, _ = run(capsys, "--json", *argv)

    assert json_code == text_code


def test_empty_input_exits_2_with_no_json(capsys, tmp_path):
    path = tmp_path / "comments.txt"
    path.write_bytes(b"# nothing\n")

    code, out, err = run(capsys, "--json", "-f", str(path))

    assert (code, out) == (2, "")
    assert "no hashes found" in err


def test_missing_file_exits_2_with_no_json(capsys, tmp_path):
    code, out, err = run(capsys, "--json", "-f", str(tmp_path / "nope.txt"))

    assert (code, out) == (2, "")
    assert err.startswith("hashident: error: cannot read ")


# --- Help ------------------------------------------------------------------------------------


def test_help_documents_json_and_verbose(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])

    out = capsys.readouterr().out
    text = " ".join(out.split())
    assert "--json" in text and "-v, --verbose" in text
    assert "--json ignores -v" in text
    for key in TOP_KEYS + CANDIDATE_KEYS + TIP_KEYS:
        assert key in text, key
    assert all(len(line) <= 80 for line in out.splitlines())
