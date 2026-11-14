"""Keep README.md in step with the code.

* Every signature appears in the "Supported formats" table with the right
  Hashcat mode, John format and strength, and the table lists nothing else.
* Example output blocks are real: each block marked
  ``<!-- readme-test: output ARGS -->`` must equal what ``hashident ARGS``
  prints today, with any ``<!-- readme-test: file NAME -->`` blocks written
  out as files first.
"""

import re
import shlex
from pathlib import Path

import pytest

from hashident.cli import main
from hashident.signatures import SIGNATURES

README = Path(__file__).resolve().parent.parent / "README.md"
TEXT = README.read_text(encoding="utf-8")

_MARKED_BLOCK = re.compile(
    r"<!-- readme-test: (?P<kind>output|file) (?P<arg>[^\n]*?) -->\n"
    r"```text\n(?P<body>.*?)```",
    re.DOTALL,
)


def _section(heading: str) -> str:
    match = re.search(rf"^## {re.escape(heading)}\n(.*?)(?=^## |\Z)", TEXT, re.M | re.S)
    assert match, f"README has no '## {heading}' section"
    return match.group(1)


def _formats_table() -> dict[str, list[str]]:
    """Rows of the Supported formats table, keyed by format name."""
    rows = {}
    for line in _section("Supported formats").splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip().strip("`") for cell in line.strip("|").split("|")]
        if cells[0] in ("Format", "---"):
            continue
        rows[cells[0]] = cells[1:]
    return rows


def _marked_blocks(kind: str) -> list[tuple[str, str]]:
    return [(m["arg"], m["body"]) for m in _MARKED_BLOCK.finditer(TEXT) if m["kind"] == kind]


# --- Supported formats ----------------------------------------------------------


@pytest.mark.parametrize("sig", SIGNATURES, ids=lambda s: s.name)
def test_every_signature_is_in_the_formats_table(sig):
    rows = _formats_table()

    assert sig.name in rows, f"{sig.name} is missing from the README formats table"
    mode, john, strength = rows[sig.name]
    assert mode == ("-" if sig.hashcat_mode is None else str(sig.hashcat_mode))
    assert john == (sig.john_format or "-")
    assert strength.casefold() == sig.strength.value


def test_formats_table_lists_only_known_signatures():
    assert set(_formats_table()) == {sig.name for sig in SIGNATURES}


# --- Example output -------------------------------------------------------------


def test_readme_has_example_output_blocks():
    assert len(_marked_blocks("output")) >= 2


@pytest.mark.parametrize(
    ("args", "expected"), _marked_blocks("output"), ids=[a for a, _ in _marked_blocks("output")]
)
def test_example_output_is_current(capsys, monkeypatch, tmp_path, args, expected):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.chdir(tmp_path)
    for name, body in _marked_blocks("file"):
        (tmp_path / name).write_text(body, encoding="utf-8")

    main(shlex.split(args))

    assert capsys.readouterr().out == expected
