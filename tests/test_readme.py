"""Keep README.md in step with the code.

* Every signature appears in a "Supported formats" table with the right
  details, Hashcat mode, John format and strength; the tables list nothing
  else, and their headings add up to the number of formats.
* The banner shown in the README is the one the program prints, so its
  version and format count are current.
* Example output blocks are real: each block marked
  ``<!-- readme-test: output ARGS -->`` must equal what ``hashident ARGS``
  prints today, with any ``<!-- readme-test: file NAME -->`` blocks written
  out as files first.
* scripts/update_readme.py, which regenerates all of the above, leaves the
  README as it is: nobody needs to edit those parts by hand.
"""

import importlib.util
import re
import shlex
from pathlib import Path

import pytest

from hashident import __version__
from hashident.banner import banner
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
    details, mode, john, strength = rows[sig.name]
    assert details == (sig.summary or "-")
    assert mode == ("-" if sig.hashcat_mode is None else str(sig.hashcat_mode))
    assert john == (sig.john_format or "-")
    assert strength.casefold() == sig.strength.value


def test_formats_table_lists_only_known_signatures():
    assert set(_formats_table()) == {sig.name for sig in SIGNATURES}


def test_formats_are_grouped_under_headings_that_count_them():
    section = _section("Supported formats")
    headings = re.findall(r"^### (.+) \((\d+)\)$", section, re.M)

    assert len(headings) >= 5, "the formats should be grouped by category"
    assert sum(int(count) for _, count in headings) == len(SIGNATURES)
    for block in re.split(r"^### ", section, flags=re.M)[1:]:
        count = int(re.match(r".+ \((\d+)\)\n", block).group(1))
        rows = [line for line in block.splitlines() if line.startswith("| ")]
        # Two of the rows are the header and the rule under it.
        assert len(rows) - 2 == count, block.splitlines()[0]


def test_readme_says_how_many_formats_there_are():
    assert f"{len(SIGNATURES)} formats" in TEXT


# --- Banner and flags --------------------------------------------------------------


def test_readme_shows_the_current_banner():
    assert banner() in TEXT, "the banner in the README is out of date"
    assert f"hashident v{__version__}" in TEXT


@pytest.mark.parametrize(
    "flag",
    ["--show-modes", "--possible-only", "--no-banner", "--table", "-vv", "--json", "--from"],
)
def test_readme_documents_the_flag(flag):
    assert f"`{flag}" in TEXT



# --- Example output -------------------------------------------------------------


def test_readme_has_example_output_blocks():
    assert len(_marked_blocks("output")) >= 4


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


# --- The generator ---------------------------------------------------------------------

GENERATOR = README.parent / "scripts" / "update_readme.py"
RUN_IT = "run: python scripts/update_readme.py"


@pytest.fixture
def generator(monkeypatch):
    """scripts/update_readme.py as a module."""
    if not GENERATOR.exists():
        pytest.skip("scripts/ is not part of the sdist")
    monkeypatch.delenv("NO_COLOR", raising=False)
    spec = importlib.util.spec_from_file_location("update_readme", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_readme_is_what_the_generator_writes(generator):
    assert generator.render(TEXT) == TEXT, RUN_IT


def test_generator_leaves_the_working_directory_alone(generator, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    generator.render(TEXT)

    assert Path.cwd() == tmp_path
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    ("fresh", "stale"),
    [
        ("[+] MD5\n[+] NTLM\n", "[+] MD5\n"),
        (f"hashident v{__version__} ::", "hashident v0.0.1 ::"),
        (f"knows {len(SIGNATURES)} formats", "knows 3 formats"),
        ("| MD5 | - | 0 | `raw-md5` | Weak |", "| MD5 | - | 99 | `raw-md5` | Weak |"),
        ("| SHA-1 | - | 100 | `raw-sha1` | Weak |\n", ""),
    ],
    ids=["example-output", "banner", "format-count", "table-cell", "table-row"],
)
def test_generator_repairs_a_stale_readme(generator, tmp_path, capsys, fresh, stale):
    assert fresh in TEXT
    readme = tmp_path / "README.md"
    readme.write_text(TEXT.replace(fresh, stale), encoding="utf-8", newline="\n")

    assert generator.main(["--check", "--readme", str(readme)]) == 1
    assert "out of date" in capsys.readouterr().err
    assert readme.read_text(encoding="utf-8") != TEXT  # --check changes nothing

    assert generator.main(["--readme", str(readme)]) == 0
    assert readme.read_text(encoding="utf-8") == TEXT


def test_generator_check_passes_on_the_current_readme(generator, capsys):
    assert generator.main(["--check"]) == 0
    assert capsys.readouterr().err == ""


def test_readme_says_how_to_run_the_generator():
    development = _section("Development")

    assert "python scripts/update_readme.py" in development
    assert "--check" in development
    assert "tests/test_vectors.py" in development
