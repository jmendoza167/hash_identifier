"""Regenerate the parts of README.md that mirror the code.

    python scripts/update_readme.py           rewrite README.md
    python scripts/update_readme.py --check   change nothing; exit 1 if out of date

Four things in the README are generated, so adding a format never means
editing them by hand:

* the format tables between the ``formats-table`` markers;
* the format count, wherever the text says "knows N formats";
* the banner;
* the body of every ``<!-- readme-test: output ARGS -->`` block, which is
  what ``hashident ARGS`` prints. Any ``<!-- readme-test: file NAME -->``
  block is written out as a file first, so examples can read it.

Everything else in the README is written by hand and left alone. Review the
diff after a run: a changed example means the program's output changed.

tests/test_readme.py fails when the README is not what this script writes.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import re
import shlex
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Use this checkout's code, whatever is installed.
sys.path.insert(0, str(ROOT / "src"))

from hashident.banner import banner  # noqa: E402
from hashident.cli import main as hashident_main  # noqa: E402
from hashident.models import Signature  # noqa: E402
from hashident.signatures import (  # noqa: E402
    SIGNATURES,
    application,
    checksums,
    crypt,
    databases,
    ldap,
    network,
    raw,
    salted,
)

README = ROOT / "README.md"

# --- Format tables --------------------------------------------------------------------

# The application module holds three kinds of format. These two sets name the
# ones that are not web applications; anything else in it is listed as one.
WINDOWS = {
    "SAM (LM:NT)",
    "pwdump",
    "Domain Cached Credentials",
    "Domain Cached Credentials 2",
    "RAdmin v2.x",
}
GAMES = {"Lineage II C4", "SHA-1(MaNGOS)"}

TABLES_START = "<!-- formats-table: start -->"
TABLES_END = "<!-- formats-table: end -->"


def groups() -> list[tuple[str, Sequence[Signature]]]:
    """The README's headings, each with its formats, in the order shown."""
    apps = application.SIGNATURES
    return [
        ("Raw hashes", raw.SIGNATURES),
        ("Salted, keyed and nested hashes", salted.SIGNATURES),
        ("crypt and key-derivation formats", crypt.SIGNATURES),
        ("Web applications", [sig for sig in apps if sig.name not in WINDOWS | GAMES]),
        ("Databases", databases.SIGNATURES),
        ("Windows", [sig for sig in apps if sig.name in WINDOWS]),
        ("Network devices and protocols", network.SIGNATURES),
        ("LDAP", ldap.SIGNATURES),
        ("Games", [sig for sig in apps if sig.name in GAMES]),
        ("Checksums, not cryptographic hashes", checksums.SIGNATURES),
    ]


def _cell(value: str) -> str:
    """One table cell. Text with a dollar sign is marked as code, because
    GitHub would otherwise read what is between two of them as a formula."""
    if "|" in value or "`" in value:
        raise ValueError(f"cannot put {value!r} in a table cell")
    return f"`{value}`" if "$" in value else value


def format_tables() -> str:
    grouped = groups()
    listed = sum(len(sigs) for _, sigs in grouped)
    if listed != len(SIGNATURES):
        raise SystemExit(
            f"the README groups cover {listed} formats but the registry has "
            f"{len(SIGNATURES)}: add the new signature module to groups()"
        )
    parts = []
    for heading, sigs in grouped:
        rows = [
            "| Format | Details | Hashcat mode | John format | Strength |",
            "| --- | --- | --- | --- | --- |",
        ]
        for sig in sigs:
            mode = "-" if sig.hashcat_mode is None else str(sig.hashcat_mode)
            john = f"`{sig.john_format}`" if sig.john_format else "-"
            rows.append(
                f"| {_cell(sig.name)} | {_cell(sig.summary or '-')} | {mode} | {john} "
                f"| {sig.strength.value.capitalize()} |"
            )
        parts.append(f"### {heading} ({len(sigs)})\n\n" + "\n".join(rows))
    return "\n\n".join(parts)


def _update_tables(text: str) -> str:
    if TABLES_START not in text or TABLES_END not in text:
        raise SystemExit(f"the README has no {TABLES_START} ... {TABLES_END} markers")
    before, rest = text.split(TABLES_START, 1)
    _, after = rest.split(TABLES_END, 1)
    return f"{before}{TABLES_START}\n{format_tables()}\n{TABLES_END}{after}"


# --- Format count and banner ------------------------------------------------------------

_COUNT = re.compile(r"\bknows \d+ formats\b")
# From the first line of the art to the line that names the version.
_BANNER = re.compile(
    re.escape(banner().splitlines()[0]) + r"\n(?:[^\n]*\n)*? hashident v[^\n]*"
)


def _update_count(text: str) -> str:
    return _COUNT.sub(f"knows {len(SIGNATURES)} formats", text)


def _update_banner(text: str) -> str:
    current = banner()
    return _BANNER.sub(lambda _: current, text)


# --- Example output -----------------------------------------------------------------------

_BLOCK = re.compile(
    r"(?P<head><!-- readme-test: (?P<kind>output|file) (?P<arg>[^\n]*?) -->\n```text\n)"
    r"(?P<body>.*?)(?P<tail>```)",
    re.DOTALL,
)


def _run(args: str, files: Sequence[tuple[str, str]]) -> str:
    """What ``hashident ARGS`` prints, run in a scratch directory holding ``files``."""
    previous = Path.cwd()
    with tempfile.TemporaryDirectory() as scratch:
        for name, body in files:
            Path(scratch, name).write_text(body, encoding="utf-8")
        os.chdir(scratch)
        try:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                hashident_main(shlex.split(args))
            return output.getvalue()
        finally:
            os.chdir(previous)


def _update_examples(text: str) -> str:
    files = [(m["arg"], m["body"]) for m in _BLOCK.finditer(text) if m["kind"] == "file"]

    def refresh(match: re.Match[str]) -> str:
        if match["kind"] != "output":
            return match[0]
        return match["head"] + _run(match["arg"], files) + match["tail"]

    return _BLOCK.sub(refresh, text)


# --- Command line -------------------------------------------------------------------------


def render(text: str) -> str:
    """``text``, a README, with every generated part brought up to date."""
    for update in (_update_tables, _update_count, _update_banner, _update_examples):
        text = update(text)
    return text


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Regenerate the parts of README.md that mirror the code."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="change nothing; exit with 1 if the README is out of date",
    )
    parser.add_argument(
        "--readme",
        type=Path,
        default=README,
        metavar="PATH",
        help="the file to update (default: the README.md of this checkout)",
    )
    args = parser.parse_args(argv)

    current = args.readme.read_text(encoding="utf-8")
    updated = render(current)
    if updated == current:
        if not args.check:
            print(f"{args.readme.name} is up to date")
        return 0
    if args.check:
        print(
            f"{args.readme.name} is out of date; run: python scripts/update_readme.py",
            file=sys.stderr,
        )
        return 1
    args.readme.write_text(updated, encoding="utf-8", newline="\n")
    print(f"{args.readme.name} updated; review the diff before committing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
