"""Command-line interface for hashident."""

from __future__ import annotations

import argparse
import functools
import itertools
import os
import sys
import textwrap
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from typing import Any, NoReturn

from hashident import __version__, json_output
from hashident.engine import identify
from hashident.inputs import InputError, InputItem, gather
from hashident.models import Context, Result
from hashident.output import WIDTH, CompactTable, Positions, format_result, report_rule
from hashident.style import Styler
from hashident.terminal import COLOR_MODES, use_color
from hashident.tips import ContextTip, context_tips

_EPILOG = """\
Input: hashes given as arguments are reported first, in order, then the
lines of -f PATH. With neither, hashes are read from standard input when it
is piped or redirected. In files and piped input, blank lines and lines
starting with # are skipped. UTF-8 and UTF-16 (with a BOM) are understood.

Output: one hash gets a full report with reasons and crack commands.
Several hashes get a compact table, one row each (argument index or line
number, best format, confidence, Hashcat mode), then a count per format.
With -v, every hash gets a full report instead, under a rule naming it,
and low-confidence candidates get details as well.

JSON: --json prints one JSON object per hash, each on its own line (JSON
Lines), never colored. --json ignores -v: JSON always includes everything.
Keys, in schema_version 1: schema_version, input, source, position,
context, matched, candidates, tips. Each candidate: rank, format, score,
confidence, hashcat_mode, john_format, strength, strength_note, reasons,
commands, notes. Each tip: context, top_format. Absent values are null.

Quoting: hashes that contain $ (bcrypt, md5crypt, sha512crypt) or start
with * (MySQL) must be wrapped in single quotes, in PowerShell and bash
alike. Otherwise the shell expands them before hashident sees them:
  hashident '$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6'

Color: --color auto (the default) colors output only when it goes to a
terminal and the NO_COLOR environment variable is unset or empty. Order of
precedence: --color/--no-color, then NO_COLOR, then terminal detection.
Piped or redirected output is plain unless you pass --color always.

Exit status:
  0  every hash matched a known format
  1  none did
  3  some did and some did not
  2  invalid arguments, or input that cannot be read or has no hashes"""

EXIT_ALL_MATCHED = 0
EXIT_NONE_MATCHED = 1
EXIT_ERROR = 2
EXIT_SOME_MATCHED = 3

# Help and errors are always plain: argparse decides on its own color (3.14+)
# before --color is parsed, so it could not honour our flags anyway.
_PARSER_OPTIONS: dict[str, Any] = {"color": False} if sys.version_info >= (3, 14) else {}


class _Parser(argparse.ArgumentParser):
    """ArgumentParser whose error messages are wrapped to 80 columns."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        text = textwrap.fill(f"{self.prog}: error: {message}", width=WIDTH, subsequent_indent="  ")
        self.exit(2, text + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="hashident",
        description="Identify likely hash algorithms from a hash string.",
        epilog=_EPILOG,
        formatter_class=functools.partial(argparse.RawDescriptionHelpFormatter, width=WIDTH),
        **_PARSER_OPTIONS,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--from",
        dest="context",
        type=str.lower,
        choices=[c.value for c in Context],
        help="where the hash came from; ranks formats common there higher",
    )
    color = parser.add_mutually_exclusive_group()
    color.add_argument(
        "--color",
        type=str.lower,
        choices=COLOR_MODES,
        help="when to use color (default: auto)",
    )
    color.add_argument(
        "--no-color",
        dest="color",
        action="store_const",
        const="never",
        help="same as --color never",
    )
    parser.set_defaults(color="auto")
    parser.add_argument(
        "-f",
        "--file",
        metavar="PATH",
        help="read hashes from PATH, one per line; - means standard input",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="full report for every hash, with details of low-confidence candidates too",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print JSON, one object per hash per line (see JSON below)",
    )
    parser.add_argument("hashes", nargs="*", metavar="hash", help="a hash to identify")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        items = gather(args.hashes, args.file)
        if items is None:
            parser.print_help()
            return EXIT_ALL_MATCHED

        first, second = next(items, None), next(items, None)
        if first is None:
            return _fail(parser, "no hashes found in the input; see hashident --help")
        several = second is not None
        values = itertools.chain((first, second) if several else (first,), items)

        tally = _Tally()
        analysed = _analyse(values, args.context, tally)
        if args.json:
            # Checked before use_color, which may change the console's mode.
            _print_json(analysed)
        else:
            style = Styler(enabled=use_color(args.color, sys.stdout, os.environ))
            if several and not args.verbose:
                _print_compact(analysed, CompactTable(_positions(args), style))
            else:
                _print_reports(analysed, style, several=several, show_low=args.verbose)
        return tally.exit_status()
    except InputError as exc:
        return _fail(parser, str(exc))


_Analysed = Iterator[tuple[InputItem, Result, tuple[ContextTip, ...]]]


@dataclass
class _Tally:
    """Counts of values with and without a match, for the exit status."""

    matched: int = 0
    unmatched: int = 0

    def exit_status(self) -> int:
        if not self.unmatched:
            return EXIT_ALL_MATCHED
        return EXIT_SOME_MATCHED if self.matched else EXIT_NONE_MATCHED


def _analyse(items: Iterable[InputItem], context: str | None, tally: _Tally) -> _Analysed:
    """Identify each value as it arrives, counting matches into ``tally``."""
    for item in items:
        result = identify(item.value, context=context)
        if result.candidates:
            tally.matched += 1
        else:
            tally.unmatched += 1
        yield item, result, context_tips(result)


def _print_json(analysed: _Analysed) -> None:
    for item, result, tips in analysed:
        print(json_output.dumps(json_output.to_record(item, result, tips)))


def _print_reports(analysed: _Analysed, style: Styler, *, several: bool, show_low: bool) -> None:
    """Full reports; with several values, each under a rule naming it."""
    for index, (item, result, tips) in enumerate(analysed):
        if several:
            if index:
                print()
            print(report_rule(item))
        print(format_result(result, tips=tips, style=style, show_low=show_low))


def _print_compact(analysed: _Analysed, table: CompactTable) -> None:
    print("\n".join(table.header()))
    for item, result, tips in analysed:
        print(table.row(item, result, tips))
    print("\n".join(table.footer()))


def _positions(args: argparse.Namespace) -> Positions:
    """What the compact table's first column counts, given the inputs used."""
    if not args.hashes:
        return Positions.LINE  # -f, or piped stdin
    return Positions.ARGUMENT if args.file is None else Positions.MIXED


def _fail(parser: argparse.ArgumentParser, message: str) -> int:
    """Print a one-line error (never wrapped: it may hold a path)."""
    print(f"{parser.prog}: error: {message}", file=sys.stderr)
    return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
