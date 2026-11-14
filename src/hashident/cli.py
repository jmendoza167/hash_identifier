"""Command-line interface for hashident."""

from __future__ import annotations

import argparse
import functools
import itertools
import os
import sys
import textwrap
from collections.abc import Sequence
from typing import Any, NoReturn

from hashident import __version__
from hashident.engine import identify
from hashident.inputs import InputError, gather
from hashident.models import Context
from hashident.output import WIDTH, CompactTable, Positions, format_result
from hashident.style import Styler
from hashident.terminal import COLOR_MODES, use_color
from hashident.tips import context_tips

_EPILOG = """\
Input: hashes given as arguments are reported first, in order, then the
lines of -f PATH. With neither, hashes are read from standard input when it
is piped or redirected. In files and piped input, blank lines and lines
starting with # are skipped. UTF-8 and UTF-16 (with a BOM) are understood.

Output: one hash gets a full report with reasons and crack commands.
Several hashes get a compact table, one row each (argument index or line
number, best format, confidence, Hashcat mode), then a count per format.

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

        style = Styler(enabled=use_color(args.color, sys.stdout, os.environ))
        first, second = next(items, None), next(items, None)
        if first is None:
            return _fail(parser, "no hashes found in the input; see hashident --help")
        if second is None:
            result = identify(first.value, context=args.context)
            print(format_result(result, tips=context_tips(result), style=style))
            matched = bool(result.candidates)
            return _exit_status(matched=matched, unmatched=not matched)

        table = CompactTable(_positions(args), style)
        print("\n".join(table.header()))
        for item in itertools.chain((first, second), items):
            result = identify(item.value, context=args.context)
            print(table.row(item, result, context_tips(result)))
        print("\n".join(table.footer()))
        return _exit_status(matched=table.matched, unmatched=table.unmatched)
    except InputError as exc:
        return _fail(parser, str(exc))


def _positions(args: argparse.Namespace) -> Positions:
    """What the compact table's first column counts, given the inputs used."""
    if not args.hashes:
        return Positions.LINE  # -f, or piped stdin
    return Positions.ARGUMENT if args.file is None else Positions.MIXED


def _exit_status(*, matched: int, unmatched: int) -> int:
    if not unmatched:
        return EXIT_ALL_MATCHED
    return EXIT_SOME_MATCHED if matched else EXIT_NONE_MATCHED


def _fail(parser: argparse.ArgumentParser, message: str) -> int:
    """Print a one-line error (never wrapped: it may hold a path)."""
    print(f"{parser.prog}: error: {message}", file=sys.stderr)
    return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
