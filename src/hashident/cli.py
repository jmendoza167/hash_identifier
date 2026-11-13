"""Command-line interface for hashident."""

from __future__ import annotations

import argparse
import functools
import os
import sys
import textwrap
from collections.abc import Sequence
from typing import Any, NoReturn

from hashident import __version__
from hashident.engine import identify
from hashident.inputs import InputError, gather
from hashident.models import Context
from hashident.output import WIDTH, format_result
from hashident.style import Styler
from hashident.terminal import COLOR_MODES, use_color
from hashident.tips import context_tips

_EPILOG = """\
Input: hashes given as arguments are reported first, in order, then the
lines of -f PATH. With neither, hashes are read from standard input when it
is piped or redirected. In files and piped input, blank lines and lines
starting with # are skipped. UTF-8 and UTF-16 (with a BOM) are understood.

Quoting: hashes that contain $ (bcrypt, md5crypt, sha512crypt) or start
with * (MySQL) must be wrapped in single quotes, in PowerShell and bash
alike. Otherwise the shell expands them before hashident sees them:
  hashident '$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6'

Color: --color auto (the default) colors output only when it goes to a
terminal and the NO_COLOR environment variable is unset or empty. Order of
precedence: --color/--no-color, then NO_COLOR, then terminal detection.
Piped or redirected output is plain unless you pass --color always.

Exit status: 0 if every hash matched a known format, 1 if any did not,
2 for invalid arguments or input that cannot be read."""

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
    reported = unmatched = 0
    try:
        items = gather(args.hashes, args.file)
        if items is None:
            parser.print_help()
            return 0

        style = Styler(enabled=use_color(args.color, sys.stdout, os.environ))
        for item in items:
            result = identify(item.value, context=args.context)
            if reported:
                print()
            print(format_result(result, tips=context_tips(result), style=style))
            reported += 1
            unmatched += not result.candidates
    except InputError as exc:
        return _fail(parser, str(exc))
    if not reported:
        return _fail(parser, "no hashes found in the input; see hashident --help")
    return 1 if unmatched else 0


def _fail(parser: argparse.ArgumentParser, message: str) -> int:
    """Print a one-line error (never wrapped: it may hold a path) and return 2."""
    print(f"{parser.prog}: error: {message}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
