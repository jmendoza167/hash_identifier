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
from hashident.models import Context
from hashident.output import WIDTH, format_result
from hashident.style import Styler
from hashident.terminal import COLOR_MODES, use_color
from hashident.tips import context_tips

_EPILOG = """\
Quoting: hashes that contain $ (bcrypt, md5crypt, sha512crypt) or start
with * (MySQL) must be wrapped in single quotes, in PowerShell and bash
alike. Otherwise the shell expands them before hashident sees them:
  hashident '$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6'

Color: --color auto (the default) colors output only when it goes to a
terminal and the NO_COLOR environment variable is unset or empty. Order of
precedence: --color/--no-color, then NO_COLOR, then terminal detection.
Piped or redirected output is plain unless you pass --color always.

Exit status: 0 if the hash matched a known format, 1 if it did not,
2 for invalid arguments."""

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
    parser.add_argument("hash", nargs="?", help="the hash to identify")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.hash is None:
        parser.print_help()
        return 0

    style = Styler(enabled=use_color(args.color, sys.stdout, os.environ))
    result = identify(args.hash, context=args.context)
    print(format_result(result, tips=context_tips(result), style=style))
    return 0 if result.candidates else 1


if __name__ == "__main__":
    raise SystemExit(main())
