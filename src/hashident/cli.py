"""Command-line interface for hashident."""

from __future__ import annotations

import argparse
import sys
import textwrap
from collections.abc import Sequence
from typing import NoReturn

from hashident import __version__
from hashident.engine import identify
from hashident.models import Context
from hashident.output import format_result
from hashident.tips import context_tips

_EPILOG = """\
Quoting: hashes that contain $ (bcrypt, md5crypt, sha512crypt) or start
with * (MySQL) must be wrapped in single quotes, in PowerShell and bash
alike. Otherwise the shell expands them before hashident sees them:
  hashident '$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6'

Exit status: 0 if the hash matched a known format, 1 if it did not."""


class _Parser(argparse.ArgumentParser):
    """ArgumentParser whose error messages are wrapped to 80 columns."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        text = textwrap.fill(f"{self.prog}: error: {message}", width=80, subsequent_indent="  ")
        self.exit(2, text + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="hashident",
        description="Identify likely hash algorithms from a hash string.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
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
    parser.add_argument("hash", nargs="?", help="the hash to identify")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.hash is None:
        parser.print_help()
        return 0

    result = identify(args.hash, context=args.context)
    print(format_result(result, tips=context_tips(result)))
    return 0 if result.candidates else 1


if __name__ == "__main__":
    raise SystemExit(main())
