"""Command-line interface for hashident."""

from __future__ import annotations

import argparse
import dataclasses
import functools
import itertools
import os
import sys
import textwrap
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from typing import Any, NoReturn

from hashident import __version__, interactive, json_output
from hashident.banner import banner
from hashident.classic import format_classic
from hashident.engine import identify
from hashident.inputs import InputError, InputItem, gather
from hashident.models import Context, Result, Tier
from hashident.output import WIDTH, CompactTable, Positions, format_result, report_rule
from hashident.style import Styler
from hashident.terminal import COLOR_MODES, is_terminal, use_color
from hashident.tips import ContextTip, context_tips

_EPILOG = """\
Input: hashes given as arguments are reported first, in order, then the
lines of -f PATH. With neither, hashes are read from standard input when it
is piped or redirected. In files and piped input, blank lines and lines
starting with # are skipped. UTF-8 and UTF-16 (with a BOM) are understood.

Interactive mode: with no input at all on a terminal, hashident shows its
banner and a HASH: prompt, and identifies each hash you enter. An empty
line or Ctrl+C quits.

Output: each hash gets a block listing the formats it could be, under
"Possible Hashes" (the usual formats for its shape, or a format pinned by
its prefix; best first) and "Least Possible Hashes" (same shape, but
rarer). --show-modes adds each format's Hashcat mode and John format, and
--possible-only leaves out the second list. With several hashes, each
block is under a rule naming its argument or line.
  -v       a detailed report instead: a ranked table, then the reasons,
           strength and crack commands of each possible format; -vv adds
           those details for the least possible formats too
  --table  one row per hash instead (argument index or line number, best
           format, confidence, Hashcat mode), then a count per format

Banner: printed first when output goes to a terminal, and in interactive
mode. --no-banner hides it. Piped output and --json never have one.

JSON: --json prints one JSON object per hash, each on its own line (JSON
Lines), never colored. --json ignores -v, --table, --show-modes and
--possible-only: JSON always includes everything.
Keys, in schema_version 1: schema_version, input, source, position,
context, matched, candidates, tips. Each candidate: rank, format, category,
score, confidence, tier, hashcat_mode, john_format, strength, strength_note,
reasons, commands, notes. Each tip: context, top_format. Absent values are
null.

Quoting: hashes that contain $ (bcrypt, md5crypt, sha512crypt) or start
with * (MySQL) must be wrapped in single quotes, in PowerShell and bash
alike. Otherwise the shell expands them before hashident sees them:
  hashident '$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6'

Color: --color auto (the default) colors output only when it goes to a
terminal and the NO_COLOR environment variable is unset or empty. Order of
precedence: --color/--no-color, then NO_COLOR, then terminal detection.
Piped or redirected output is plain unless you pass --color always.

Exit status:
  0  every hash matched a known format (also after interactive mode)
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
    view = parser.add_mutually_exclusive_group()
    view.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="detailed report: reasons, strength and crack commands (-vv: more)",
    )
    view.add_argument(
        "--table",
        action="store_true",
        help="compact table, one row per hash",
    )
    parser.add_argument(
        "--possible-only",
        action="store_true",
        help="leave out the least possible formats",
    )
    parser.add_argument(
        "--show-modes",
        action="store_true",
        help="show each format's Hashcat mode and John format",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="do not print the banner",
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
            if args.json or args.table:
                # Formats meant for scripts and batches have no prompt.
                parser.print_help()
                return EXIT_ALL_MATCHED
            return _interactive(args)

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
            return tally.exit_status()

        style = Styler(enabled=use_color(args.color, sys.stdout, os.environ))
        if not args.no_banner and is_terminal(sys.stdout):
            print(banner(style))
            print()
        if args.possible_only:
            analysed = _possible_only(analysed)
        if args.table:
            _print_compact(analysed, CompactTable(_positions(args), style))
        else:
            _print_blocks(analysed, _renderer(args, style), several=several)
        return tally.exit_status()
    except InputError as exc:
        return _fail(parser, str(exc))


_Render = Callable[[Result, "tuple[ContextTip, ...]"], str]


def _renderer(args: argparse.Namespace, style: Styler, *, prompted: bool = False) -> _Render:
    """The function that turns one result into text, for the view asked for.

    ``prompted`` is for interactive mode: the hash is already on screen, on
    the prompt line, and it never went through a shell.
    """
    if args.verbose:
        show_low = args.verbose >= 2
        return lambda result, tips: format_result(
            result, tips=tips, style=style, show_low=show_low
        )
    return lambda result, tips: format_classic(
        result,
        style,
        show_modes=args.show_modes,
        show_input=not prompted,
        shell_hint=not prompted,
    )


def _interactive(args: argparse.Namespace) -> int:
    """Run the HASH: prompt until the user quits."""
    style = Styler(enabled=use_color(args.color, sys.stdout, os.environ))
    render_result = _renderer(args, style, prompted=True)

    def render(entered: str) -> str:
        result = identify(entered, context=args.context)
        tips = context_tips(result)
        if args.possible_only:
            result = _only_possible(result)
        return render_result(result, tips)

    intro = [] if args.no_banner else [banner(style), ""]
    intro += [style.muted(interactive.HOW_TO_QUIT), ""]
    interactive.run(render, intro=intro)
    return EXIT_ALL_MATCHED


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


def _only_possible(result: Result) -> Result:
    kept = tuple(cand for cand in result.candidates if cand.tier is Tier.POSSIBLE)
    return dataclasses.replace(result, candidates=kept)


def _possible_only(analysed: _Analysed) -> _Analysed:
    """Drop the least possible candidates from every result (--possible-only)."""
    for item, result, tips in analysed:
        yield item, _only_possible(result), tips


def _print_blocks(analysed: _Analysed, render: _Render, *, several: bool) -> None:
    """One block per value; with several values, each under a rule naming it."""
    for index, (item, result, tips) in enumerate(analysed):
        if several:
            if index:
                print()
            print(report_rule(item))
        print(render(result, tips))


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
