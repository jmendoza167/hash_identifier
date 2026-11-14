"""Plain-text rendering of results for the terminal.

``format_result`` is the full report for one value; ``CompactTable`` is the
one-row-per-value view used when there are several.

Output is pure ASCII and every line fits in ``WIDTH`` columns, so it renders
correctly in old Windows consoles. Commands are never wrapped, so they stay
copy-pasteable. Wrapped text always continues under the first character
after its label (a hanging indent), e.g.

    Strength: STRONG - Salted and deliberately slow, with a tunable cost
                       factor per guess.

Color is optional: layout (padding, wrapping) is always done on plain text
first, and the ``Styler`` is applied to finished pieces afterwards. Widths
are therefore measured in visible characters, and with ``PLAIN`` (the
default) no escape codes are ever produced.
"""

from __future__ import annotations

import textwrap
from collections import Counter
from collections.abc import Callable, Sequence
from enum import Enum

from hashident.commands import HASH_FILE, crack_commands, tool_notes
from hashident.inputs import ARGUMENT_SOURCE, InputItem
from hashident.models import Candidate, Confidence, Context, Result
from hashident.signatures import SIGNATURES
from hashident.style import PLAIN, Styler
from hashident.tips import ContextTip

WIDTH = 80
_LABEL_WIDTH = len("Context: ")
MAX_INPUT_CHARS = WIDTH - _LABEL_WIDTH
_INDENT = "   "

_TIP_QUESTIONS: dict[Context, str] = {
    Context.WINDOWS: "hash from a Windows system?",
    Context.LINUX: "hash from a Linux system?",
    Context.WEB: "hash from a web application?",
    Context.DB: "hash from a database?",
}


def format_result(
    result: Result,
    tips: Sequence[ContextTip] = (),
    style: Styler = PLAIN,
    *,
    show_low: bool = False,
) -> str:
    """Render ``result`` (and any re-run tips) as text, without a trailing newline.

    LOW-confidence candidates get a detail block only with ``show_low``
    (--verbose); otherwise they appear in the table alone.
    """
    lines = _header(result)
    lines.append("")

    if not result.candidates:
        lines += _no_match(style)
        return "\n".join(lines)

    lines += _table(result.candidates, style)
    for rank, cand in enumerate(result.candidates, start=1):
        if show_low or cand.confidence is not Confidence.LOW:
            lines.append("")
            lines += _details(rank, cand, result.normalized, style)

    if not show_low and any(c.confidence is Confidence.LOW for c in result.candidates):
        lines += ["", style.muted("Low-confidence candidates are shown in the table only.")]
    if tips:
        lines.append("")
        for tip in tips:
            text = (
                f"{_TIP_QUESTIONS[tip.context]} Re-run with --from "
                f"{tip.context.value} ({tip.top.name} ranks first)"
            )
            lines += [style.tip(line) for line in _wrap("", "Tip: ", text)]
    return "\n".join(lines)


def _header(result: Result) -> list[str]:
    value = result.normalized
    if not value:
        lines = [_label("Input") + "(empty)"]
    else:
        # Escaping control characters also stops input from injecting ANSI codes.
        shown = _shorten(_printable(value), MAX_INPUT_CHARS)
        noun = "character" if len(value) == 1 else "characters"
        lines = [_label("Input") + shown, _label("Length") + f"{len(value)} {noun}"]
    if result.context is not None:
        lines.append(_label("Context") + result.context.value)
    return lines


def report_rule(item: InputItem) -> str:
    """A full-width rule naming ``item``, put above each report in --verbose.

    e.g. ``== line 7 =====...``; the path is left out so it always fits.
    """
    kind = "arg" if item.source == ARGUMENT_SOURCE else "line"
    label = f"== {kind} {item.position} "
    return label + "=" * max(WIDTH - len(label), 2)


def _label(name: str) -> str:
    return f"{name}:".ljust(_LABEL_WIDTH)


def _printable(value: str) -> str:
    """Escape anything that is not printable ASCII, e.g. '\\x1b' or '\\xe9'."""
    return "".join(
        ch if " " <= ch <= "~" else ch.encode("unicode_escape").decode("ascii")
        for ch in value
    )


def _shorten(text: str, limit: int) -> str:
    """Fit ``text`` in ``limit`` characters by eliding its middle with '...'.

    Both ends are kept because hashes are usually told apart by their
    prefix ($2a$, *) and checked by their last characters.
    """
    if len(text) <= limit:
        return text
    keep = max(limit - len("..."), 0)
    head = (keep + 1) // 2
    return text[:head] + "..." + text[len(text) - (keep - head) :]


_Paint = Callable[[str], str]
_COLUMN_GAP = "  "


def _columns(
    cells: Sequence[str], widths: Sequence[int], paints: Sequence[_Paint | None] = ()
) -> str:
    """Join ``cells`` padded to ``widths``; trailing spaces are dropped."""
    parts = []
    for i, (cell, width) in enumerate(zip(cells, widths)):
        paint = paints[i] if i < len(paints) else None
        # Pad outside the color codes so padding is measured on visible text.
        parts.append((paint(cell) if paint else cell) + " " * (width - len(cell)))
    return _COLUMN_GAP.join(parts).rstrip(" ")


def _table(candidates: Sequence[Candidate], style: Styler) -> list[str]:
    header = ("#", "Format", "Confidence", "Hashcat", "John")
    rows: list[tuple[Sequence[str], Sequence[_Paint | None]]] = []
    for rank, c in enumerate(candidates, start=1):
        sig = c.signature
        cells = (
            str(rank),
            sig.name,
            c.confidence.name,
            "-" if sig.hashcat_mode is None else str(sig.hashcat_mode),
            sig.john_format or "-",
        )
        paints = (
            None,
            style.name,
            lambda text, level=c.confidence: style.confidence(text, level),
            None,
            None,
        )
        rows.append((cells, paints))

    widths = [max(len(cell) for cell in col) for col in zip(header, *(r for r, _ in rows))]
    return [
        _columns(header, widths),
        _columns(["-" * w for w in widths], widths),
        *(_columns(cells, widths, paints) for cells, paints in rows),
    ]


def _details(rank: int, cand: Candidate, value: str, style: Styler) -> list[str]:
    sig = cand.signature
    level = cand.confidence
    lines = [
        f"{rank}. {style.name(sig.name)} - "
        + style.confidence(f"{level.value} confidence", level)
    ]

    lines.append(f"{_INDENT}Reasons:")
    for reason in cand.reasons:
        lines += _wrap(_INDENT + "  ", "- ", reason)

    label = f"Strength: {sig.strength.name} - "
    styled_label = f"Strength: {style.strength(sig.strength.name, sig.strength)} - "
    lines += _wrap(_INDENT, label, sig.strength_note, styled_label)

    commands = crack_commands(sig)
    if commands:
        lines.append(f"{_INDENT}Crack it (save the hash to {HASH_FILE} first):")
        lines += [f"{_INDENT}  {style.command(cmd)}" for cmd in commands]
    for note in tool_notes(sig, value):
        lines += _wrap(_INDENT, "Note: ", note)
    return lines


def _no_match(style: Styler) -> list[str]:
    known = ", ".join(sig.name for sig in SIGNATURES)
    return [
        style.warning("No known hash format matched this input."),
        "",
        *_wrap(
            "",
            "Hint: ",
            "check for extra characters (quotes, spaces, a 'user:' prefix) "
            "or a truncated copy. Hashes containing $ must be wrapped in single "
            "quotes, or the shell changes them.",
        ),
        *_wrap("", "Known formats: ", f"{known}."),
    ]


def _wrap(indent: str, label: str, text: str, styled_label: str | None = None) -> list[str]:
    """Wrap ``indent + label + text``; continuation lines align after ``label``.

    Wrapping is computed on the plain ``label``; ``styled_label`` (the same
    text with color codes) is swapped in afterwards, so widths stay visible.
    """
    lines = textwrap.wrap(
        text,
        width=WIDTH,
        initial_indent=indent + label,
        subsequent_indent=indent + " " * len(label),
        break_on_hyphens=False,
    )
    if styled_label is not None and lines:
        lines[0] = indent + styled_label + lines[0][len(indent + label) :]
    return lines


# --- Compact view: one row per value ------------------------------------------


class Positions(Enum):
    """What the first column of the compact table counts."""

    ARGUMENT = "Arg"  # only positional arguments: their index
    LINE = "Line"  # only lines of a file or stdin: the line number
    MIXED = "Pos"  # both: "arg 1", "line 7"


NO_MATCH = "no match"
COMPACT_NOTE = "Run hashident on a single value to see its full report and crack commands."

# Fixed widths, so rows can be printed as values arrive instead of after
# the whole input has been read. Position widths fit 6-digit line numbers;
# a longer one pushes its row right and the value gets shorter to compensate.
_POSITION_WIDTH = {Positions.ARGUMENT: 6, Positions.LINE: 6, Positions.MIXED: len("line 999999")}
_FORMAT_WIDTH = max(len(NO_MATCH), *(len(sig.name) for sig in SIGNATURES))
_COMPACT_HEADER = ("Value", "Format", "Conf", "Hashcat")
# "Conf", not "Confidence": the 6 columns saved let 40-41 character hashes
# (SHA-1, MySQL 4.1+) show in full instead of being shortened.
_CONF_WIDTH = max(len("Conf"), *(len(level.name) for level in Confidence))
_TAIL_WIDTHS = (_FORMAT_WIDTH, _CONF_WIDTH, len("Hashcat"))
# Lets textwrap treat "MySQL 4.1+" as one word; same length as a space.
_NBSP = "\xa0"


class CompactTable:
    """Renders several values as a table, one row each, then a summary.

    Call ``header()`` once, ``row()`` per value, then ``footer()``. Rows are
    independent of each other, so a caller can print each one as soon as it
    is ready. ``row()`` also keeps the counts the footer and exit status use.
    """

    def __init__(self, positions: Positions, style: Styler = PLAIN) -> None:
        self._positions = positions
        self._style = style
        position_width = _POSITION_WIDTH[positions]
        value_width = WIDTH - position_width - sum(_TAIL_WIDTHS) - 4 * len(_COLUMN_GAP)
        self._widths = (position_width, value_width, *_TAIL_WIDTHS)
        self._formats: Counter[str] = Counter()
        self.unmatched = 0
        self._tip_contexts: set[Context] = set()
        self._tipped = 0

    @property
    def matched(self) -> int:
        return sum(self._formats.values())

    @property
    def total(self) -> int:
        return self.matched + self.unmatched

    def header(self) -> list[str]:
        names = (self._positions.value, *_COMPACT_HEADER)
        return [
            _columns(names, self._widths),
            _columns(["-" * w for w in self._widths], self._widths),
        ]

    def row(self, item: InputItem, result: Result, tips: Sequence[ContextTip] = ()) -> str:
        """One table row for ``item``; ``tips`` feed the footer's tip line."""
        style = self._style
        position = self._position(item)
        widths = list(self._widths)
        overflow = max(len(position) - widths[0], 0)
        widths[0] += overflow
        widths[1] = max(widths[1] - overflow, len("a...b"))
        shown = _shorten(_printable(result.normalized), widths[1]) or "(empty)"

        best = result.best
        if best is None:
            self.unmatched += 1
            cells = (position, shown, NO_MATCH, "-", "-")
            paints: tuple[_Paint | None, ...] = (None, None, style.warning)
        else:
            sig = best.signature
            self._formats[sig.name] += 1
            mode = "-" if sig.hashcat_mode is None else str(sig.hashcat_mode)
            cells = (position, shown, sig.name, best.confidence.name, mode)
            paints = (
                None,
                None,
                style.name,
                lambda text: style.confidence(text, best.confidence),
            )
        if tips:
            self._tipped += 1
            self._tip_contexts.update(tip.context for tip in tips)
        return _columns(cells, widths, paints)

    def footer(self) -> list[str]:
        """Blank line, summary, the --from tip if any, and the note."""
        style = self._style
        lines = [""]
        counts = [f"{n} {name}" for name, n in self._formats.most_common()]
        if self.unmatched:
            counts.append(f"{self.unmatched} {NO_MATCH}")
        noun = "value" if self.total == 1 else "values"
        text = ", ".join(c.replace(" ", _NBSP) for c in counts)
        lines += [
            line.replace(_NBSP, " ") for line in _wrap("", f"{self.total} {noun}: ", text)
        ]
        if self._tip_contexts:
            names = [c.value for c in Context if c in self._tip_contexts]
            choices = names[0] if len(names) == 1 else f"{', '.join(names[:-1])} or {names[-1]}"
            text = (
                f"--from {choices} would change the top format for "
                f"{self._tipped} of {self.total} {noun}."
            )
            lines += [style.tip(line) for line in _wrap("", "Tip: ", text)]
        lines.append(style.muted(COMPACT_NOTE))
        return lines

    def _position(self, item: InputItem) -> str:
        if self._positions is not Positions.MIXED:
            return str(item.position)
        kind = "arg" if item.source == ARGUMENT_SOURCE else "line"
        return f"{kind} {item.position}"
