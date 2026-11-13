"""Plain-text rendering of a Result for the terminal.

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
from collections.abc import Callable, Sequence

from hashident.commands import HASH_FILE, crack_commands, tool_notes
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
    result: Result, tips: Sequence[ContextTip] = (), style: Styler = PLAIN
) -> str:
    """Render ``result`` (and any re-run tips) as text, without a trailing newline."""
    lines = _header(result)
    lines.append("")

    if not result.candidates:
        lines += _no_match(style)
        return "\n".join(lines)

    lines += _table(result.candidates, style)
    for rank, cand in enumerate(result.candidates, start=1):
        if cand.confidence is not Confidence.LOW:
            lines.append("")
            lines += _details(rank, cand, result.normalized, style)

    if any(c.confidence is Confidence.LOW for c in result.candidates):
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
        shown = _printable(value)
        if len(shown) > MAX_INPUT_CHARS:
            keep = MAX_INPUT_CHARS - len("...")
            head = (keep + 1) // 2
            shown = shown[:head] + "..." + shown[len(shown) - (keep - head) :]
        noun = "character" if len(value) == 1 else "characters"
        lines = [_label("Input") + shown, _label("Length") + f"{len(value)} {noun}"]
    if result.context is not None:
        lines.append(_label("Context") + result.context.value)
    return lines


def _label(name: str) -> str:
    return f"{name}:".ljust(_LABEL_WIDTH)


def _printable(value: str) -> str:
    """Escape anything that is not printable ASCII, e.g. '\\x1b' or '\\xe9'."""
    return "".join(
        ch if " " <= ch <= "~" else ch.encode("unicode_escape").decode("ascii")
        for ch in value
    )


_Paint = Callable[[str], str]


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

    def line(cells: Sequence[str], paints: Sequence[_Paint | None] = ()) -> str:
        parts = []
        for i, (cell, width) in enumerate(zip(cells, widths)):
            paint = paints[i] if i < len(paints) else None
            # Pad outside the color codes so padding is measured on visible text.
            parts.append((paint(cell) if paint else cell) + " " * (width - len(cell)))
        return "  ".join(parts).rstrip(" ")

    return [
        line(header),
        line(["-" * w for w in widths]),
        *(line(cells, paints) for cells, paints in rows),
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
