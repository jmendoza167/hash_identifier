"""Plain-text rendering of a Result for the terminal.

Output is pure ASCII and every line fits in ``WIDTH`` columns, so it renders
correctly in old Windows consoles. Commands are never wrapped, so they stay
copy-pasteable.
"""

from __future__ import annotations

import textwrap
from collections.abc import Sequence

from hashident.commands import HASH_FILE, crack_commands, tool_notes
from hashident.models import Candidate, Confidence, Result
from hashident.signatures import SIGNATURES

WIDTH = 80
MAX_INPUT_CHARS = WIDTH - len("Input:  ")
_INDENT = "   "


def format_result(result: Result) -> str:
    """Render ``result`` as text, without a trailing newline."""
    lines = _header(result.normalized)
    lines.append("")

    if not result.candidates:
        lines += _no_match()
        return "\n".join(lines)

    lines += _table(result.candidates)
    for rank, cand in enumerate(result.candidates, start=1):
        if cand.confidence is not Confidence.LOW:
            lines.append("")
            lines += _details(rank, cand, result.normalized)

    if any(c.confidence is Confidence.LOW for c in result.candidates):
        lines += ["", "Low-confidence candidates are shown in the table only."]
    return "\n".join(lines)


def _header(value: str) -> list[str]:
    if not value:
        return ["Input:  (empty)"]
    shown = _printable(value)
    if len(shown) > MAX_INPUT_CHARS:
        keep = MAX_INPUT_CHARS - len("...")
        head = (keep + 1) // 2
        shown = shown[:head] + "..." + shown[len(shown) - (keep - head) :]
    noun = "character" if len(value) == 1 else "characters"
    return [f"Input:  {shown}", f"Length: {len(value)} {noun}"]


def _printable(value: str) -> str:
    """Escape anything that is not printable ASCII, e.g. '\\x1b' or '\\xe9'."""
    return "".join(
        ch if " " <= ch <= "~" else ch.encode("unicode_escape").decode("ascii")
        for ch in value
    )


def _table(candidates: Sequence[Candidate]) -> list[str]:
    header = ("#", "Format", "Confidence", "Hashcat", "John")
    rows = [
        (
            str(rank),
            c.signature.name,
            c.confidence.name,
            "-" if c.signature.hashcat_mode is None else str(c.signature.hashcat_mode),
            c.signature.john_format or "-",
        )
        for rank, c in enumerate(candidates, start=1)
    ]
    widths = [max(len(cell) for cell in column) for column in zip(header, *rows)]

    def line(cells: Sequence[str]) -> str:
        return "  ".join(cell.ljust(w) for cell, w in zip(cells, widths)).rstrip()

    return [line(header), line(["-" * w for w in widths]), *(line(r) for r in rows)]


def _details(rank: int, cand: Candidate, value: str) -> list[str]:
    sig = cand.signature
    lines = [f"{rank}. {sig.name} - {cand.confidence.value} confidence"]

    lines.append(f"{_INDENT}Reasons:")
    for reason in cand.reasons:
        lines += _wrap(reason, f"{_INDENT}  - ", f"{_INDENT}    ")

    label = "Strength: "
    lines += _wrap(
        f"{label}{sig.strength.name} - {sig.strength_note}",
        _INDENT,
        _INDENT + " " * len(label),
    )

    commands = crack_commands(sig)
    if commands:
        lines.append(f"{_INDENT}Crack it (save the hash to {HASH_FILE} first):")
        lines += [f"{_INDENT}  {cmd}" for cmd in commands]
    for note in tool_notes(sig, value):
        lines += _wrap(f"Note: {note}", _INDENT, _INDENT + "      ")
    return lines


def _no_match() -> list[str]:
    known = ", ".join(sig.name for sig in SIGNATURES)
    return [
        "No known hash format matched this input.",
        "",
        *_wrap(
            "Hint: check for extra characters (quotes, spaces, a 'user:' prefix) "
            "or a truncated copy. Hashes containing $ must be wrapped in single "
            "quotes, or the shell changes them.",
            "",
            "      ",
        ),
        *_wrap(f"Known formats: {known}.", "", " " * len("Known formats: ")),
    ]


def _wrap(text: str, first: str, rest: str) -> list[str]:
    return textwrap.wrap(
        text,
        width=WIDTH,
        initial_indent=first,
        subsequent_indent=rest,
        break_on_hyphens=False,
    )
