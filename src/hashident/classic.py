"""The classic view: one block per hash, its formats listed in two tiers.

    HASH: b89eaac7e61417341b710b727768294d0e6a277b

    Possible Hashes:
    [+] SHA-1
    [+] MySQL 4.1+ - MySQL5, SHA-1(SHA-1($pass))

    Least Possible Hashes:
    [+] ...

Formats keep the engine's order, best first within each tier. With
--show-modes each line also ends in ``(hashcat 100 | john raw-sha1)``. Like
the other views, the block is pure ASCII, fits in ``WIDTH`` columns, and is
laid out on plain text before any color is applied.
"""

from __future__ import annotations

from hashident.models import Candidate, Category, Result, Signature, Tier
from hashident.output import NO_MATCH_MESSAGE, WIDTH, no_match_hint, printable, shorten
from hashident.style import PLAIN, Styler

INPUT_LABEL = "HASH: "
POSSIBLE_HEADING = "Possible Hashes:"
LEAST_POSSIBLE_HEADING = "Least Possible Hashes:"
NO_MATCH = f"[-] {NO_MATCH_MESSAGE}"
WHITESPACE_NOTE = "[*] Whitespace inside the input was ignored."
HEX_PREFIX_NOTE = "[*] Formats for the hex after '{prefix}' are included."

_SECTIONS = ((Tier.POSSIBLE, POSSIBLE_HEADING), (Tier.LEAST_POSSIBLE, LEAST_POSSIBLE_HEADING))
_MARKER = "[+]"
_INDENT = len(_MARKER) + 1
_GAP = "  "


def format_classic(
    result: Result,
    style: Styler = PLAIN,
    *,
    show_modes: bool = False,
    show_input: bool = True,
    shell_hint: bool = True,
) -> str:
    """Render ``result`` as a classic block, without a trailing newline.

    ``show_input=False`` leaves out the ``HASH:`` line, for interactive mode
    where the prompt already shows it. ``shell_hint=False`` leaves shell
    quoting out of the no-match hint, for input that never went through a
    shell.
    """
    lines: list[str] = []
    if show_input:
        value = result.normalized
        shown = shorten(printable(value), WIDTH - len(INPUT_LABEL)) if value else "(empty)"
        lines += [INPUT_LABEL + shown, ""]
    if result.whitespace_removed:
        lines += [style.muted(WHITESPACE_NOTE), ""]
    prefix = next((c.ignored_prefix for c in result.candidates if c.ignored_prefix), "")
    if prefix:
        lines += [style.muted(HEX_PREFIX_NOTE.format(prefix=prefix)), ""]

    if not result.candidates:
        lines += [style.warning(NO_MATCH), "", *no_match_hint(shell=shell_hint)]
        return "\n".join(lines)

    modes_width = _modes_label_width(result.candidates) if show_modes else None
    sections = []
    for tier, heading in _SECTIONS:
        group = [cand for cand in result.candidates if cand.tier is tier]
        if group:
            rows = [line for cand in group for line in _row(cand, style, modes_width)]
            sections.append([style.heading(heading), *rows])
    for index, section in enumerate(sections):
        if index:
            lines.append("")
        lines += section
    return "\n".join(lines)


def _label(sig: Signature) -> str:
    """The name, then what else is worth knowing: ``name - checksum, summary``."""
    extras = ["checksum"] if sig.category is Category.CHECKSUM else []
    if sig.summary:
        extras.append(sig.summary)
    return f"{sig.name} - {', '.join(extras)}" if extras else sig.name


def _modes(sig: Signature) -> str:
    """``(hashcat 100 | john raw-sha1)``, with only the tools that apply."""
    parts = []
    if sig.hashcat_mode is not None:
        parts.append(f"hashcat {sig.hashcat_mode}")
    if sig.john_format is not None:
        parts.append(f"john {sig.john_format}")
    return f"({' | '.join(parts)})" if parts else ""


def _fits_beside(label: str, modes: str) -> bool:
    return _INDENT + len(label) + len(_GAP) + len(modes) <= WIDTH


def _modes_label_width(candidates: tuple[Candidate, ...]) -> int:
    """The label width to pad to, so that modes line up in one column.

    Only labels whose modes fit on the same line count; a longer label gets
    its modes on a line of their own and must not push the column right.
    """
    widths = [
        len(_label(cand.signature))
        for cand in candidates
        if _modes(cand.signature) and _fits_beside(_label(cand.signature), _modes(cand.signature))
    ]
    return max(widths, default=0)


def _row(cand: Candidate, style: Styler, modes_width: int | None) -> list[str]:
    sig = cand.signature
    label = _label(sig)
    styled = label
    if cand.tier is Tier.POSSIBLE:
        styled = style.name(sig.name) + label[len(sig.name) :]
    head = f"{style.marker(_MARKER, cand.tier)} {styled}"

    modes = _modes(sig) if modes_width is not None else ""
    if not modes:
        return [head]
    if not _fits_beside(label, modes):
        return [head, " " * _INDENT + style.muted(modes)]
    # Pad outside the color codes, so the column is measured on visible text.
    width = modes_width or 0
    if _INDENT + width + len(_GAP) + len(modes) > WIDTH:
        width = len(label)
    return [head + " " * (width - len(label)) + _GAP + style.muted(modes)]
