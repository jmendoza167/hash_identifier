"""Optional ANSI styling for text output.

The layout code in ``hashident.output`` calls a ``Styler`` on finished,
already padded and wrapped pieces of text. With ``PLAIN`` every method
returns its input unchanged, so plain output never contains escape codes,
and stripping the codes from styled output gives exactly the plain output.

Only the 8 standard foreground colors plus bold and dim are used (no
backgrounds), so the terminal's own theme keeps them readable on dark and
light backgrounds.
"""

from __future__ import annotations

import re

from hashident.models import Confidence, Strength, Tier

_RESET = "\x1b[0m"
_BOLD, _DIM = "1", "2"
_RED, _GREEN, _YELLOW, _CYAN = "31", "32", "33", "36"

_CONFIDENCE = {Confidence.HIGH: _GREEN, Confidence.MEDIUM: _YELLOW, Confidence.LOW: _DIM}
_STRENGTH = {Strength.WEAK: _RED, Strength.MODERATE: _YELLOW, Strength.STRONG: _GREEN}
_TIER = {Tier.POSSIBLE: _GREEN, Tier.LEAST_POSSIBLE: _DIM}

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    """Remove ANSI style codes."""
    return ANSI_RE.sub("", text)


def visible_len(text: str) -> int:
    """Length of ``text`` as shown in a terminal, ignoring style codes."""
    return len(strip_ansi(text))


class Styler:
    """Applies colors by meaning; does nothing when disabled."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _paint(self, text: str, code: str) -> str:
        if not self.enabled or not text:
            return text
        return f"\x1b[{code}m{text}{_RESET}"

    def name(self, text: str) -> str:
        return self._paint(text, _BOLD)

    def heading(self, text: str) -> str:
        return self._paint(text, _BOLD)

    def banner(self, text: str) -> str:
        return self._paint(text, _CYAN)

    def marker(self, text: str, tier: Tier) -> str:
        return self._paint(text, _TIER[tier])

    def command(self, text: str) -> str:
        return self._paint(text, _CYAN)

    def muted(self, text: str) -> str:
        return self._paint(text, _DIM)

    def tip(self, text: str) -> str:
        return self._paint(text, _DIM)

    def warning(self, text: str) -> str:
        return self._paint(text, _YELLOW)

    def confidence(self, text: str, level: Confidence) -> str:
        return self._paint(text, _CONFIDENCE[level])

    def strength(self, text: str, level: Strength) -> str:
        return self._paint(text, _STRENGTH[level])


PLAIN = Styler(enabled=False)
ANSI = Styler(enabled=True)
