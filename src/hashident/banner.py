"""The startup banner: the tool's name in ASCII art, then its version.

The art is a hash sign followed by "hashident". It is pure ASCII and fits
in 80 columns, like the rest of the output.
"""

from __future__ import annotations

from hashident import __version__
from hashident.signatures import SIGNATURES
from hashident.style import PLAIN, Styler

_ART = r"""
    _  _     _               _     _     _            _
  _| || |_  | |__   __ _ ___| |__ (_) __| | ___ _ __ | |_
 |_  ..  _| | '_ \ / _` / __| '_ \| |/ _` |/ _ \ '_ \| __|
 |_      _| | | | | (_| \__ \ | | | | (_| |  __/ | | | |_
   |_||_|   |_| |_|\__,_|___/_| |_|_|\__,_|\___|_| |_|\__|
""".strip("\n")

TAGLINE = "identify likely hash algorithms"


def banner(style: Styler = PLAIN) -> str:
    """The banner as text, without a trailing newline."""
    lines = [style.banner(line) for line in _ART.splitlines()]
    info = f" hashident v{__version__} :: {len(SIGNATURES)} formats :: {TAGLINE}"
    lines.append(style.muted(info))
    return "\n".join(lines)
