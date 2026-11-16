"""Core data structures for hashident.

These are plain, immutable value types. They hold data and do not contain
identification logic beyond a signature's own pattern match.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class Strength(Enum):
    """How resistant an algorithm is to offline cracking."""

    WEAK = "weak"  # e.g. MD5, NTLM: fast, unsalted
    MODERATE = "moderate"  # e.g. unsalted SHA-256: sound primitive, too fast for passwords
    STRONG = "strong"  # e.g. bcrypt, Argon2: salted, deliberately slow


class Confidence(Enum):
    """How sure we are that a candidate is the real algorithm."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Context(Enum):
    """Where a hash was found; matches the values of the --from hint."""

    WINDOWS = "windows"
    LINUX = "linux"
    WEB = "web"
    DB = "db"


class Tier(Enum):
    """How likely a format is to be the answer for an input of its shape."""

    POSSIBLE = "possible"  # pinned by a prefix or structure, or the usual format for the shape
    LEAST_POSSIBLE = "least_possible"  # same shape, but rarer


class Category(Enum):
    """What kind of format a signature describes; groups the format lists."""

    CHECKSUM = "checksum"  # error detection, not a cryptographic hash
    RAW = "raw"  # a bare digest of the password
    SALTED = "salted"  # generic salted, HMAC and nested constructions
    APPLICATION = "application"  # tied to a product, database, OS or protocol
    CRYPT = "crypt"  # crypt(3)-style and key-derivation formats


class Charset(Enum):
    """The alphabet a format's digest is written in."""

    HEX = "hex"  # either case
    HEX_LOWER = "hex_lower"
    HEX_UPPER = "hex_upper"
    BASE64 = "base64"  # standard alphabet, without padding
    CRYPT64 = "crypt64"  # the ./0-9A-Za-z alphabet of crypt(3)
    MIXED = "mixed"  # several alphabets, or none in particular

    @property
    def char_class(self) -> str | None:
        """The regex character class for one character, or None for MIXED."""
        return _CHAR_CLASSES.get(self)


_CHAR_CLASSES = {
    Charset.HEX: "[0-9a-fA-F]",
    Charset.HEX_LOWER: "[0-9a-f]",
    Charset.HEX_UPPER: "[0-9A-F]",
    Charset.BASE64: "[A-Za-z0-9+/]",
    Charset.CRYPT64: "[./0-9A-Za-z]",
}


@dataclass(frozen=True, kw_only=True)
class Signature:
    """Describes one hash format and how to recognise it.

    A plain shape needs only ``length`` and ``charset``: the pattern is
    derived from them. Anything with structure gives an explicit ``pattern``,
    which must match the *whole* hash (it is applied with fullmatch). Use
    inline flags such as ``(?i)`` for case-insensitive formats.

    ``length`` is the total number of characters when that is fixed, and
    None when it varies. ``charset`` is the alphabet of the digest itself.
    ``prefixes`` are the literal markers the format starts with (``$2b$``,
    ``*``), and ``structure`` names its layout when it has one without a
    marker (``hash:salt``). ``summary`` holds other names for the format, or
    the construction behind it.
    """

    name: str
    category: Category
    tier: Tier
    strength: Strength
    strength_note: str
    example: str
    pattern: str = ""
    length: int | None = None
    charset: Charset = Charset.MIXED
    prefixes: tuple[str, ...] = ()
    structure: str | None = None
    summary: str = ""
    hashcat_mode: int | None = None
    john_format: str | None = None
    popularity: float = 1.0
    contexts: frozenset[Context] = frozenset()

    _regex: re.Pattern[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("Signature name must not be empty")
        if self.popularity < 0:
            raise ValueError(f"{self.name}: popularity must be >= 0")
        # frozen=True blocks normal assignment, so derived fields are set directly.
        if not self.pattern:
            char_class = self.charset.char_class
            if self.length is None or char_class is None:
                raise ValueError(
                    f"{self.name}: give a pattern, or a length and a charset to derive one"
                )
            object.__setattr__(self, "pattern", f"{char_class}{{{self.length}}}")
        object.__setattr__(self, "_regex", re.compile(self.pattern))
        if not self.matches(self.example):
            raise ValueError(f"{self.name}: example does not match its own pattern")
        if self.length is not None and len(self.example) != self.length:
            raise ValueError(
                f"{self.name}: example is {len(self.example)} characters, "
                f"but the declared length is {self.length}"
            )
        if self.prefixes and not self.example.startswith(self.prefixes):
            raise ValueError(f"{self.name}: example starts with none of its prefixes")

    def matches(self, value: str) -> bool:
        """Return True if ``value`` is entirely in this signature's format."""
        return self._regex.fullmatch(value) is not None


@dataclass(frozen=True)
class Adjustment:
    """A change to a candidate's score, with the reason shown to the user."""

    delta: float
    reason: str


@dataclass(frozen=True, kw_only=True)
class Candidate:
    """One possible identification of a hash, with the evidence for it."""

    signature: Signature
    score: float
    confidence: Confidence
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class Result:
    """The outcome of identifying one input string.

    ``normalized`` is derived from ``raw`` (surrounding whitespace stripped).
    ``candidates`` is ordered best-first and is empty if nothing matched.
    ``context`` is the hint the result was computed with, if any.
    """

    raw: str
    candidates: tuple[Candidate, ...] = ()
    context: Context | None = None
    normalized: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "normalized", self.raw.strip())

    @property
    def best(self) -> Candidate | None:
        """The top-ranked candidate, or None if nothing matched."""
        return self.candidates[0] if self.candidates else None
