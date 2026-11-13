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


@dataclass(frozen=True, kw_only=True)
class Signature:
    """Describes one hash format and how to recognise it.

    ``pattern`` must match the *whole* hash (it is applied with fullmatch).
    Use inline flags such as ``(?i)`` for case-insensitive formats.
    """

    name: str
    pattern: str
    strength: Strength
    strength_note: str
    example: str
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
        # frozen=True blocks normal assignment, so set the cached regex directly.
        object.__setattr__(self, "_regex", re.compile(self.pattern))
        if not self.matches(self.example):
            raise ValueError(f"{self.name}: example does not match its own pattern")

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
    """

    raw: str
    candidates: tuple[Candidate, ...] = ()
    normalized: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "normalized", self.raw.strip())

    @property
    def best(self) -> Candidate | None:
        """The top-ranked candidate, or None if nothing matched."""
        return self.candidates[0] if self.candidates else None
