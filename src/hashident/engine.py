"""Identification engine: turns a raw string into ranked candidates.

Pipeline for one input:

1. Normalize (``Result`` strips surrounding whitespace).
2. Match the normalized value against every signature. If nothing matches
   and the value has whitespace inside it (a hash pasted with a line break,
   or printed in groups), match again without that whitespace.
3. Keep only the most specific kind of match (see below).
4. Score each match: popularity, then any score adjustments
   (currently the context hint, see ``hashident.context``).
5. Rank: POSSIBLE tier before LEAST_POSSIBLE, then score descending, then
   name, so output is deterministic.
6. Label confidence and add reasons that depend on the other matches.

Specificity
-----------
A match is one of three kinds, most specific first:

* PREFIX: the input starts with one of the signature's ``prefixes``
  (``$2b$``, ``*``).
* STRUCTURE: the input has the signature's ``structure`` (``hash:salt``).
* SHAPE: only the length and character set fit.

Only the most specific kind present is kept, so a prefix match wins
outright: no lookalike of the same length is listed next to it. A format
whose prefix or structure is optional (MySQL 4.1+ without its ``*``, a
salted MD5 without its salt) is a SHAPE match when the input lacks it.

Tiers and confidence
--------------------
A candidate's tier is its signature's, with two exceptions. A PREFIX match
is always POSSIBLE. A format with a structure that is matched without it is
always LEAST_POSSIBLE: 32 hex characters could be a salted MD5 whose salt is
stored elsewhere, but that is a long shot next to plain MD5. A context hint
reorders candidates within a tier; it never moves one across tiers.

Confidence is derived from the tier:

* Exactly one candidate: HIGH. The shape alone pins down the format.
* Several: the input is genuinely ambiguous, so nothing is HIGH, with or
  without a context hint. POSSIBLE candidates are MEDIUM and
  LEAST_POSSIBLE ones are LOW.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from enum import IntEnum

from hashident.context import context_adjustments, parse_context
from hashident.models import Adjustment, Candidate, Confidence, Context, Result, Signature, Tier
from hashident.signatures import SIGNATURES

WHITESPACE_REASON = "ignoring whitespace inside the input"

ALSO_MATCHES_LIMIT = 3
"""How many other formats a reason names before it just counts the rest."""

_HEX_RE = re.compile(r"[0-9a-fA-F]+")

# Modular crypt format identifiers whose first parameter is a cost factor.
_MCF_COST_IDS = frozenset({"2a", "2b", "2y"})

_TIER_ORDER = {Tier.POSSIBLE: 0, Tier.LEAST_POSSIBLE: 1}


class _Specificity(IntEnum):
    """What kind of evidence a match rests on; higher is stronger."""

    SHAPE = 0
    STRUCTURE = 1
    PREFIX = 2


@dataclass(frozen=True)
class _Scored:
    signature: Signature
    tier: Tier
    score: float
    reasons: tuple[str, ...]


def identify(
    raw: str,
    context: Context | str | None = None,
    *,
    signatures: Sequence[Signature] = SIGNATURES,
) -> Result:
    """Identify which hash formats ``raw`` could be, best guess first.

    ``context`` is an optional hint about where the hash came from, as a
    ``Context`` or its name (e.g. ``"windows"``, case-insensitive). An
    unknown name raises ValueError listing the valid options.

    Returns a ``Result`` with no candidates for empty input or input that
    matches no known format; it does not raise for those cases.
    """
    hint = parse_context(context)
    result = Result(raw=raw, context=hint)
    value = result.normalized
    if not value:
        return result

    matched = _match(value, signatures)
    squeezed = "".join(value.split())
    whitespace_removed = not matched and squeezed != value
    if whitespace_removed:
        value = squeezed
        matched = _match(value, signatures)
    if not matched:
        return result

    scored = [
        _score(sig, specificity, value, hint, whitespace_removed)
        for sig, specificity in matched
    ]
    scored.sort(key=lambda s: (_TIER_ORDER[s.tier], -s.score, s.signature.name))

    candidates = tuple(_to_candidate(s, scored, value) for s in scored)
    return Result(
        raw=raw, candidates=candidates, context=hint, whitespace_removed=whitespace_removed
    )


def _match(
    value: str, signatures: Sequence[Signature]
) -> list[tuple[Signature, _Specificity]]:
    """The signatures that match ``value``, keeping only the most specific kind."""
    matched = [
        (sig, _specificity(sig, value, match))
        for sig in signatures
        if (match := sig.match(value)) is not None
    ]
    if not matched:
        return []
    strongest = max(specificity for _, specificity in matched)
    return [(sig, specificity) for sig, specificity in matched if specificity is strongest]


def _specificity(sig: Signature, value: str, match: re.Match[str]) -> _Specificity:
    if sig.prefixes and value.startswith(sig.prefixes):
        return _Specificity.PREFIX
    if sig.has_structure(match):
        return _Specificity.STRUCTURE
    return _Specificity.SHAPE


def _tier(sig: Signature, specificity: _Specificity) -> Tier:
    if specificity is _Specificity.PREFIX:
        return Tier.POSSIBLE
    if specificity is _Specificity.SHAPE and sig.structure is not None:
        return Tier.LEAST_POSSIBLE  # seen without its salt: a long shot
    return sig.tier


def _score(
    sig: Signature,
    specificity: _Specificity,
    value: str,
    context: Context | None,
    whitespace_removed: bool,
) -> _Scored:
    """Score one matching signature: popularity plus every adjustment."""
    score = float(sig.popularity)
    reasons = [_shape_reason(sig, value, specificity)]
    if whitespace_removed:
        reasons.append(WHITESPACE_REASON)
    for adj in _adjustments(sig, value, context):
        score += adj.delta
        reasons.append(adj.reason)
    tier = _tier(sig, specificity)
    return _Scored(signature=sig, tier=tier, score=score, reasons=tuple(reasons))


def _adjustments(sig: Signature, value: str, context: Context | None) -> list[Adjustment]:
    """Score adjustments for one candidate.

    This is the single place where scores are changed beyond popularity.
    """
    return context_adjustments(sig, context)


def _to_candidate(item: _Scored, ranked: Sequence[_Scored], value: str) -> Candidate:
    """Label confidence and add reasons that depend on the other matches."""
    others = [s.signature.name for s in ranked if s is not item]
    reasons = list(item.reasons)

    if not others:
        confidence = Confidence.HIGH
        reasons.append("no other known format has this shape")
    else:
        confidence = Confidence.MEDIUM if item.tier is Tier.POSSIBLE else Confidence.LOW
        reasons.append(_ranking_reason(item, ranked))
        why = "same length and charset" if _HEX_RE.fullmatch(value) else "same format"
        reasons.append(f"also matches {_some(others)}: {why}")

    return Candidate(
        signature=item.signature,
        tier=item.tier,
        score=item.score,
        confidence=confidence,
        reasons=tuple(reasons),
    )


def _some(names: Sequence[str]) -> str:
    """Up to ``ALSO_MATCHES_LIMIT`` names, then a count of the rest."""
    shown = ", ".join(names[:ALSO_MATCHES_LIMIT])
    rest = len(names) - ALSO_MATCHES_LIMIT
    return f"{shown} and {rest} more" if rest > 0 else shown


def _ranking_reason(item: _Scored, ranked: Sequence[_Scored]) -> str:
    """Explain this candidate's place in the final ranking.

    Popularity comparisons are always true statements about popularity;
    when an adjustment reversed the popularity order, the reason says so.
    """
    top = ranked[0]
    pop = item.signature.popularity
    if item is top:
        more_popular = [
            s.signature.name
            for s in ranked
            if s.tier is item.tier and s.signature.popularity > pop
        ]
        if not more_popular:
            return "most common format with this shape"
        return f"ranked above {', '.join(more_popular)} by the context hint"

    leader, top_pop = top.signature.name, top.signature.popularity
    if item.tier is not top.tier or pop < top_pop:
        return f"less common than {leader} with this shape"
    if pop == top_pop and item.score == top.score:
        return f"as common as {leader} with this shape"
    comparison = f"more common than {leader}" if pop > top_pop else f"as common as {leader}"
    return f"{comparison} with this shape, but {leader} matches the context hint"


def _shape_reason(sig: Signature, value: str, specificity: _Specificity) -> str:
    """Describe what about the input's shape matched this signature."""
    if _HEX_RE.fullmatch(value):
        return f"{len(value)} hexadecimal characters"
    if value.startswith("*") and _HEX_RE.fullmatch(value[1:]):
        return f"'*' followed by {len(value) - 1} hexadecimal characters"
    if value.startswith("$") and value.count("$") >= 2:
        parts = value.split("$")
        reason = f"starts with {sig.name} prefix ${parts[1]}$"
        if parts[1] in _MCF_COST_IDS and len(parts) > 2 and parts[2].isdigit():
            reason += f" (cost {int(parts[2])})"
        return reason
    if specificity is _Specificity.PREFIX:
        prefix = next(p for p in sig.prefixes if value.startswith(p))
        return f"starts with {sig.name} prefix {prefix}"
    if specificity is _Specificity.STRUCTURE:
        return f"has the {sig.structure} layout"
    return f"matches the {sig.name} format ({len(value)} characters)"
