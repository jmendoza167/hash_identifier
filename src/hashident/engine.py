"""Identification engine: turns a raw string into ranked candidates.

Pipeline for one input:

1. Normalize (``Result`` strips surrounding whitespace).
2. Match the normalized value against every signature.
3. Score each match: popularity, then any score adjustments
   (currently the context hint, see ``hashident.context``).
4. Rank: score descending, then name, so output is deterministic.
5. Label confidence and add reasons that depend on the other matches.

Confidence thresholds
---------------------
* Exactly one signature matches: HIGH. The shape alone pins down the format.
* Several match: the input is genuinely ambiguous, so nothing is HIGH,
  with or without a context hint.
  A candidate within ``MEDIUM_MAX_GAP`` points of the top score is MEDIUM
  (the top candidate always is); anything further behind is LOW.

``MEDIUM_MAX_GAP`` is 20 because popularity tiers are 20 points apart
(see ``hashident.signatures``): a candidate within one tier of the leader
is still a serious contender, while one two or more tiers behind is a
long shot. MD5 (100) vs NTLM (60) gives MD5 MEDIUM and NTLM LOW.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from hashident.context import context_adjustments, parse_context
from hashident.models import Adjustment, Candidate, Confidence, Context, Result, Signature
from hashident.signatures import SIGNATURES

MEDIUM_MAX_GAP = 20.0
"""Max points behind the top score for a candidate to still be MEDIUM."""

_HEX_RE = re.compile(r"[0-9a-fA-F]+")

# Modular crypt format identifiers whose first parameter is a cost factor.
_MCF_COST_IDS = frozenset({"2a", "2b", "2y"})


@dataclass(frozen=True)
class _Scored:
    signature: Signature
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

    matched = [sig for sig in signatures if sig.matches(value)]
    scored = [_score(sig, value, hint) for sig in matched]
    scored.sort(key=lambda s: (-s.score, s.signature.name))

    candidates = tuple(_to_candidate(s, scored, value) for s in scored)
    return Result(raw=raw, candidates=candidates, context=hint)


def _score(sig: Signature, value: str, context: Context | None) -> _Scored:
    """Score one matching signature: popularity plus every adjustment."""
    score = float(sig.popularity)
    reasons = [_shape_reason(sig, value)]
    for adj in _adjustments(sig, value, context):
        score += adj.delta
        reasons.append(adj.reason)
    return _Scored(signature=sig, score=score, reasons=tuple(reasons))


def _adjustments(sig: Signature, value: str, context: Context | None) -> list[Adjustment]:
    """Score adjustments for one candidate.

    This is the single place where scores are changed beyond popularity.
    """
    return context_adjustments(sig, context)


def _to_candidate(item: _Scored, ranked: Sequence[_Scored], value: str) -> Candidate:
    """Label confidence and add reasons that depend on the other matches."""
    top = ranked[0]
    others = [s.signature.name for s in ranked if s is not item]
    reasons = list(item.reasons)

    if not others:
        confidence = Confidence.HIGH
        reasons.append("no other known format has this shape")
    else:
        gap = top.score - item.score
        confidence = Confidence.MEDIUM if gap <= MEDIUM_MAX_GAP else Confidence.LOW
        reasons.append(_ranking_reason(item, top, ranked))
        why = "same length and charset" if _HEX_RE.fullmatch(value) else "same format"
        reasons.append(f"also matches {', '.join(others)}: {why}")

    return Candidate(
        signature=item.signature,
        score=item.score,
        confidence=confidence,
        reasons=tuple(reasons),
    )


def _ranking_reason(item: _Scored, top: _Scored, ranked: Sequence[_Scored]) -> str:
    """Explain this candidate's place in the final ranking.

    Popularity comparisons are always true statements about popularity;
    when an adjustment reversed the popularity order, the reason says so.
    """
    pop = item.signature.popularity
    if item is top:
        more_popular = [s.signature.name for s in ranked if s.signature.popularity > pop]
        if not more_popular:
            return "most common format with this shape"
        return f"ranked above {', '.join(more_popular)} by the context hint"

    leader, top_pop = top.signature.name, top.signature.popularity
    if pop < top_pop:
        return f"less common than {leader} with this shape"
    if pop == top_pop and item.score == top.score:
        return f"as common as {leader} with this shape"
    comparison = f"more common than {leader}" if pop > top_pop else f"as common as {leader}"
    return f"{comparison} with this shape, but {leader} matches the context hint"


def _shape_reason(sig: Signature, value: str) -> str:
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
    return f"matches the {sig.name} format ({len(value)} characters)"
