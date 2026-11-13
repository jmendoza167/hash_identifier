"""Identification engine: turns a raw string into ranked candidates.

Pipeline for one input:

1. Normalize (``Result`` strips surrounding whitespace).
2. Match the normalized value against every signature.
3. Score each match: popularity, then any score adjustments.
4. Rank: score descending, then name, so output is deterministic.
5. Label confidence and add reasons that depend on the other matches.

Confidence thresholds
---------------------
* Exactly one signature matches: HIGH. The shape alone pins down the format.
* Several match: the input is genuinely ambiguous, so nothing is HIGH.
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

from hashident.models import Candidate, Confidence, Result, Signature
from hashident.signatures import SIGNATURES

MEDIUM_MAX_GAP = 20.0
"""Max points behind the top score for a candidate to still be MEDIUM."""

_HEX_RE = re.compile(r"[0-9a-fA-F]+")

# Modular crypt format identifiers whose first parameter is a cost factor.
_MCF_COST_IDS = frozenset({"2a", "2b", "2y"})


@dataclass(frozen=True)
class Adjustment:
    """A change to a candidate's score, with the reason shown to the user."""

    delta: float
    reason: str


@dataclass(frozen=True)
class _Scored:
    signature: Signature
    score: float
    reasons: tuple[str, ...]


def identify(raw: str, *, signatures: Sequence[Signature] = SIGNATURES) -> Result:
    """Identify which hash formats ``raw`` could be, best guess first.

    Returns a ``Result`` with no candidates for empty input or input that
    matches no known format; it does not raise for those cases.
    """
    result = Result(raw=raw)
    value = result.normalized
    if not value:
        return result

    matched = [sig for sig in signatures if sig.matches(value)]
    scored = [_score(sig, value) for sig in matched]
    scored.sort(key=lambda s: (-s.score, s.signature.name))

    candidates = tuple(_to_candidate(s, scored, value) for s in scored)
    return Result(raw=raw, candidates=candidates)


def _score(sig: Signature, value: str) -> _Scored:
    """Score one matching signature: popularity plus every adjustment."""
    score = float(sig.popularity)
    reasons = [_shape_reason(sig, value)]
    for adj in _adjustments(sig, value):
        score += adj.delta
        reasons.append(adj.reason)
    return _Scored(signature=sig, score=score, reasons=tuple(reasons))


def _adjustments(sig: Signature, value: str) -> list[Adjustment]:
    """Score adjustments for one candidate.

    This is the single place where scores are changed beyond popularity.
    Context hints (step 6) will return their boosts from here.
    """
    return []


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
        if item is top:
            reasons.append("most common format with this shape")
        elif gap == 0:
            reasons.append(f"as common as {top.signature.name} with this shape")
        else:
            reasons.append(f"less common than {top.signature.name} with this shape")
        why = "same length and charset" if _HEX_RE.fullmatch(value) else "same format"
        reasons.append(f"also matches {', '.join(others)}: {why}")

    return Candidate(
        signature=item.signature,
        score=item.score,
        confidence=confidence,
        reasons=tuple(reasons),
    )


def _shape_reason(sig: Signature, value: str) -> str:
    """Describe what about the input's shape matched this signature."""
    if _HEX_RE.fullmatch(value):
        return f"{len(value)} hexadecimal characters"
    if value.startswith("$") and value.count("$") >= 2:
        parts = value.split("$")
        reason = f"starts with {sig.name} prefix ${parts[1]}$"
        if parts[1] in _MCF_COST_IDS and len(parts) > 2 and parts[2].isdigit():
            reason += f" (cost {int(parts[2])})"
        return reason
    return f"matches the {sig.name} format ({len(value)} characters)"
