"""Suggestions for re-running with a context hint (--from).

Tips are computed, not hardcoded: each context is tried with ``identify()``
and only the ones that change the top-ranked format are suggested.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from hashident.engine import identify
from hashident.models import Confidence, Context, Result, Signature
from hashident.signatures import SIGNATURES


@dataclass(frozen=True)
class ContextTip:
    """Re-running with ``context`` would rank ``top`` first."""

    context: Context
    top: Signature


def context_tips(
    result: Result, *, signatures: Sequence[Signature] = SIGNATURES
) -> tuple[ContextTip, ...]:
    """Contexts that would change the best candidate of an ambiguous result.

    Returns nothing if a context was already given, nothing matched, or the
    top candidate is HIGH confidence. ``signatures`` must be the same set
    the result was computed with.
    """
    best = result.best
    if result.context is not None or best is None or len(result.candidates) < 2:
        return ()
    if best.confidence is Confidence.HIGH:
        return ()

    tips = []
    for context in Context:
        top = identify(result.raw, context, signatures=signatures).best
        if top is not None and top.signature != best.signature:
            tips.append(ContextTip(context=context, top=top.signature))
    return tuple(tips)
