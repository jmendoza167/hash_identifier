"""Context hints: where the hash was found (the --from option).

A hint boosts signatures that are typical for that environment. It never
penalises the others; it only changes which plausible format is preferred.

Boost size
----------
``CONTEXT_BOOST`` is 50 points on the 0-100 popularity scale, where tiers
are 20 points apart (see ``hashident.signatures``):

* It overturns a popularity gap of up to two tiers (40 points) but not
  three (60). NTLM (60) beats MD5 (100) with --from windows (110 vs 100),
  but a rare format (20) cannot overtake a ubiquitous one (100) on a hint
  alone (70 vs 100).
* After such a flip the two are 10 points apart, well within the engine's
  ``MEDIUM_MAX_GAP`` of 20, so both stay MEDIUM. A hint changes the best
  guess; it does not turn an ambiguous match into a certain one.
"""

from __future__ import annotations

from hashident.models import Adjustment, Context, Signature

CONTEXT_BOOST = 50.0
"""Points added to a signature whose contexts include the hint."""

_DESCRIPTIONS: dict[Context, str] = {
    Context.WINDOWS: "common in Windows environments",
    Context.LINUX: "common in Linux environments",
    Context.WEB: "common in web applications",
    Context.DB: "common in databases",
}


def parse_context(value: Context | str | None) -> Context | None:
    """Turn a hint like ``"Windows"`` into a ``Context``; None means no hint.

    Raises ValueError, listing the valid options, for an unknown string.
    """
    if value is None or isinstance(value, Context):
        return value
    if not isinstance(value, str):
        raise TypeError(f"context must be a Context, str or None, not {type(value).__name__}")
    try:
        return Context(value.strip().casefold())
    except ValueError:
        valid = ", ".join(c.value for c in Context)
        raise ValueError(f"Invalid context {value!r}; choose one of: {valid}") from None


def context_adjustments(sig: Signature, context: Context | None) -> list[Adjustment]:
    """The boost for ``sig`` under ``context``, if it fits; otherwise none."""
    if context is None or context not in sig.contexts:
        return []
    reason = f"{_DESCRIPTIONS[context]} (--from {context.value})"
    return [Adjustment(delta=CONTEXT_BOOST, reason=reason)]
