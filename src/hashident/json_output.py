"""Machine-readable output for --json.

Every value becomes one JSON object written on a single line, so output for
several values is JSON Lines (https://jsonlines.org) and can be processed as
it streams, e.g. by ``jq``. Output for one value is a single line too: a
complete JSON document and a one-line JSON Lines file at the same time.

Output is pure ASCII: non-ASCII and control characters in the input are
written as ``\\uXXXX`` escapes, which also keeps terminal escape codes out.

Schema version 1
----------------
Keys appear in this order. New keys may be added without changing
``schema_version``; renaming or removing a key, or changing its type, will
increase it.

============================  ====================================================
``schema_version``: int       always 1 for this layout
``input``: string             the value as received: an argument exactly as
                              typed, or a line with its whitespace stripped
``source``: string            "argument", "<stdin>", or the path given to -f
``position``: int             1-based argument index, or line number in source
``context``: string | null    the --from value ("windows", "linux", "web", "db")
``matched``: bool             whether any known format matched
``candidates``: list          best first; empty when nothing matched
``tips``: list                --from values that would change the top format
============================  ====================================================

Each candidate:

============================  ====================================================
``rank``: int                 1 for the best candidate
``format``: string            format name, e.g. "MD5", "bcrypt", "MySQL 4.1+"
``score``: number             ranking score: popularity plus any --from boost
``confidence``: string        "high", "medium" or "low"
``hashcat_mode``: int | null  hashcat -m value; null if hashcat lacks the format
``john_format``: string|null  John the Ripper --format value; null if it lacks it
``strength``: string          "weak", "moderate" or "strong"
``strength_note``: string     one sentence on why
``reasons``: list of string   why it matched and why it ranks where it does
``commands``: list of string  ready-to-run hashcat and john commands
``notes``: list of string     how to prepare the hash for those tools, if needed
============================  ====================================================

Each tip: ``context`` (the --from value) and ``top_format`` (the format that
would rank first with it).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from hashident.commands import crack_commands, tool_notes
from hashident.inputs import InputItem
from hashident.models import Candidate, Result
from hashident.tips import ContextTip

SCHEMA_VERSION = 1


def to_record(
    item: InputItem, result: Result, tips: Sequence[ContextTip] = ()
) -> dict[str, Any]:
    """The schema-version-1 object for one value, as plain Python data."""
    return {
        "schema_version": SCHEMA_VERSION,
        "input": item.value,
        "source": item.source,
        "position": item.position,
        "context": None if result.context is None else result.context.value,
        "matched": bool(result.candidates),
        "candidates": [
            _candidate(rank, cand, result.normalized)
            for rank, cand in enumerate(result.candidates, start=1)
        ],
        "tips": [{"context": tip.context.value, "top_format": tip.top.name} for tip in tips],
    }


def dumps(record: dict[str, Any]) -> str:
    """``record`` as one line of ASCII JSON, without the trailing newline."""
    return json.dumps(record, ensure_ascii=True)


def _candidate(rank: int, cand: Candidate, value: str) -> dict[str, Any]:
    sig = cand.signature
    return {
        "rank": rank,
        "format": sig.name,
        "score": float(cand.score),
        "confidence": cand.confidence.value,
        "hashcat_mode": sig.hashcat_mode,
        "john_format": sig.john_format,
        "strength": sig.strength.value,
        "strength_note": sig.strength_note,
        "reasons": list(cand.reasons),
        "commands": list(crack_commands(sig)),
        "notes": list(tool_notes(sig, value)),
    }
