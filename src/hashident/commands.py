"""Ready-to-run cracking commands for a signature.

Kept separate from text formatting so other output formats (e.g. JSON)
can reuse the same commands and notes.
"""

from __future__ import annotations

from hashident.models import Signature
from hashident.signatures import MYSQL41

HASH_FILE = "hash.txt"
WORDLIST = "wordlist.txt"

# Hashcat 8.0.0 added a range of mode numbers for formats it defines with a
# stored recipe. Formats that only exist there need that version.
RECIPE_MODES_START = 40000
RECIPE_MODES_VERSION = "8.0.0"


def crack_commands(sig: Signature) -> tuple[str, ...]:
    """Hashcat and John wordlist commands, for the tools that support ``sig``."""
    commands = []
    if sig.hashcat_mode is not None:
        commands.append(f"hashcat -m {sig.hashcat_mode} -a 0 {HASH_FILE} {WORDLIST}")
    if sig.john_format is not None:
        commands.append(f"john --format={sig.john_format} --wordlist={WORDLIST} {HASH_FILE}")
    return tuple(commands)


def tool_notes(sig: Signature, value: str) -> tuple[str, ...]:
    """Notes on using the tools with ``value``: its form, or the version needed."""
    notes = list(sig.notes)
    if sig is MYSQL41:
        if value.startswith("*"):
            notes.append(
                "For hashcat, save the hash without the leading '*' (mode 300 "
                "expects exactly 40 hex characters). John's mysql-sha1 format "
                "needs the '*', so keep it for john."
            )
        else:
            notes.append(
                "For john, add a leading '*' (its mysql-sha1 format expects '*' "
                "plus 40 hex characters). Hashcat mode 300 takes the hash as is."
            )
    if sig.hashcat_mode is not None and sig.hashcat_mode >= RECIPE_MODES_START:
        notes.append(
            f"Hashcat mode {sig.hashcat_mode} needs hashcat {RECIPE_MODES_VERSION} or newer."
        )
    return tuple(notes)
