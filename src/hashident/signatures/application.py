"""Formats tied to a product: databases, operating systems, applications."""

from __future__ import annotations

from hashident.models import Category, Charset, Context, Signature, Strength, Tier
from hashident.signatures._shared import hex_chars

# MySQL 4.1+ PASSWORD(): "*" + uppercase hex of SHA1(SHA1(password)).
# The pattern accepts the bare 40-hex form too, because Hashcat's own
# mode 300 example (and many cracking lists) drop the asterisk. A bare
# value also matches SHA-1, which outranks MySQL; only the "*" form is
# unambiguous. For Hashcat, strip the leading "*": mode 300 expects exactly
# 40 hex characters. John's mysql-sha1 format requires the asterisk: its
# valid() rejects anything but "*" + 40 hex (src/mysqlSHA1_fmt_plug.c).
# See hashident.commands.tool_notes.
MYSQL41 = Signature(
    name="MySQL 4.1+",
    category=Category.APPLICATION,
    tier=Tier.POSSIBLE,
    pattern=r"\*?" + hex_chars(40),
    charset=Charset.HEX,
    prefixes=("*",),
    summary="MySQL5, SHA-1(SHA-1($pass))",
    strength=Strength.WEAK,
    strength_note="Unsalted double SHA-1: identical passwords give identical hashes.",
    example="*FCF7C1B8749CF99D88E5F34271D636178FB5D130",
    hashcat_mode=300,
    john_format="mysql-sha1",
    popularity=40,
    contexts=frozenset({Context.DB}),
)

SIGNATURES: tuple[Signature, ...] = (MYSQL41,)
