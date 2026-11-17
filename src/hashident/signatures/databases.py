"""Password hashes as database servers store them.

SQL Server prints its hashes as ``0x`` followed by hex, with a version header
first: ``0x0100`` or ``0x0200``. Those headers are the prefixes here, so an
MSSQL hash is pinned by them and other hex with ``0x`` in front is not.
"""

from __future__ import annotations

from hashident.models import Category, Charset, Signature, Strength, Tier
from hashident.signatures import _examples
from hashident.signatures._shared import BASE64, DB, hex_chars

_P = Tier.POSSIBLE
_WEAK, _MODERATE, _STRONG = Strength.WEAK, Strength.MODERATE, Strength.STRONG

_SALTED_ONCE = "Salted, but one round of a fast hash: the salt stops lookup tables, not GPUs."


def _db(
    name: str,
    popularity: float,
    example: str,
    *,
    strength: Strength,
    note: str,
    pattern: str = "",
    length: int | None = None,
    charset: Charset = Charset.HEX,
    prefixes: tuple[str, ...] = (),
    structure: str | None = None,
    summary: str = "",
    hashcat: int | None = None,
    john: str | None = None,
    notes: tuple[str, ...] = (),
) -> Signature:
    return Signature(
        name=name,
        category=Category.APPLICATION,
        tier=_P,
        pattern=pattern,
        length=length,
        charset=charset,
        prefixes=prefixes,
        structure=structure,
        summary=summary,
        strength=strength,
        strength_note=note,
        example=example,
        hashcat_mode=hashcat,
        john_format=john,
        notes=notes,
        popularity=popularity,
        contexts=DB,
    )


# --- MySQL --------------------------------------------------------------------

MYSQL323 = _db(
    "MySQL323",
    60,
    "7196759210defdc0",
    length=16,
    summary="MySQL before 4.1, OLD_PASSWORD()",
    strength=_WEAK,
    note="A weak home-grown hash: a matching password is found in seconds.",
    hashcat=200,
    john="mysql",
)

# MySQL 4.1+ PASSWORD(): "*" + uppercase hex of SHA1(SHA1(password)).
# The pattern accepts the bare 40-hex form too, because Hashcat's own
# mode 300 example (and many cracking lists) drop the asterisk. A bare
# value also matches SHA-1, which outranks MySQL; only the "*" form is
# unambiguous. For Hashcat, strip the leading "*": mode 300 expects exactly
# 40 hex characters. John's mysql-sha1 format requires the asterisk: its
# valid() rejects anything but "*" + 40 hex (src/mysqlSHA1_fmt_plug.c).
# See hashident.commands.tool_notes.
MYSQL41 = _db(
    "MySQL 4.1+",
    40,
    "*FCF7C1B8749CF99D88E5F34271D636178FB5D130",
    pattern=r"\*?" + hex_chars(40),
    prefixes=("*",),
    summary="MySQL5, SHA-1(SHA-1($pass))",
    strength=_WEAK,
    note="Unsalted double SHA-1: identical passwords give identical hashes.",
    hashcat=300,
    john="mysql-sha1",
)

# --- Microsoft SQL Server -----------------------------------------------------
# 0x, a 4-digit version header, an 8-digit salt, then the hash.

MSSQL2000 = _db(
    "MSSQL 2000",
    40,
    _examples.MSSQL_2000,
    # Two SHA-1 hashes: of the password as typed, and of it in upper case.
    pattern=rf"0x0100{hex_chars(88)}",
    length=94,
    prefixes=("0x0100",),
    strength=_WEAK,
    note="Salted SHA-1, stored a second time for the upper-cased password.",
    hashcat=131,
    john="mssql",
)

MSSQL2005 = _db(
    "MSSQL 2005",
    60,
    _examples.MSSQL_2005,
    pattern=rf"0x0100{hex_chars(48)}",
    length=54,
    prefixes=("0x0100",),
    summary="SQL Server 2005 and 2008",
    strength=_WEAK,
    note=_SALTED_ONCE,
    hashcat=132,
    john="mssql05",
)

MSSQL2012 = _db(
    "MSSQL 2012",
    60,
    _examples.MSSQL_2012,
    pattern=rf"0x0200{hex_chars(136)}",
    length=142,
    prefixes=("0x0200",),
    summary="SQL Server 2012 to 2022",
    strength=_MODERATE,
    note="Salted, but one round of SHA-512: fast to guess on GPUs.",
    hashcat=1731,
    john="mssql12",
)

# --- Oracle -------------------------------------------------------------------

# The S: value of a user's password versions: a SHA-1 of the password and a
# 10-byte salt, written as 40 + 20 hex characters. Hashcat wants the two
# parts split as hash:salt, which is also accepted here as a structure match
# next to the other salted SHA-1 formats.
ORACLE11 = _db(
    "Oracle 11g",
    30,
    "S:AC5F1E62D21FD0529428B84D42E8955B0496670338445748184477378130",
    pattern=rf"(?:S:{hex_chars(60)}|{hex_chars(40)}:{hex_chars(20)})",
    prefixes=("S:",),
    structure="hash:salt",
    summary="the S: verifier, sha1($pass.$salt)",
    strength=_WEAK,
    note=_SALTED_ONCE,
    hashcat=112,
    john="oracle11",
    notes=(
        "Hashcat mode 112 wants hash:salt: the first 40 hex characters after "
        "'S:', a ':', then the last 20.",
    ),
)

# The T: value: 160 hex characters, also seen without the marker.
ORACLE12C = _db(
    "Oracle 12c",
    40,
    "T:" + _examples.ORACLE_12C,
    pattern=rf"(?:T:)?{hex_chars(160)}",
    prefixes=("T:",),
    summary="the T: verifier, PBKDF2-SHA512",
    strength=_STRONG,
    note="Salted PBKDF2-SHA512 with 4,096 rounds.",
    hashcat=12300,
    john="oracle12c",
    notes=("For hashcat, leave out the 'T:' and give the 160 hex characters alone.",),
)

# --- PostgreSQL ---------------------------------------------------------------

POSTGRESQL_MD5 = _db(
    "PostgreSQL MD5",
    60,
    "md5a6343a68d964ca596d9752250d54bb8a",
    pattern=rf"md5{hex_chars(32)}",
    length=35,
    prefixes=("md5",),
    summary="md5($pass.$user), from pg_shadow",
    strength=_WEAK,
    note="One MD5 round salted with the user name only.",
    hashcat=12,
    notes=(
        "Hashcat mode 12 wants hash:salt: the 32 hex characters without 'md5', "
        "a ':', then the user name.",
    ),
)

POSTGRESQL_SCRAM = _db(
    "PostgreSQL SCRAM-SHA-256",
    60,
    _examples.POSTGRESQL_SCRAM,
    # SCRAM-SHA-256$iterations:salt$StoredKey:ServerKey, all three in base64.
    pattern=rf"SCRAM-SHA-256\$[0-9]+:{BASE64}+={{0,2}}\${BASE64}{{43}}=:{BASE64}{{43}}=",
    charset=Charset.BASE64,
    prefixes=("SCRAM-SHA-256$",),
    summary="default since PostgreSQL 14",
    strength=_STRONG,
    note="Salted PBKDF2-SHA256 with a tunable iteration count (4,096 by default).",
    hashcat=28600,
    john="scram-pbkdf2-sha256",
)

SIGNATURES: tuple[Signature, ...] = (
    MYSQL323,
    MYSQL41,
    MSSQL2000,
    MSSQL2005,
    MSSQL2012,
    ORACLE11,
    ORACLE12C,
    POSTGRESQL_MD5,
    POSTGRESQL_SCRAM,
)
