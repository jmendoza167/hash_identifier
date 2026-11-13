"""The signature database: every hash format hashident knows how to recognise.

Example hashes are taken from the Hashcat example hashes list
(https://hashcat.net/wiki/doku.php?id=example_hashes); the plaintext for all
of them is "hashcat". The one exception is MySQL 4.1+, whose example is
Hashcat's mode 300 hash written in MySQL's own format (see below).

Popularity scale
----------------
``popularity`` is a prior on a 0-100 scale: how likely this format is to be
the right answer, before any context hint, when an input matches it.
Signatures that match the same input are ranked by it, so only the relative
order between overlapping formats really matters.

    100  ubiquitous  - the default guess for its shape (MD5 for 32 hex)
     80  very common - widely deployed, often seen in leaks and audits
     60  common      - regularly seen, but usually needs context to win
     40  uncommon    - specific products or niches
     20  rare        - legacy or exotic formats

Keep gaps between overlapping formats modest, so that a --from context hint
can still lift a lower-ranked format to the top, e.g. NTLM over MD5 with
--from windows.
"""

from __future__ import annotations

from hashident.models import Context, Signature, Strength

_B64 = "[./A-Za-z0-9]"  # crypt(3) base64 alphabet
_SALT = r"[^$:\s]"  # crypt salts may hold any character except these


def _hex(length: int) -> str:
    return f"[0-9a-fA-F]{{{length}}}"


_WEB_DB = frozenset({Context.WEB, Context.DB})
_LINUX = frozenset({Context.LINUX})

# --- Raw hex digests ---------------------------------------------------------

MD5 = Signature(
    name="MD5",
    pattern=_hex(32),
    strength=Strength.WEAK,
    strength_note="Fast and unsalted: GPUs test billions of guesses per second.",
    example="8743b52063cd84097a65d1633f5c74f5",
    hashcat_mode=0,
    john_format="raw-md5",
    popularity=100,
    contexts=_WEB_DB,
)

NTLM = Signature(
    name="NTLM",
    pattern=_hex(32),
    strength=Strength.WEAK,
    strength_note="Unsalted MD4 of the password: even faster to crack than MD5.",
    example="b4b9b02e6f09a9bd760f388b67351e2b",
    hashcat_mode=1000,
    john_format="nt",
    popularity=60,
    contexts=frozenset({Context.WINDOWS}),
)

SHA1 = Signature(
    name="SHA-1",
    pattern=_hex(40),
    strength=Strength.WEAK,
    strength_note="Fast and unsalted, and collision-broken since 2017.",
    example="b89eaac7e61417341b710b727768294d0e6a277b",
    hashcat_mode=100,
    john_format="raw-sha1",
    popularity=80,
    contexts=_WEB_DB,
)

SHA224 = Signature(
    name="SHA-224",
    pattern=_hex(56),
    strength=Strength.MODERATE,
    strength_note="Sound SHA-2 primitive, but fast and unsalted for passwords.",
    example="e4fa1555ad877bf0ec455483371867200eee89550a93eff2f95a6198",
    hashcat_mode=1300,
    john_format="raw-sha224",
    popularity=20,
    contexts=_WEB_DB,
)

SHA256 = Signature(
    name="SHA-256",
    pattern=_hex(64),
    strength=Strength.MODERATE,
    strength_note="Sound SHA-2 primitive, but fast and unsalted for passwords.",
    example="127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935",
    hashcat_mode=1400,
    john_format="raw-sha256",
    popularity=80,
    contexts=_WEB_DB,
)

SHA512 = Signature(
    name="SHA-512",
    pattern=_hex(128),
    strength=Strength.MODERATE,
    strength_note="Sound SHA-2 primitive, but fast and unsalted for passwords.",
    example=(
        "82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e291"
        "34d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f"
    ),
    hashcat_mode=1700,
    john_format="raw-sha512",
    popularity=60,
    contexts=_WEB_DB,
)

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
    pattern=r"\*?" + _hex(40),
    strength=Strength.WEAK,
    strength_note="Unsalted double SHA-1: identical passwords give identical hashes.",
    example="*FCF7C1B8749CF99D88E5F34271D636178FB5D130",
    hashcat_mode=300,
    john_format="mysql-sha1",
    popularity=40,
    contexts=frozenset({Context.DB}),
)

# --- Modular crypt format ($id$...) -----------------------------------------

MD5CRYPT = Signature(
    name="md5crypt",
    # $1$, a salt of up to 8 chars, then a 22-char hash.
    pattern=rf"\$1\${_SALT}{{0,8}}\${_B64}{{22}}",
    strength=Strength.WEAK,
    strength_note="Salted but outdated: 1,000 MD5 rounds are fast on modern GPUs.",
    example="$1$ehAsHC4t$4IbK3fHS/H1YGtNYBrIEB1",
    hashcat_mode=500,
    john_format="md5crypt",
    popularity=60,
    contexts=_LINUX,
)

SHA512CRYPT = Signature(
    name="sha512crypt",
    # $6$, optional rounds=N$, a salt of up to 16 chars, then an 86-char hash.
    pattern=rf"\$6\$(?:rounds=[0-9]{{1,9}}\$)?{_SALT}{{0,16}}\${_B64}{{86}}",
    strength=Strength.STRONG,
    strength_note="Salted, with 5,000 SHA-512 rounds by default (tunable via rounds=).",
    example=(
        "$6$qdMgClgO2dQWB37F$jhexCX1SdsCAi0OZmoRVAPnWSwuP/mHVhXIMJfKlaacx"
        "FkwWLDZ0ViF8Ur3WcHashcatVp2WShcEILi8QZCbt/"
    ),
    hashcat_mode=1800,
    john_format="sha512crypt",
    popularity=80,
    contexts=_LINUX,
)

BCRYPT = Signature(
    name="bcrypt",
    # $2a$/$2b$/$2y$, a cost of 04-31, then 22 salt + 31 hash chars of bcrypt base64.
    pattern=rf"\$2[aby]\$(?:0[4-9]|[12][0-9]|3[01])\${_B64}{{53}}",
    strength=Strength.STRONG,
    strength_note="Salted and deliberately slow, with a tunable cost factor per guess.",
    example="$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6",
    hashcat_mode=3200,
    john_format="bcrypt",
    popularity=80,
    contexts=_WEB_DB,
)

SIGNATURES: tuple[Signature, ...] = (
    MD5,
    NTLM,
    SHA1,
    SHA224,
    SHA256,
    SHA512,
    MYSQL41,
    MD5CRYPT,
    SHA512CRYPT,
    BCRYPT,
)

_BY_NAME: dict[str, Signature] = {sig.name.casefold(): sig for sig in SIGNATURES}


def get_signature(name: str) -> Signature:
    """Look up a signature by name, ignoring case.

    Raises KeyError if no signature has that name.
    """
    try:
        return _BY_NAME[name.casefold()]
    except KeyError:
        known = ", ".join(sig.name for sig in SIGNATURES)
        raise KeyError(f"Unknown signature {name!r}; known: {known}") from None
