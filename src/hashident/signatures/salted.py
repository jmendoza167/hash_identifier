"""Generic salted, keyed and nested constructions around a plain hash.

These are not tied to one product: ``md5($pass.$salt)`` is how countless
home-grown applications store passwords.

A salted hash is written ``hash:salt``, the form Hashcat uses. Its pattern
makes the salt optional, because a dump often has the salt in another
column: with the salt the format is a structure match, and without it the
engine lists it as a least possible format for a bare digest.

Nested hashes such as ``md5(md5($pass))`` have no salt and look exactly like
a raw digest, so they are always least possible.
"""

from __future__ import annotations

from hashident.models import Category, Charset, Signature, Strength, Tier
from hashident.signatures._shared import COLON_FIELD, hex_chars

_P, _L = Tier.POSSIBLE, Tier.LEAST_POSSIBLE
_WEAK, _MODERATE = Strength.WEAK, Strength.MODERATE

_SALTED_NOTE = "Salted, but one round of a fast hash: the salt stops lookup tables, not GPUs."
_NESTED_NOTE = "Hashing twice adds almost nothing: still fast and unsalted."
_KEYED_NOTE = "A keyed hash is as fast to guess as the hash inside it."


def _john_dynamic(number: int) -> str:
    return f"For john, write it as '$dynamic_{number}$', the hash, '$', then the salt."


_JOHN_HMAC = "For john, write it as the salt, '#', then the hash."


def _salted(
    name: str,
    hex_length: int,
    tier: Tier,
    popularity: float,
    example: str,
    *,
    strength: Strength,
    note: str = _SALTED_NOTE,
    hashcat: int | None = None,
    john: str | None = None,
    notes: tuple[str, ...] = (),
) -> Signature:
    """A digest of ``hex_length`` hex characters, then an optional ``:salt``."""
    return Signature(
        name=name,
        category=Category.SALTED,
        tier=tier,
        pattern=rf"{hex_chars(hex_length)}(?P<structure>:{COLON_FIELD})?",
        charset=Charset.HEX,
        structure="hash:salt",
        strength=strength,
        strength_note=note,
        example=example,
        hashcat_mode=hashcat,
        john_format=john,
        notes=notes,
        popularity=popularity,
    )


def _dynamic(
    name: str,
    hex_length: int,
    popularity: float,
    example: str,
    *,
    strength: Strength,
    hashcat: int,
    john: int,
) -> Signature:
    """``$pass`` and ``$salt`` joined and hashed once: possible when salted."""
    return _salted(
        name,
        hex_length,
        _P,
        popularity,
        example,
        strength=strength,
        hashcat=hashcat,
        john=f"dynamic_{john}",
        notes=(_john_dynamic(john),),
    )


def _hmac(
    name: str,
    hex_length: int,
    popularity: float,
    example: str,
    *,
    strength: Strength,
    hashcat: int,
    john: str | None = None,
) -> Signature:
    """An HMAC over ``$pass`` and ``$salt``; John only does the key = $pass kind."""
    return _salted(
        name,
        hex_length,
        _L,
        popularity,
        example,
        strength=strength,
        note=_KEYED_NOTE,
        hashcat=hashcat,
        john=john,
        notes=(_JOHN_HMAC,) if john else (),
    )


def _nested(
    name: str,
    hex_length: int,
    popularity: float,
    example: str,
    *,
    hashcat: int,
    john: str | None = None,
) -> Signature:
    """A hash of a hash, with no salt: the same shape as a raw digest."""
    return Signature(
        name=name,
        category=Category.SALTED,
        tier=_L,
        length=hex_length,
        charset=Charset.HEX,
        strength=_WEAK,
        strength_note=_NESTED_NOTE,
        example=example,
        hashcat_mode=hashcat,
        john_format=john,
        popularity=popularity,
    )


# --- MD5: 32 hex characters ---------------------------------------------------

MD5_MD5 = _nested(
    "md5(md5($pass))", 32, 38, "a936af92b0ae20b1ff6c3347a72e5fbe", hashcat=2600, john="dynamic_2"
)

MD5_PASS_SALT = _dynamic(
    "md5($pass.$salt)",
    32,
    34,
    "01dfae6e5d4d90d9892622325959afbe:7050461",
    strength=_WEAK,
    hashcat=10,
    john=1,
)

MD5_SALT_PASS = _dynamic(
    "md5($salt.$pass)",
    32,
    33,
    "f0fda58630310a6dd91a7d8f0a4ceda2:4225637426",
    strength=_WEAK,
    hashcat=20,
    john=4,
)

MD5_SHA1 = _nested(
    "md5(sha1($pass))", 32, 25, "288496df99b33f8f75a7ce4837d1b480", hashcat=4400, john="dynamic_22"
)

HMAC_MD5_PASS = _hmac(
    "HMAC-MD5 (key = $pass)",
    32,
    22,
    "fc741db0a2968c39d9c2a5cc75b05370:1234",
    strength=_WEAK,
    hashcat=50,
    john="hmac-md5",
)

HMAC_MD5_SALT = _hmac(
    "HMAC-MD5 (key = $salt)",
    32,
    21,
    "bfd280436f45fa38eaacac3b00518f29:1234",
    strength=_WEAK,
    hashcat=60,
)

MD5_SALT_MD5 = _salted(
    "md5($salt.md5($pass))",
    32,
    _L,
    18,
    "95248989ec91f6d0439dbde2bd0140be:1234",
    strength=_WEAK,
    hashcat=3710,
    john="dynamic_9",
    notes=(_john_dynamic(9),),
)

# --- SHA-1: 40 hex characters -------------------------------------------------

SHA1_PASS_SALT = _dynamic(
    "sha1($pass.$salt)",
    40,
    34,
    "2fc5a684737ce1bf7b3b239df432416e0dd07357:2014",
    strength=_WEAK,
    hashcat=110,
    john=24,
)

SHA1_SALT_PASS = _dynamic(
    "sha1($salt.$pass)",
    40,
    33,
    "cac35ec206d868b7d7cb0b55f31d9425b075082b:5363620024",
    strength=_WEAK,
    hashcat=120,
    john=25,
)

SHA1_MD5 = _nested(
    "sha1(md5($pass))",
    40,
    30,
    "92d85978d884eb1d99a51652b1139c8279fa8663",
    hashcat=4700,
    john="dynamic_23",
)

# Not MySQL 4.1+: there the inner SHA-1 is hashed as raw bytes, here as hex.
SHA1_SHA1 = _nested(
    "sha1(sha1($pass))", 40, 25, "3db9184f5da4e463832b086211af8d2314919951", hashcat=4500
)

HMAC_SHA1_PASS = _hmac(
    "HMAC-SHA1 (key = $pass)",
    40,
    22,
    "c898896f3f70f61bc3fb19bef222aa860e5ea717:1234",
    strength=_WEAK,
    hashcat=150,
    john="hmac-sha1",
)

HMAC_SHA1_SALT = _hmac(
    "HMAC-SHA1 (key = $salt)",
    40,
    21,
    "d89c92b4400b15c39e462a8caa939ab40c3aeeea:1234",
    strength=_WEAK,
    hashcat=160,
)

# --- SHA-256: 64 hex characters -----------------------------------------------

SHA256_PASS_SALT = _dynamic(
    "sha256($pass.$salt)",
    64,
    34,
    "c73d08de890479518ed60cf670d17faa26a4a71f995c1dcc978165399401a6c4:53743528",
    strength=_MODERATE,
    hashcat=1410,
    john=62,
)

SHA256_SALT_PASS = _dynamic(
    "sha256($salt.$pass)",
    64,
    33,
    "eb368a2dfd38b405f014118c7d9747fcc97f4f0ee75c05963cd9da6ee65ef498:560407001617",
    strength=_MODERATE,
    hashcat=1420,
    john=61,
)

HMAC_SHA256_PASS = _hmac(
    "HMAC-SHA256 (key = $pass)",
    64,
    22,
    "abaf88d66bf2334a4a8b207cc61a96fb46c3e38e882e6f6f886742f688b8588c:1234",
    strength=_MODERATE,
    hashcat=1450,
    john="hmac-sha256",
)

HMAC_SHA256_SALT = _hmac(
    "HMAC-SHA256 (key = $salt)",
    64,
    21,
    "8efbef4cec28f228fa948daaf4893ac3638fbae81358ff9020be1d7a9a509fc6:1234",
    strength=_MODERATE,
    hashcat=1460,
)

# --- SHA-512: 128 hex characters ----------------------------------------------

SHA512_PASS_SALT = _dynamic(
    "sha512($pass.$salt)",
    128,
    34,
    (
        "e5c3ede3e49fb86592fb03f471c35ba13e8d89b8ab65142c9a8fdafb635fa222"
        "3c24e5558fd9313e8995019dcbec1fb584146b7bb12685c7765fc8c0d51379fd:6352283260"
    ),
    strength=_MODERATE,
    hashcat=1710,
    john=82,
)

SHA512_SALT_PASS = _dynamic(
    "sha512($salt.$pass)",
    128,
    33,
    (
        "976b451818634a1e2acba682da3fd6efa72adf8a7a08d7939550c244b237c72c"
        "7d42367544e826c0c83fe5c02f97c0373b6b1386cc794bf0d21d2df01bb9c08a:2613516180127"
    ),
    strength=_MODERATE,
    hashcat=1720,
    john=81,
)

HMAC_SHA512_PASS = _hmac(
    "HMAC-SHA512 (key = $pass)",
    128,
    22,
    (
        "94cb9e31137913665dbea7b058e10be5f050cc356062a2c9679ed0ad6119648e"
        "7be620e9d4e1199220cd02b9efb2b1c78234fa1000c728f82bf9f14ed82c1976:1234"
    ),
    strength=_MODERATE,
    hashcat=1750,
    john="hmac-sha512",
)

HMAC_SHA512_SALT = _hmac(
    "HMAC-SHA512 (key = $salt)",
    128,
    21,
    (
        "7cce966f5503e292a51381f238d071971ad5442488f340f98e379b3aeae2f337"
        "78e3e732fcc2f7bdc04f3d460eebf6f8cb77da32df25500c09160dd3bf7d2a6b:1234"
    ),
    strength=_MODERATE,
    hashcat=1760,
)

SIGNATURES: tuple[Signature, ...] = (
    MD5_MD5,
    MD5_PASS_SALT,
    MD5_SALT_PASS,
    MD5_SHA1,
    HMAC_MD5_PASS,
    HMAC_MD5_SALT,
    MD5_SALT_MD5,
    SHA1_PASS_SALT,
    SHA1_SALT_PASS,
    SHA1_MD5,
    SHA1_SHA1,
    HMAC_SHA1_PASS,
    HMAC_SHA1_SALT,
    SHA256_PASS_SALT,
    SHA256_SALT_PASS,
    HMAC_SHA256_PASS,
    HMAC_SHA256_SALT,
    SHA512_PASS_SALT,
    SHA512_SALT_PASS,
    HMAC_SHA512_PASS,
    HMAC_SHA512_SALT,
)
