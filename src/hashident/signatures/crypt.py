"""crypt(3)-style formats: a ``$id$`` marker, then parameters, salt and hash."""

from __future__ import annotations

from hashident.models import Category, Charset, Signature, Strength, Tier
from hashident.signatures._shared import B64, LINUX, SALT, WEB_DB

MD5CRYPT = Signature(
    name="md5crypt",
    category=Category.CRYPT,
    tier=Tier.POSSIBLE,
    # $1$, a salt of up to 8 chars, then a 22-char hash.
    pattern=rf"\$1\${SALT}{{0,8}}\${B64}{{22}}",
    charset=Charset.CRYPT64,
    prefixes=("$1$",),
    summary="MD5(Unix), Cisco-IOS type 5",
    strength=Strength.WEAK,
    strength_note="Salted but outdated: 1,000 MD5 rounds are fast on modern GPUs.",
    example="$1$ehAsHC4t$4IbK3fHS/H1YGtNYBrIEB1",
    hashcat_mode=500,
    john_format="md5crypt",
    popularity=60,
    contexts=LINUX,
)

SHA512CRYPT = Signature(
    name="sha512crypt",
    category=Category.CRYPT,
    tier=Tier.POSSIBLE,
    # $6$, optional rounds=N$, a salt of up to 16 chars, then an 86-char hash.
    pattern=rf"\$6\$(?:rounds=[0-9]{{1,9}}\$)?{SALT}{{0,16}}\${B64}{{86}}",
    charset=Charset.CRYPT64,
    prefixes=("$6$",),
    strength=Strength.STRONG,
    strength_note="Salted, with 5,000 SHA-512 rounds by default (tunable via rounds=).",
    example=(
        "$6$qdMgClgO2dQWB37F$jhexCX1SdsCAi0OZmoRVAPnWSwuP/mHVhXIMJfKlaacx"
        "FkwWLDZ0ViF8Ur3WcHashcatVp2WShcEILi8QZCbt/"
    ),
    hashcat_mode=1800,
    john_format="sha512crypt",
    popularity=80,
    contexts=LINUX,
)

BCRYPT = Signature(
    name="bcrypt",
    category=Category.CRYPT,
    tier=Tier.POSSIBLE,
    # $2a$/$2b$/$2y$, a cost of 04-31, then 22 salt + 31 hash chars of bcrypt base64.
    pattern=rf"\$2[aby]\$(?:0[4-9]|[12][0-9]|3[01])\${B64}{{53}}",
    length=60,
    charset=Charset.CRYPT64,
    prefixes=("$2a$", "$2b$", "$2y$"),
    strength=Strength.STRONG,
    strength_note="Salted and deliberately slow, with a tunable cost factor per guess.",
    example="$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6",
    hashcat_mode=3200,
    john_format="bcrypt",
    popularity=80,
    contexts=WEB_DB,
)

SIGNATURES: tuple[Signature, ...] = (MD5CRYPT, SHA512CRYPT, BCRYPT)
