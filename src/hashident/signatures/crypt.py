"""crypt(3)-style and key-derivation formats.

Most start with a ``$id$`` marker, then parameters, a salt and the hash, so
they are pinned down by their prefix. Traditional DES crypt has no marker
and is recognised by its 13 characters alone.
"""

from __future__ import annotations

from hashident.models import Category, Charset, Context, Signature, Strength, Tier
from hashident.signatures._shared import B64, BASE64, LINUX, SALT, WEB, WEB_DB

_P = Tier.POSSIBLE
_WEAK, _STRONG = Strength.WEAK, Strength.STRONG

_MEMORY_HARD = "Salted and memory-hard: each guess costs memory as well as time."


def _crypt(
    name: str,
    popularity: float,
    example: str,
    *,
    pattern: str,
    strength: Strength,
    note: str,
    prefixes: tuple[str, ...] = (),
    length: int | None = None,
    charset: Charset = Charset.CRYPT64,
    summary: str = "",
    hashcat: int | None = None,
    john: str | None = None,
    notes: tuple[str, ...] = (),
    contexts: frozenset[Context] = LINUX,
) -> Signature:
    return Signature(
        name=name,
        category=Category.CRYPT,
        tier=_P,
        pattern=pattern,
        length=length,
        charset=charset,
        prefixes=prefixes,
        summary=summary,
        strength=strength,
        strength_note=note,
        example=example,
        hashcat_mode=hashcat,
        john_format=john,
        notes=notes,
        popularity=popularity,
        contexts=contexts,
    )


# 13 characters: a 2-character salt and an 11-character hash. The last
# character carries only 4 bits, so it is one of 16 of the 64 characters;
# checking that keeps most 13-letter words from matching.
DESCRYPT = _crypt(
    "descrypt",
    40,
    "48c/R8JAv757A",
    pattern=rf"{B64}{{12}}[.26AEIMQUYcgkosw]",
    length=13,
    summary="DES(Unix), traditional crypt",
    strength=_WEAK,
    note="Only the first 8 characters count and the salt is 12 bits: exhaustible.",
    hashcat=1500,
    john="descrypt",
)

MD5CRYPT = _crypt(
    "md5crypt",
    60,
    "$1$ehAsHC4t$4IbK3fHS/H1YGtNYBrIEB1",
    # $1$, a salt of up to 8 chars, then a 22-char hash.
    pattern=rf"\$1\${SALT}{{0,8}}\${B64}{{22}}",
    prefixes=("$1$",),
    summary="MD5(Unix), Cisco-IOS type 5",
    strength=_WEAK,
    note="Salted but outdated: 1,000 MD5 rounds are fast on modern GPUs.",
    hashcat=500,
    john="md5crypt",
)

MD5APR = _crypt(
    "MD5(APR)",
    50,
    "$apr1$71850310$gh9m4xcAn3MGxogwX/ztb.",
    # md5crypt with Apache's own marker.
    pattern=rf"\$apr1\${SALT}{{0,8}}\${B64}{{22}}",
    prefixes=("$apr1$",),
    summary="Apache htpasswd",
    strength=_WEAK,
    note="Salted but outdated: 1,000 MD5 rounds are fast on modern GPUs.",
    hashcat=1600,
    john="md5crypt",
    contexts=WEB,
)

SHA256CRYPT = _crypt(
    "sha256crypt",
    60,
    "$5$rounds=5000$GX7BopJZJxPc/KEK$le16UF8I2Anb.rOrn22AUPWvzUETDGefUmAV8AZkGcD",
    # $5$, optional rounds=N$, a salt of up to 16 chars, then a 43-char hash.
    pattern=rf"\$5\$(?:rounds=[0-9]{{1,9}}\$)?{SALT}{{0,16}}\${B64}{{43}}",
    prefixes=("$5$",),
    summary="SHA-256(Unix)",
    strength=_STRONG,
    note="Salted, with 5,000 SHA-256 rounds by default (tunable via rounds=).",
    hashcat=7400,
    john="sha256crypt",
)

SHA512CRYPT = _crypt(
    "sha512crypt",
    80,
    (
        "$6$qdMgClgO2dQWB37F$jhexCX1SdsCAi0OZmoRVAPnWSwuP/mHVhXIMJfKlaacx"
        "FkwWLDZ0ViF8Ur3WcHashcatVp2WShcEILi8QZCbt/"
    ),
    # $6$, optional rounds=N$, a salt of up to 16 chars, then an 86-char hash.
    pattern=rf"\$6\$(?:rounds=[0-9]{{1,9}}\$)?{SALT}{{0,16}}\${B64}{{86}}",
    prefixes=("$6$",),
    strength=_STRONG,
    note="Salted, with 5,000 SHA-512 rounds by default (tunable via rounds=).",
    hashcat=1800,
    john="sha512crypt",
)

BCRYPT = _crypt(
    "bcrypt",
    80,
    "$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6",
    # $2a$/$2b$/$2y$, a cost of 04-31, then 22 salt + 31 hash chars of bcrypt base64.
    pattern=rf"\$2[aby]\$(?:0[4-9]|[12][0-9]|3[01])\${B64}{{53}}",
    length=60,
    prefixes=("$2a$", "$2b$", "$2y$"),
    strength=_STRONG,
    note="Salted and deliberately slow, with a tunable cost factor per guess.",
    hashcat=3200,
    john="bcrypt",
    contexts=WEB_DB,
)

ARGON2 = _crypt(
    "Argon2",
    80,
    "$argon2id$v=19$m=65536,t=3,p=1$FBMjI4RJBhIykCgol1KEJA$2ky5GAdhT1kH4kIgPN/oERE3Taiy43vNN70a3HpiKQU",
    # $argon2id$ (or i, d), optional v=N$, the m,t,p costs, then salt$hash in base64.
    pattern=(
        r"\$argon2(?:id|i|d)\$(?:v=[0-9]+\$)?m=[0-9]+,t=[0-9]+,p=[0-9]+"
        rf"(?:,[a-z]+=[^$,\s]+)*\${BASE64}+\${BASE64}+"
    ),
    charset=Charset.BASE64,
    prefixes=("$argon2id$", "$argon2i$", "$argon2d$"),
    summary="Argon2i, Argon2d, Argon2id",
    strength=_STRONG,
    note=_MEMORY_HARD,
    hashcat=34000,
    john="argon2",
    contexts=WEB,
)

SCRYPT = _crypt(
    "scrypt",
    60,
    "SCRYPT:1024:1:1:MDIwMzMwNTQwNDQyNQ==:5FW+zWivLxgCWj7qLiQbeC8zaNQ+qdO0NUinvqyFcfo=",
    # SCRYPT:N:r:p:salt:hash, the layout Hashcat uses; salt and hash in base64.
    pattern=rf"SCRYPT:[0-9]+:[0-9]+:[0-9]+:{BASE64}+={{0,2}}:{BASE64}+={{0,2}}",
    charset=Charset.BASE64,
    prefixes=("SCRYPT:",),
    summary="SCRYPT:N:r:p:salt:hash",
    strength=_STRONG,
    note=_MEMORY_HARD,
    hashcat=8900,
    contexts=WEB,
)

SCRYPT_UNIX = _crypt(
    "scrypt (Unix)",
    40,
    "$7$C6..../....SodiumChloride$kBGj9fHznVYFQMEn/qDCfrDevf9YDtcDdKvEqHJLV8D",
    # $7$, 11 characters of cost settings, the salt, then a 43-char hash.
    pattern=rf"\$7\${B64}{{11}}[^$\s]*\${B64}{{43}}",
    prefixes=("$7$",),
    summary="scryptcrypt, $7$",
    strength=_STRONG,
    note=_MEMORY_HARD,
    hashcat=36300,
    john="scrypt",
)

YESCRYPT = _crypt(
    "yescrypt",
    80,
    "$y$j9T$oJqQoBLMgF5$77xERSZazujSxPgj6nYmzH5r0O2HelZJUyfW.ta7vxD",
    # $y$, the cost settings, the salt, then a 43-char hash.
    pattern=rf"\$y\${B64}+\${B64}{{0,86}}\${B64}{{43}}",
    prefixes=("$y$",),
    summary="default in current Debian, Ubuntu and Fedora",
    strength=_STRONG,
    note=_MEMORY_HARD,
    hashcat=36100,
    john="crypt",
    notes=("John's crypt format calls the system's crypt(3), so it needs a Linux with yescrypt.",),
)

GOST_YESCRYPT = _crypt(
    "gost-yescrypt",
    20,
    "$gy$j9T$HtyOX9cwJ2Dh8LlJV8IJ30$ZCSJt69pE/HLXFfIuxukRc2PlNla.tbqJxUHCp/WHVD",
    pattern=rf"\$gy\${B64}+\${B64}{{0,86}}\${B64}{{43}}",
    prefixes=("$gy$",),
    summary="yescrypt with GOST R 34.11-2012, used by ALT Linux",
    strength=_STRONG,
    note=_MEMORY_HARD,
    hashcat=36200,
)

SIGNATURES: tuple[Signature, ...] = (
    MD5CRYPT,
    SHA512CRYPT,
    BCRYPT,
    DESCRYPT,
    MD5APR,
    SHA256CRYPT,
    ARGON2,
    SCRYPT,
    SCRYPT_UNIX,
    YESCRYPT,
    GOST_YESCRYPT,
)
