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

# --- PBKDF2 ---------------------------------------------------------------------

_PBKDF2_NOTE = "Salted PBKDF2 with a tunable iteration count."
_AB64 = "[./0-9A-Za-z]"  # passlib's adapted base64: '.' for '+', no padding


def _passlib(digest: str, tag: str, characters: int, example: str, hashcat: int, john=None):
    """``$tag$rounds$salt$hash``, as Python's passlib writes PBKDF2."""
    return _crypt(
        f"passlib PBKDF2-{digest}",
        60,
        example,
        pattern=rf"\${tag}\$[0-9]+\${_AB64}+\${_AB64}{{{characters}}}",
        prefixes=(f"${tag}$",),
        summary=f"${tag}$",
        strength=_STRONG,
        note=_PBKDF2_NOTE,
        hashcat=hashcat,
        john=john,
        contexts=WEB,
    )


PASSLIB_PBKDF2_SHA256 = _passlib(
    "SHA256",
    "pbkdf2-sha256",
    43,
    "$pbkdf2-sha256$29000$x9h7j/Ge8x6DMEao1VqrdQ$kra3R1wEnY8mPdDWOpTqOTINaAmZvRMcYd8u5OBQP9A",
    20300,
    john="pbkdf2-hmac-sha256",
)

PASSLIB_PBKDF2_SHA512 = _passlib(
    "SHA512",
    "pbkdf2-sha512",
    86,
    (
        "$pbkdf2-sha512$25000$LyWE0HrP2RsjZCxlDGFMKQ$1vC5Ohk2mCS9b6akqsEfgeb4l74SF8XjH"
        ".SljXf3dMLHdlY1GK9ojcCKts6/asR4aPqBmk74nCDddU3tvSCJvw"
    ),
    20200,
)

PASSLIB_PBKDF2_SHA1 = _passlib(
    "SHA1",
    "pbkdf2",
    27,
    "$pbkdf2$131000$r5WythYixPgfQ2jt3buXcg$8Kdr.QQEOaZIXNOrrru36I/.6Po",
    20400,
)


def _pbkdf2_line(digest: str, tag: str, example: str, hashcat: int) -> Signature:
    """``tag:rounds:salt:hash`` with salt and hash in base64, as Hashcat reads it."""
    return _crypt(
        f"PBKDF2-HMAC-{digest}",
        50,
        example,
        pattern=rf"{tag}:[0-9]+:{BASE64}+={{0,2}}:{BASE64}+={{0,2}}",
        charset=Charset.BASE64,
        prefixes=(f"{tag}:",),
        summary=f"{tag}:rounds:salt:hash",
        strength=_STRONG,
        note=_PBKDF2_NOTE,
        hashcat=hashcat,
        contexts=WEB,
    )


PBKDF2_SHA256 = _pbkdf2_line(
    "SHA256", "sha256", "sha256:1000:MTc3MTA0MTQwMjQxNzY=:PYjCU215Mi57AYPKva9j7mvF4Rc5bCnt", 10900
)

PBKDF2_SHA1 = _pbkdf2_line(
    "SHA1", "sha1", "sha1:1000:MzU4NTA4MzIzNzA1MDQ=:19ofiY+ahBXhvkDsp0j2ww==", 12000
)

PBKDF2_SHA512 = _pbkdf2_line(
    "SHA512", "sha512", "sha512:1000:ODQyMDEwNjQyODY=:MKaHNWXUsuJB3IEwBHbm3w==", 12100
)

PBKDF2_MD5 = _pbkdf2_line(
    "MD5", "md5", "md5:1000:MTg1MzA=:Lz84VOcrXd699Edsj34PP98+f4f3S0rTZ4kHAIHoAjs=", 11900
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
    PASSLIB_PBKDF2_SHA256,
    PASSLIB_PBKDF2_SHA512,
    PASSLIB_PBKDF2_SHA1,
    PBKDF2_SHA256,
    PBKDF2_SHA1,
    PBKDF2_SHA512,
    PBKDF2_MD5,
)
