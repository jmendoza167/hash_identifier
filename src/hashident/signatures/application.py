"""Formats tied to a product: web applications, Windows and games.

Databases are in ``databases`` and network devices and protocols in
``network``; all three modules hold the application category.
"""

from __future__ import annotations

from hashident.models import Category, Charset, Context, Signature, Strength, Tier
from hashident.signatures._shared import B64, BASE64, COLON_FIELD, WEB, WINDOWS, hex_chars

_P, _L = Tier.POSSIBLE, Tier.LEAST_POSSIBLE
_WEAK, _MODERATE, _STRONG = Strength.WEAK, Strength.MODERATE, Strength.STRONG

_PHPASS_NOTE = "Salted, with a few thousand MD5 rounds: slower than raw MD5, still GPU-friendly."
_SALTED_ONCE = "Salted, but one round of a fast hash: the salt stops lookup tables, not GPUs."


def _app(
    name: str,
    tier: Tier,
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
    contexts: frozenset[Context] = frozenset(),
) -> Signature:
    return Signature(
        name=name,
        category=Category.APPLICATION,
        tier=tier,
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
        contexts=contexts,
    )


# --- phpass: $P$ (WordPress and others) and $H$ (phpBB3) ------------------------
# A cost character, an 8-character salt and a 22-character hash.

WORDPRESS = _app(
    "WordPress (phpass)",
    _P,
    60,
    "$P$9d2OMJEOHyPg11MeSv46hashcatG.F1",
    pattern=rf"\$P\${B64}{{31}}",
    length=34,
    charset=Charset.CRYPT64,
    prefixes=("$P$",),
    summary="MD5(Wordpress), also Joomla 2.5.18+",
    strength=_WEAK,
    note=_PHPASS_NOTE,
    hashcat=400,
    john="phpass",
    contexts=WEB,
)

PHPBB3 = _app(
    "phpBB3 (phpass)",
    _P,
    60,
    "$H$984478476IagS59wHZvyQMArzfx58u.",
    pattern=rf"\$H\${B64}{{31}}",
    length=34,
    charset=Charset.CRYPT64,
    prefixes=("$H$",),
    summary="MD5(phpBB3)",
    strength=_WEAK,
    note=_PHPASS_NOTE,
    hashcat=400,
    john="phpass",
    contexts=WEB,
)

# Listed by classic hash identifiers; no specification or vector was found,
# so the example is a placeholder with the right shape.
WORDPRESS_HMAC = _app(
    "MD5(HMAC(Wordpress))",
    _L,
    12,
    "3f2a9c5d7e1b4a6088c0d1e2f3a4b5c6",
    length=32,
    strength=_WEAK,
    note="A keyed MD5: as fast to guess as MD5 once the key is known.",
)

# --- Joomla -------------------------------------------------------------------

# md5($pass.$salt) with a random salt of 32 characters (16 in old versions).
# Without the salt it cannot be told from any other salted MD5.
JOOMLA = _app(
    "Joomla",
    _P,
    60,
    "19e0e8d91c722e7091ca7a6a6fb0f4fa:54718031842521651757785603028777",
    pattern=rf"{hex_chars(32)}:[0-9A-Za-z]{{16}}(?:[0-9A-Za-z]{{16}})?",
    structure="hash:salt",
    summary="md5($pass.$salt), before 2.5.18",
    strength=_WEAK,
    note=_SALTED_ONCE,
    hashcat=11,
    john="dynamic_1",
    notes=("For john, write it as '$dynamic_1$', the hash, '$', then the salt.",),
    contexts=WEB,
)

# --- Django -------------------------------------------------------------------
# algorithm$salt$hash, or algorithm$iterations$salt$hash for PBKDF2.

DJANGO_SHA1 = _app(
    "Django SHA-1",
    _P,
    40,
    "sha1$fe76b$02d5916550edf7fc8c886f044887f4b1abf9b013",
    pattern=rf"sha1\$[^$\s]*\${hex_chars(40)}",
    prefixes=("sha1$",),
    summary="SHA-1(Django), sha1($salt.$pass)",
    strength=_WEAK,
    note=_SALTED_ONCE,
    hashcat=124,
    contexts=WEB,
)

DJANGO_SHA256 = _app(
    "Django SHA-256",
    _P,
    30,
    "sha256$fe76b$3cf18d7e96a945e53d51a2e62a742eb95297bfd373518dcdff1133d54268dcee",
    pattern=rf"sha256\$[^$\s]*\${hex_chars(64)}",
    prefixes=("sha256$",),
    summary="SHA-256(Django), sha256($salt.$pass)",
    strength=_MODERATE,
    note=_SALTED_ONCE,
    contexts=WEB,
)

DJANGO_SHA384 = _app(
    "Django SHA-384",
    _P,
    20,
    (
        "sha384$fe76b$a77a0b1f30d4bbf195646e4e3a8dd28026c56467f54f12c9"
        "040321f3c9197afca17cb7f12e3f53653f65117fc62d0a8a"
    ),
    pattern=rf"sha384\$[^$\s]*\${hex_chars(96)}",
    prefixes=("sha384$",),
    summary="SHA-384(Django), sha384($salt.$pass)",
    strength=_MODERATE,
    note=_SALTED_ONCE,
    contexts=WEB,
)

DJANGO_PBKDF2 = _app(
    "Django PBKDF2-SHA256",
    _P,
    80,
    "pbkdf2_sha256$20000$H0dPx8NeajVu$GiC4k5kqbbR9qWBlsRgDywNqC2vd9kqfk7zdorEnNas=",
    pattern=rf"pbkdf2_sha256\$[0-9]+\$[^$\s]+\${BASE64}{{43}}=",
    charset=Charset.BASE64,
    prefixes=("pbkdf2_sha256$",),
    summary="Django's default since 1.4",
    strength=_STRONG,
    note="Salted PBKDF2-SHA256 with a tunable iteration count.",
    hashcat=10000,
    john="django",
    notes=("For john, put '$django$*1*' in front of the hash.",),
    contexts=WEB,
)

# --- Windows ------------------------------------------------------------------

SAM = _app(
    "SAM (LM:NT)",
    _P,
    65,
    "299bd128c1101fd6aad3b435b51404ee:b4b9b02e6f09a9bd760f388b67351e2b",
    pattern=rf"{hex_chars(32)}:{hex_chars(32)}",
    length=65,
    structure="LM:NT",
    summary="LM hash, then NTLM hash",
    strength=_WEAK,
    note="Both halves are unsalted and fast; the LM half falls in seconds.",
    hashcat=1000,
    john="nt",
    notes=(
        "Crack the NTLM half, after the ':', with hashcat mode 1000 or john's nt "
        "format. The LM half takes hashcat mode 3000 or john's lm format.",
    ),
    contexts=WINDOWS,
)

# One line of pwdump or secretsdump output: user:rid:LM:NT:::. An account
# without an LM hash may show a placeholder in that field.
_NO_PASSWORD = r"NO PASSWORD\*{21}"
PWDUMP = _app(
    "pwdump",
    _P,
    70,
    "Administrator:500:299bd128c1101fd6aad3b435b51404ee:b4b9b02e6f09a9bd760f388b67351e2b:::",
    pattern=(
        rf"[^:\s][^:]*:[0-9]+:(?:{hex_chars(32)}|{_NO_PASSWORD})"
        rf":(?:{hex_chars(32)}|{_NO_PASSWORD}):[^:]*:[^:]*:[^:]*"
    ),
    structure="user:rid:LM:NT:::",
    summary="a line of pwdump or secretsdump output",
    strength=_WEAK,
    note="Both hashes are unsalted and fast; the LM hash falls in seconds.",
    hashcat=1000,
    john="nt",
    notes=(
        "Hashcat mode 1000 and john's nt format read the whole line and take the "
        "NTLM hash from it. Use hashcat mode 3000 or john's lm format for the LM hash.",
    ),
    contexts=WINDOWS,
)

# MD4(NT hash + lowercased username). Hashcat writes it hash:username; the
# username is the salt, so without it this is one more guess for 32 hex.
DCC = _app(
    "Domain Cached Credentials",
    _P,
    30,
    "4dd8965d1d476fa0d026722989a6b772:3060147285011",
    pattern=rf"{hex_chars(32)}(?P<structure>:{COLON_FIELD})?",
    structure="hash:username",
    summary="DCC, MS Cache, mscash",
    strength=_WEAK,
    note="Salted with the username only, and one fast MD4 round on top of NTLM.",
    hashcat=1100,
    john="mscash",
    contexts=WINDOWS,
)

DCC2 = _app(
    "Domain Cached Credentials 2",
    _P,
    60,
    "$DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f",
    pattern=rf"\$DCC2\$[0-9]+#[^#\s]+#{hex_chars(32)}",
    prefixes=("$DCC2$",),
    summary="DCC2, MS Cache 2, mscash2",
    strength=_MODERATE,
    note="Salted with the username, with 10,240 PBKDF2-SHA1 rounds by default.",
    hashcat=2100,
    john="mscash2",
    contexts=WINDOWS,
)

RADMIN2 = _app(
    "RAdmin v2.x",
    _L,
    18,
    "22527bee5c29ce95373c4e0f359f079b",
    length=32,
    summary="MD5 of the password padded to 100 bytes",
    strength=_WEAK,
    note="Unsalted MD5 of a padded password: as fast to crack as MD5.",
    hashcat=9900,
    john="radmin",
    notes=("For john, put '$radmin2$' in front of the hash.",),
    contexts=WINDOWS,
)

# --- Games ----------------------------------------------------------------------

# "0x" and 32 hex characters, as classic hash identifiers list it. No
# specification or vector was found; the example is a placeholder. It is not
# given a prefix: "0x" in front of hex is far too common to pin a format down.
LINEAGE2_C4 = _app(
    "Lineage II C4",
    _L,
    10,
    "0x6b3e2c9a1f4d8705b2c1e09f7a6d5c4b",
    pattern=rf"0x{hex_chars(32)}",
    length=34,
    strength=_WEAK,
    note="A game server's own unsalted hash.",
)

MANGOS = _app(
    "SHA-1(MaNGOS)",
    _L,
    12,
    "4f65fa6d23df9c6308babc1ae87c0e7dbef4764b",
    length=40,
    summary="sha1(upper($user):upper($pass))",
    strength=_WEAK,
    note="One SHA-1 round salted with the account name only.",
    john="dynamic_35",
)

SIGNATURES: tuple[Signature, ...] = (
    WORDPRESS,
    PHPBB3,
    WORDPRESS_HMAC,
    JOOMLA,
    DJANGO_SHA1,
    DJANGO_SHA256,
    DJANGO_SHA384,
    DJANGO_PBKDF2,
    SAM,
    PWDUMP,
    DCC,
    DCC2,
    RADMIN2,
    LINEAGE2_C4,
    MANGOS,
)
