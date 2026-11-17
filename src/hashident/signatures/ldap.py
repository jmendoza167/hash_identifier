"""LDAP userPassword values: a ``{SCHEME}`` tag, then the digest in base64.

In the salted schemes the salt follows the digest inside the base64, so the
encoded part has a minimum length and no fixed one. Scheme names are not
case-sensitive.
"""

from __future__ import annotations

from hashident.models import Category, Charset, Signature, Strength, Tier
from hashident.signatures._shared import BASE64

_WEAK, _MODERATE = Strength.WEAK, Strength.MODERATE

_UNSALTED = "One unsalted round of a fast hash."
_SALTED = "Salted, but one round of a fast hash: the salt stops lookup tables, not GPUs."


def _ldap(
    scheme: str,
    example: str,
    *,
    encoded: str,
    strength: Strength,
    note: str,
    summary: str,
    hashcat: int | None = None,
    john: str | None = None,
) -> Signature:
    """``{SCHEME}`` in either case, then ``encoded``: a pattern for the base64."""
    tag = "{" + scheme + "}"
    return Signature(
        name=f"LDAP {tag}",
        category=Category.APPLICATION,
        tier=Tier.POSSIBLE,
        pattern=rf"(?i:\{{{scheme}\}}){encoded}",
        charset=Charset.BASE64,
        prefixes=(tag, tag.lower()),
        summary=summary,
        strength=strength,
        strength_note=note,
        example=example,
        hashcat_mode=hashcat,
        john_format=john,
        popularity=60,
    )


def _at_least(characters: int) -> str:
    """Base64 of a digest and a salt: ``characters`` or more, then any padding."""
    return rf"{BASE64}{{{characters},}}={{0,2}}"


LDAP_SHA = _ldap(
    "SHA",
    "{SHA}uJ6qx+YUFzQbcQtyd2gpTQ5qJ3s=",
    encoded=rf"{BASE64}{{27}}=",
    summary="SHA-1 in base64, nsldap",
    strength=_WEAK,
    note=_UNSALTED,
    hashcat=101,
    john="raw-sha1",
)

LDAP_SSHA = _ldap(
    "SSHA",
    "{SSHA}AZKja92fbuuB9SpRlHqaoXxbTc43Mzc2MDM1Ng==",
    encoded=_at_least(28),
    summary="salted SHA-1, nsldaps",
    strength=_WEAK,
    note=_SALTED,
    hashcat=111,
    john="salted-sha1",
)

LDAP_SSHA256 = _ldap(
    "SSHA256",
    "{SSHA256}OZiz0cnQ5hgyel3Emh7NCbhBRCQ+HVBwYplQunHYnER7TLuV",
    encoded=_at_least(44),
    summary="salted SHA-256",
    strength=_MODERATE,
    note=_SALTED,
    hashcat=1411,
)

LDAP_SSHA512 = _ldap(
    "SSHA512",
    (
        "{SSHA512}ALtwKGBdRgD+U0fPAy31C28RyKYx7+a8kmfksccsOeLknLHv2DBXYI7TDnTo"
        "lQMBuPkWDISgZr2cHfnNPFjGZTEyNDU4OTkw"
    ),
    encoded=_at_least(88),
    summary="salted SHA-512",
    strength=_MODERATE,
    note=_SALTED,
    hashcat=1711,
    john="ssha512",
)

LDAP_MD5 = _ldap(
    "MD5",
    "{MD5}h0O1IGPNhAl6ZdFjP1x09Q==",
    encoded=rf"{BASE64}{{22}}==",
    summary="MD5 in base64",
    strength=_WEAK,
    note=_UNSALTED,
)

LDAP_SMD5 = _ldap(
    "SMD5",
    "{SMD5}zXXWW6eICejpQqwFi7YVlnNhbHQ=",
    encoded=_at_least(24),
    summary="salted MD5",
    strength=_WEAK,
    note=_SALTED,
)

SIGNATURES: tuple[Signature, ...] = (
    LDAP_SHA,
    LDAP_SSHA,
    LDAP_SSHA256,
    LDAP_SSHA512,
    LDAP_MD5,
    LDAP_SMD5,
)
