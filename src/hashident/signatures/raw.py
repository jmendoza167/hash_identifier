"""Raw digests: the bare output of a hash function, with no salt or marker."""

from __future__ import annotations

from hashident.models import Category, Charset, Context, Signature, Strength, Tier
from hashident.signatures._shared import WEB_DB

MD5 = Signature(
    name="MD5",
    category=Category.RAW,
    tier=Tier.POSSIBLE,
    length=32,
    charset=Charset.HEX,
    strength=Strength.WEAK,
    strength_note="Fast and unsalted: GPUs test billions of guesses per second.",
    example="8743b52063cd84097a65d1633f5c74f5",
    hashcat_mode=0,
    john_format="raw-md5",
    popularity=100,
    contexts=WEB_DB,
)

NTLM = Signature(
    name="NTLM",
    category=Category.RAW,
    tier=Tier.POSSIBLE,
    length=32,
    charset=Charset.HEX,
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
    category=Category.RAW,
    tier=Tier.POSSIBLE,
    length=40,
    charset=Charset.HEX,
    strength=Strength.WEAK,
    strength_note="Fast and unsalted, and collision-broken since 2017.",
    example="b89eaac7e61417341b710b727768294d0e6a277b",
    hashcat_mode=100,
    john_format="raw-sha1",
    popularity=80,
    contexts=WEB_DB,
)

SHA224 = Signature(
    name="SHA-224",
    category=Category.RAW,
    tier=Tier.POSSIBLE,
    length=56,
    charset=Charset.HEX,
    strength=Strength.MODERATE,
    strength_note="Sound SHA-2 primitive, but fast and unsalted for passwords.",
    example="e4fa1555ad877bf0ec455483371867200eee89550a93eff2f95a6198",
    hashcat_mode=1300,
    john_format="raw-sha224",
    popularity=20,
    contexts=WEB_DB,
)

SHA256 = Signature(
    name="SHA-256",
    category=Category.RAW,
    tier=Tier.POSSIBLE,
    length=64,
    charset=Charset.HEX,
    strength=Strength.MODERATE,
    strength_note="Sound SHA-2 primitive, but fast and unsalted for passwords.",
    example="127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935",
    hashcat_mode=1400,
    john_format="raw-sha256",
    popularity=80,
    contexts=WEB_DB,
)

SHA512 = Signature(
    name="SHA-512",
    category=Category.RAW,
    tier=Tier.POSSIBLE,
    length=128,
    charset=Charset.HEX,
    strength=Strength.MODERATE,
    strength_note="Sound SHA-2 primitive, but fast and unsalted for passwords.",
    example=(
        "82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e291"
        "34d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f"
    ),
    hashcat_mode=1700,
    john_format="raw-sha512",
    popularity=60,
    contexts=WEB_DB,
)

SIGNATURES: tuple[Signature, ...] = (MD5, NTLM, SHA1, SHA224, SHA256, SHA512)
