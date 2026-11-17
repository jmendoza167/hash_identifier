"""Raw digests: the bare output of a hash function, with no salt or marker.

All of them are plain hex, so a digest is recognised by its length alone and
many formats share each length. The tier and popularity of each entry decide
how the formats of one length are presented: see ``hashident.signatures``.
"""

from __future__ import annotations

from hashident.models import Category, Charset, Context, Signature, Strength, Tier
from hashident.signatures._shared import WEB_DB

_P, _L = Tier.POSSIBLE, Tier.LEAST_POSSIBLE
_WEAK, _MODERATE = Strength.WEAK, Strength.MODERATE

_SOUND = "Sound primitive, but fast and unsalted for passwords."
_SHA2 = "Sound SHA-2 primitive, but fast and unsalted for passwords."
_LEGACY = "Legacy design with known weaknesses, and fast and unsalted for passwords."
_HAVAL_PASSES = (
    "HAVAL has 3, 4 and 5 pass variants with the same shape: hashcat modes {0}, {1} and {2}."
)
_BLAKE2_PREFIX = "For hashcat, put '$BLAKE2$' in front of the hash."


def _raw(
    name: str,
    length: int,
    tier: Tier,
    popularity: float,
    example: str,
    *,
    strength: Strength,
    note: str,
    hashcat: int | None = None,
    john: str | None = None,
    summary: str = "",
    notes: tuple[str, ...] = (),
    contexts: frozenset[Context] = frozenset(),
) -> Signature:
    """One raw hex digest of ``length`` characters."""
    return Signature(
        name=name,
        category=Category.RAW,
        tier=tier,
        length=length,
        charset=Charset.HEX,
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


def _haval(bits: int, popularity: float, example: str, first_mode: int, john: str | None = None):
    notes = [_HAVAL_PASSES.format(first_mode, first_mode + 1, first_mode + 2)]
    if john == "haval-128-4":
        notes.append("John's haval-128-4 format covers the 4 pass variant only.")
    if john == "haval-256-3":
        notes.append("John's haval-256-3 format covers the 3 pass variant only.")
    return _raw(
        f"HAVAL-{bits}",
        bits // 4,
        _L,
        popularity,
        example,
        strength=_WEAK,
        note=_LEGACY,
        hashcat=first_mode,
        john=john,
        notes=tuple(notes),
    )


# --- 16 hex characters --------------------------------------------------------

MD5_HALF = _raw(
    "MD5(Half)",
    16,
    _P,
    40,
    "8743b52063cd8409",
    summary="first 16 characters of an MD5",
    strength=_WEAK,
    note="Half of an unsalted MD5: just as fast to attack as the full digest.",
    hashcat=5100,
)

MD5_MIDDLE = _raw(
    "MD5(Middle)",
    16,
    _L,
    20,
    "63cd84097a65d163",
    summary="characters 9 to 24 of an MD5",
    strength=_WEAK,
    note="Half of an unsalted MD5: just as fast to attack as the full digest.",
)

# --- 32 hex characters --------------------------------------------------------

MD5 = _raw(
    "MD5",
    32,
    _P,
    100,
    "8743b52063cd84097a65d1633f5c74f5",
    strength=_WEAK,
    note="Fast and unsalted: GPUs test billions of guesses per second.",
    hashcat=0,
    john="raw-md5",
    contexts=WEB_DB,
)

NTLM = _raw(
    "NTLM",
    32,
    _P,
    60,
    "b4b9b02e6f09a9bd760f388b67351e2b",
    strength=_WEAK,
    note="Unsalted MD4 of the password: even faster to crack than MD5.",
    hashcat=1000,
    john="nt",
    contexts=frozenset({Context.WINDOWS}),
)

# The LM hash of "hashcat": Hashcat's mode 3000 example (one 16-character
# half), then the well-known half for an empty second part, since the
# password is no longer than 7 characters.
LM = _raw(
    "LM",
    32,
    _L,
    40,
    "299bd128c1101fd6aad3b435b51404ee",
    summary="LAN Manager",
    strength=_WEAK,
    note="Uppercased and split into two 7-character DES halves: cracked in seconds.",
    hashcat=3000,
    john="lm",
    contexts=frozenset({Context.WINDOWS}),
)

MD4 = _raw(
    "MD4",
    32,
    _L,
    35,
    "afe04867ec7a3845145579a95f72eca7",
    strength=_WEAK,
    note="Broken, fast and unsalted.",
    hashcat=900,
    john="raw-md4",
)

RIPEMD128 = _raw(
    "RIPEMD-128",
    32,
    _L,
    20,
    "c79c5eefc7c8e629c12aa936f1bda9a9",
    strength=_WEAK,
    note=_LEGACY,
    hashcat=40086,
    john="ripemd-128",
)

MD2 = _raw(
    "MD2",
    32,
    _L,
    15,
    "742fd7197420380cf5bb80b9c85a117d",
    strength=_WEAK,
    note=_LEGACY,
    hashcat=40084,
    john="md2",
)

HAVAL128 = _haval(128, 15, "7bdb3946de69fa2bbd719b97f4472b4c", 40102, john="haval-128-4")

TIGER128 = _raw(
    "Tiger-128",
    32,
    _L,
    15,
    "6e2d24e09a70a02bdd9c4885ea199b06",
    summary="Tiger-192 cut to 128 bits",
    strength=_MODERATE,
    note=_SOUND,
    hashcat=40090,
)

SNEFRU128 = _raw(
    "Snefru-128",
    32,
    _L,
    10,
    "ba1d02bbc8eb20ace9162b1653da8483",
    strength=_WEAK,
    note=_LEGACY,
    hashcat=40094,
    john="snefru-128",
)

# --- 40 hex characters --------------------------------------------------------

SHA1 = _raw(
    "SHA-1",
    40,
    _P,
    80,
    "b89eaac7e61417341b710b727768294d0e6a277b",
    strength=_WEAK,
    note="Fast and unsalted, and collision-broken since 2017.",
    hashcat=100,
    john="raw-sha1",
    contexts=WEB_DB,
)

RIPEMD160 = _raw(
    "RIPEMD-160",
    40,
    _L,
    40,
    "012cb9b334ec1aeb71a9c8ce85586082467f7eb6",
    strength=_MODERATE,
    note=_SOUND,
    hashcat=6000,
    john="ripemd-160",
)

TIGER160 = _raw(
    "Tiger-160",
    40,
    _L,
    15,
    "6e2d24e09a70a02bdd9c4885ea199b0649821304",
    summary="Tiger-192 cut to 160 bits",
    strength=_MODERATE,
    note=_SOUND,
    hashcat=40091,
)

HAVAL160 = _haval(160, 15, "7e7e7fe1c80992a5183138e3948e4424c4121e6a", 40105)

# --- 48 hex characters --------------------------------------------------------

TIGER192 = _raw(
    "Tiger-192",
    48,
    _P,
    40,
    "6e2d24e09a70a02bdd9c4885ea199b064982130432331b44",
    strength=_MODERATE,
    note=_SOUND,
    hashcat=40089,
    john="tiger",
)

HAVAL192 = _haval(192, 15, "5d97366a5be117a571a6e0541397c2e3d051aab557a224b0", 40108)

# --- 56 hex characters --------------------------------------------------------

SHA224 = _raw(
    "SHA-224",
    56,
    _P,
    40,
    "e4fa1555ad877bf0ec455483371867200eee89550a93eff2f95a6198",
    strength=_MODERATE,
    note=_SHA2,
    hashcat=1300,
    john="raw-sha224",
    contexts=WEB_DB,
)

SHA3_224 = _raw(
    "SHA3-224",
    56,
    _P,
    20,
    "412ef78534ba6ab0e9b1607d3e9767a25c1ea9d5e83176b4c2817a6c",
    strength=_MODERATE,
    note=_SOUND,
    hashcat=17300,
)

HAVAL224 = _haval(224, 10, "fa9f54ea58a54f14bc9592e27b8aea42f21e3851a3d724be32e5813d", 40111)

# --- 64 hex characters --------------------------------------------------------

SHA256 = _raw(
    "SHA-256",
    64,
    _P,
    80,
    "127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935",
    strength=_MODERATE,
    note=_SHA2,
    hashcat=1400,
    john="raw-sha256",
    contexts=WEB_DB,
)

SHA3_256 = _raw(
    "SHA3-256",
    64,
    _P,
    40,
    "d60fcf6585da4e17224f58858970f0ed5ab042c3916b76b0b828e62eaf636cbd",
    strength=_MODERATE,
    note=_SOUND,
    hashcat=17400,
)

BLAKE2S = _raw(
    "BLAKE2s-256",
    64,
    _L,
    30,
    "2c719b484789ad5f6fc1739012182169b25484af156adc91d4f64f72400e574a",
    strength=_MODERATE,
    note=_SOUND,
    hashcat=31000,
    notes=(_BLAKE2_PREFIX,),
)

GOST94 = _raw(
    "GOST R 34.11-94",
    64,
    _L,
    20,
    "df226c2c6dcb1d995c0299a33a084b201544293c31fc3d279530121d36bbcea9",
    strength=_WEAK,
    note=_LEGACY,
    hashcat=6900,
    john="gost",
)

RIPEMD256 = _raw(
    "RIPEMD-256",
    64,
    _L,
    15,
    "33d5166e2930db590e82d3a855564acc526568c39679d778844ebf9b5be75738",
    strength=_MODERATE,
    note=_SOUND,
    hashcat=40087,
)

HAVAL256 = _haval(
    256,
    15,
    "9ddb8d41435015df7caf22cbe436f512f90008a119fb7836c79af30a15e61e37",
    40114,
    john="haval-256-3",
)

SNEFRU256 = _raw(
    "Snefru-256",
    64,
    _L,
    10,
    "7f224f9a530d90acae8c051c87e9f2dfd60232c6529aee3aec16e0578d625f7e",
    strength=_WEAK,
    note=_LEGACY,
    hashcat=40095,
    john="snefru-256",
)

# --- 80 hex characters --------------------------------------------------------

RIPEMD320 = _raw(
    "RIPEMD-320",
    80,
    _P,
    20,
    "8339009b816d4e4c2a6be3c6e1daac6aca69a7670ecdc583adfca0db17cc8f08ce35d6c759b038ab",
    strength=_MODERATE,
    note=_SOUND,
    hashcat=33600,
)

# --- 96 hex characters --------------------------------------------------------

SHA384 = _raw(
    "SHA-384",
    96,
    _P,
    60,
    (
        "07371af1ca1fca7c6941d2399f3610f1e392c56c6d73fddf"
        "fe38f18c430a2817028dae1ef09ac683b62148a2c8757f42"
    ),
    strength=_MODERATE,
    note=_SHA2,
    hashcat=10800,
    john="raw-sha384",
    contexts=WEB_DB,
)

SHA3_384 = _raw(
    "SHA3-384",
    96,
    _P,
    20,
    (
        "983ba28532cc6320d04f20fa485bcedb38bddb666eca5f1e"
        "5aa279ff1c6244fe5f83cf4bbf05b95ff378dd2353617221"
    ),
    strength=_MODERATE,
    note=_SOUND,
    hashcat=17500,
)

# --- 128 hex characters -------------------------------------------------------

SHA512 = _raw(
    "SHA-512",
    128,
    _P,
    60,
    (
        "82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e291"
        "34d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f"
    ),
    strength=_MODERATE,
    note=_SHA2,
    hashcat=1700,
    john="raw-sha512",
    contexts=WEB_DB,
)

SHA3_512 = _raw(
    "SHA3-512",
    128,
    _P,
    30,
    (
        "7c2dc1d743735d4e069f3bda85b1b7e9172033dfdd8cd599ca094ef8570f3930"
        "c3f2c0b7afc8d6152ce4eaad6057a2ff22e71934b3a3dd0fb55a7fc84a53144e"
    ),
    strength=_MODERATE,
    note=_SOUND,
    hashcat=17600,
    john="raw-sha3",
)

BLAKE2B = _raw(
    "BLAKE2b-512",
    128,
    _L,
    30,
    (
        "296c269e70ac5f0095e6fb47693480f0f7b97ccd0307f5c3bfa4df8f5ca5c930"
        "8a0e7108e80a0a9c0ebb715e8b7109b072046c6cd5e155b4cfd2f27216283b1e"
    ),
    strength=_MODERATE,
    note=_SOUND,
    hashcat=600,
    john="raw-blake2",
    notes=(_BLAKE2_PREFIX,),
)

WHIRLPOOL = _raw(
    "Whirlpool",
    128,
    _L,
    25,
    (
        "7ca8eaaaa15eaa4c038b4c47b9313e92da827c06940e69947f85bc0fbef3eb8f"
        "d254da220ad9e208b6b28f6bb9be31dd760f1fdb26112d83f87d96b416a4d258"
    ),
    strength=_MODERATE,
    note=_SOUND,
    hashcat=6100,
    john="whirlpool",
)

# --- More digests that share the lengths above ---------------------------------

SHA512_224 = _raw(
    "SHA-512/224",
    56,
    _L,
    12,
    "6e8f8ef6b20f7ad1a75f5bac75585b5a98b890013d317a9b45f477d1",
    summary="SHA-512 cut to 224 bits",
    strength=_MODERATE,
    note=_SHA2,
)

SHA512_256 = _raw(
    "SHA-512/256",
    64,
    _L,
    15,
    "7bf80da439438473433145774c02ca78960b4135d5d4eb52c656cda2cb45010f",
    summary="SHA-512 cut to 256 bits",
    strength=_MODERATE,
    note=_SHA2,
)

# Keccak as submitted to the SHA-3 competition; the standard changed the
# padding, so its digests differ from SHA3-*.
KECCAK224 = _raw(
    "Keccak-224",
    56,
    _L,
    15,
    "e1dfad9bafeae6ef15f5bbb16cf4c26f09f5f1e7870581962fc84636",
    strength=_MODERATE,
    note=_SOUND,
    hashcat=17700,
)

KECCAK256 = _raw(
    "Keccak-256",
    64,
    _L,
    28,
    "203f88777f18bb4ee1226627b547808f38d90d3e106262b5de9ca943b57137b6",
    summary="pre-standard SHA-3, used by Ethereum",
    strength=_MODERATE,
    note=_SOUND,
    hashcat=17800,
    john="raw-keccak-256",
)

KECCAK384 = _raw(
    "Keccak-384",
    96,
    _L,
    15,
    (
        "5804b7ada5806ba79540100e9a7ef493654ff2a21d94d4f2"
        "ce4bf69abda5d94bf03701fe9525a15dfdc625bfbd769701"
    ),
    strength=_MODERATE,
    note=_SOUND,
    hashcat=17900,
)

KECCAK512 = _raw(
    "Keccak-512",
    128,
    _L,
    20,
    (
        "2fbf5c9080f0a704de2e915ba8fdae6ab00bbc026b2c1c8fa07da1239381c6b7"
        "f4dfd399bf9652500da723694a4c719587dd0219cb30eabe61210a8ae4dc0b03"
    ),
    strength=_MODERATE,
    note=_SOUND,
    hashcat=18000,
    john="raw-keccak",
)

SM3 = _raw(
    "SM3",
    64,
    _L,
    12,
    "51227e48ea74827b77fc142c3ec21d25cc42c794e6ac422825cd47ad4ac7913d",
    summary="Chinese national standard",
    strength=_MODERATE,
    note=_SOUND,
    hashcat=31100,
    john="raw-sm3",
)

STREEBOG256 = _raw(
    "Streebog-256",
    64,
    _L,
    12,
    "57e9e50caec93d72e9498c211d6dc4f4d328248b48ecf46ba7abfa874f666e36",
    summary="GOST R 34.11-2012",
    strength=_MODERATE,
    note=_SOUND,
    hashcat=11700,
    john="stribog-256",
)

STREEBOG512 = _raw(
    "Streebog-512",
    128,
    _L,
    15,
    (
        "5d5bdba48c8f89ee6c0a0e11023540424283e84902de08013aeeb626e819950b"
        "b32842903593a1d2e8f71897ff7fe72e17ac9ba8ce1d1d2f7e9c4359ea63bdc3"
    ),
    summary="GOST R 34.11-2012",
    strength=_MODERATE,
    note=_SOUND,
    hashcat=11800,
    john="stribog-512",
)

# --- Digests written in base64 instead of hex ----------------------------------
# The padding gives the digest size away: 22 characters and "==" are 16
# bytes, 27 and "=" are 20, 43 and "=" are 32.

_BASE64 = Charset.BASE64.char_class


def _base64(name: str, characters: int, padding: str, example: str, strength: Strength, note: str):
    return Signature(
        name=name,
        category=Category.RAW,
        tier=_P,
        pattern=rf"{_BASE64}{{{characters}}}{padding}",
        length=characters + len(padding),
        charset=Charset.BASE64,
        summary="the raw digest in base64",
        strength=strength,
        strength_note=note,
        example=example,
        popularity=40,
    )


MD5_BASE64 = _base64(
    "MD5 (Base64)",
    22,
    "==",
    "h0O1IGPNhAl6ZdFjP1x09Q==",
    _WEAK,
    "Fast and unsalted: GPUs test billions of guesses per second.",
)

SHA1_BASE64 = _base64(
    "SHA-1 (Base64)",
    27,
    "=",
    "uJ6qx+YUFzQbcQtyd2gpTQ5qJ3s=",
    _WEAK,
    "Fast and unsalted, and collision-broken since 2017.",
)

SHA256_BASE64 = _base64(
    "SHA-256 (Base64)",
    43,
    "=",
    "En5vv+JKdQ5ykwwiCo4TgnVla45dj0ipjDyS3yyrqTU=",
    _MODERATE,
    _SHA2,
)

SIGNATURES: tuple[Signature, ...] = (
    MD5,
    NTLM,
    SHA1,
    SHA224,
    SHA256,
    SHA512,
    MD5_HALF,
    MD5_MIDDLE,
    LM,
    MD4,
    RIPEMD128,
    MD2,
    HAVAL128,
    TIGER128,
    SNEFRU128,
    RIPEMD160,
    TIGER160,
    HAVAL160,
    TIGER192,
    HAVAL192,
    SHA3_224,
    HAVAL224,
    SHA3_256,
    BLAKE2S,
    GOST94,
    RIPEMD256,
    HAVAL256,
    SNEFRU256,
    RIPEMD320,
    SHA384,
    SHA3_384,
    SHA3_512,
    BLAKE2B,
    WHIRLPOOL,
    SHA512_224,
    SHA512_256,
    KECCAK224,
    KECCAK256,
    KECCAK384,
    KECCAK512,
    SM3,
    STREEBOG256,
    STREEBOG512,
    MD5_BASE64,
    SHA1_BASE64,
    SHA256_BASE64,
)
