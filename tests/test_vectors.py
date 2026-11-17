"""A known test vector for every format, and the tier it must land in.

Every signature's ``example`` is accounted for in ``VECTORS`` below, with
where the value comes from:

* ``Computed``: recomputed here from the plaintext "hashcat", with hashlib,
  zlib or one of the small reference implementations in this file.
* ``Published``: copied from a published example and not recomputed, because
  the algorithm is not in the standard library. The source is named.
* ``ShapeOnly``: no verified vector exists. The example only has the right
  shape; detection of these formats rests on length and charset alone.

For each vector the test also checks that identifying it lists the format in
the expected tier.
"""

import binascii
import hashlib
import struct
import zlib
from collections.abc import Callable
from dataclasses import dataclass

import pytest

from hashident.engine import identify
from hashident.models import Tier
from hashident.signatures import SIGNATURES, get_signature

PASSWORD = b"hashcat"

HASHCAT = "hashcat example hashes (plaintext: hashcat)"

P = Tier.POSSIBLE
L = Tier.LEAST_POSSIBLE


# --- Reference implementations --------------------------------------------------------


def md4(data: bytes) -> str:
    """MD4 (RFC 1320). hashlib only has it when OpenSSL's legacy provider is on."""
    mask = 0xFFFFFFFF

    def rol(value: int, count: int) -> int:
        return ((value << count) | (value >> (32 - count))) & mask

    message = data + b"\x80" + b"\x00" * ((55 - len(data)) % 64)
    message += struct.pack("<Q", len(data) * 8)
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    round3_order = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
    for offset in range(0, len(message), 64):
        x = struct.unpack("<16I", message[offset : offset + 64])
        start = (a, b, c, d)
        for i in range(16):
            mixed = (b & c) | (~b & d)
            step = rol((a + mixed + x[i]) & mask, (3, 7, 11, 19)[i % 4])
            a, b, c, d = d, step, b, c
        for i in range(16):
            mixed = (b & c) | (b & d) | (c & d)
            word = x[(i % 4) * 4 + i // 4]
            step = rol((a + mixed + word + 0x5A827999) & mask, (3, 5, 9, 13)[i % 4])
            a, b, c, d = d, step, b, c
        for i in range(16):
            mixed = b ^ c ^ d
            word = x[round3_order[i]]
            step = rol((a + mixed + word + 0x6ED9EBA1) & mask, (3, 9, 11, 15)[i % 4])
            a, b, c, d = d, step, b, c
        a, b, c, d = ((value + old) & mask for value, old in zip((a, b, c, d), start))
    return struct.pack("<4I", a, b, c, d).hex()


def crc(
    data: bytes, *, width: int, poly: int, init: int, reflect: bool, xorout: int
) -> str:
    """A bit-by-bit CRC in the Rocksoft model, as lowercase hex."""

    def mirrored(value: int, bits: int) -> int:
        return int(f"{value:0{bits}b}"[::-1], 2)

    top, mask = 1 << (width - 1), (1 << width) - 1
    register = init
    for byte in data:
        register ^= (mirrored(byte, 8) if reflect else byte) << (width - 8)
        for _ in range(8):
            register = ((register << 1) ^ poly) if register & top else register << 1
            register &= mask
    if reflect:
        register = mirrored(register, width)
    return f"{register ^ xorout:0{width // 4}x}"


CRC16_ARC = dict(width=16, poly=0x8005, init=0x0000, reflect=True, xorout=0x0000)
CRC16_CCITT_FALSE = dict(width=16, poly=0x1021, init=0xFFFF, reflect=False, xorout=0x0000)
CRC16_X25 = dict(width=16, poly=0x1021, init=0xFFFF, reflect=True, xorout=0xFFFF)
CRC32_BZIP2 = dict(width=32, poly=0x04C11DB7, init=0xFFFFFFFF, reflect=False, xorout=0xFFFFFFFF)
CRC32_ZLIB = dict(width=32, poly=0x04C11DB7, init=0xFFFFFFFF, reflect=True, xorout=0xFFFFFFFF)


def test_md4_reference_matches_rfc_1320():
    assert md4(b"") == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert md4(b"abc") == "a448017aaf21d8525fc10ae87aa6729d"
    assert md4(b"1234567890" * 8) == "e33b4ddc9c38f2199c3e7b164fcc0536"


@pytest.mark.parametrize(
    ("model", "check"),
    [
        (CRC16_ARC, "bb3d"),
        (CRC16_CCITT_FALSE, "29b1"),
        (CRC16_X25, "906e"),
        (CRC32_BZIP2, "fc891918"),
        (CRC32_ZLIB, "cbf43926"),
    ],
    ids=["arc", "ccitt-false", "x25", "bzip2", "zlib"],
)
def test_crc_reference_matches_the_catalogue_check_values(model, check):
    # The check value of a CRC is its result for the ASCII digits 1 to 9.
    assert crc(b"123456789", **model) == check


def test_crc_reference_agrees_with_the_standard_library():
    assert crc(PASSWORD, **CRC32_ZLIB) == f"{zlib.crc32(PASSWORD):08x}"
    assert crc(PASSWORD, **CRC16_CCITT_FALSE) == f"{binascii.crc_hqx(PASSWORD, 0xFFFF):04x}"


# --- The vector table -----------------------------------------------------------------


@dataclass(frozen=True)
class Computed:
    compute: Callable[[], str]


@dataclass(frozen=True)
class Published:
    source: str


@dataclass(frozen=True)
class ShapeOnly:
    why: str


def digest(algorithm: str, data: bytes = PASSWORD) -> Computed:
    return Computed(lambda: hashlib.new(algorithm, data).hexdigest())


def _md5() -> str:
    return hashlib.md5(PASSWORD).hexdigest()


UNDOCUMENTED = "listed by classic hash identifiers, but no specification or vector was found"

# name -> (expected tier, where the example comes from)
VECTORS: dict[str, tuple[Tier, Computed | Published | ShapeOnly]] = {
    # Checksums
    "CRC-16": (P, Computed(lambda: crc(PASSWORD, **CRC16_ARC))),
    "CRC-16-CCITT": (P, Computed(lambda: f"{binascii.crc_hqx(PASSWORD, 0xFFFF):04x}")),
    "FCS-16": (L, Computed(lambda: crc(PASSWORD, **CRC16_X25))),
    "CRC-32B": (P, Computed(lambda: f"{zlib.crc32(PASSWORD):08x}")),
    "CRC-32": (P, Computed(lambda: crc(PASSWORD, **CRC32_BZIP2))),
    "Adler-32": (P, Computed(lambda: f"{zlib.adler32(PASSWORD):08x}")),
    "GHash-32-3": (L, ShapeOnly(UNDOCUMENTED)),
    "GHash-32-5": (L, ShapeOnly(UNDOCUMENTED)),
    "XOR-32": (L, ShapeOnly(UNDOCUMENTED)),
    # Raw digests
    "MD5(Half)": (P, Computed(lambda: _md5()[:16])),
    "MD5(Middle)": (L, Computed(lambda: _md5()[8:24])),
    "MD5": (P, digest("md5")),
    "NTLM": (P, Computed(lambda: md4(PASSWORD.decode().encode("utf-16-le")))),
    "LM": (L, Published(f"{HASHCAT}, mode 3000, plus the LM hash of an empty second half")),
    "MD4": (L, Computed(lambda: md4(PASSWORD))),
    "MD2": (L, Published(f"{HASHCAT}, mode 40084")),
    "RIPEMD-128": (L, Published(f"{HASHCAT}, mode 40086")),
    "HAVAL-128": (L, Published(f"{HASHCAT}, mode 40102 (3 passes)")),
    "Tiger-128": (L, Published(f"{HASHCAT}, mode 40090")),
    "Snefru-128": (L, Published(f"{HASHCAT}, mode 40094")),
    "SHA-1": (P, digest("sha1")),
    "RIPEMD-160": (L, Published(f"{HASHCAT}, mode 6000")),
    "Tiger-160": (L, Published(f"{HASHCAT}, mode 40091")),
    "HAVAL-160": (L, Published(f"{HASHCAT}, mode 40105 (3 passes)")),
    "Tiger-192": (P, Published(f"{HASHCAT}, mode 40089")),
    "HAVAL-192": (L, Published(f"{HASHCAT}, mode 40108 (3 passes)")),
    "SHA-224": (P, digest("sha224")),
    "SHA3-224": (P, digest("sha3_224")),
    "HAVAL-224": (L, Published(f"{HASHCAT}, mode 40111 (3 passes)")),
    "SHA-256": (P, digest("sha256")),
    "SHA3-256": (P, digest("sha3_256")),
    "BLAKE2s-256": (L, digest("blake2s")),
    "GOST R 34.11-94": (L, Published(f"{HASHCAT}, mode 6900")),
    "RIPEMD-256": (L, Published(f"{HASHCAT}, mode 40087")),
    "HAVAL-256": (L, Published(f"{HASHCAT}, mode 40114 (3 passes)")),
    "Snefru-256": (L, Published(f"{HASHCAT}, mode 40095")),
    "RIPEMD-320": (P, Published(f"{HASHCAT}, mode 33600")),
    "SHA-384": (P, digest("sha384")),
    "SHA3-384": (P, digest("sha3_384")),
    "SHA-512": (P, digest("sha512")),
    "SHA3-512": (P, digest("sha3_512")),
    "BLAKE2b-512": (L, digest("blake2b")),
    "Whirlpool": (L, Published(f"{HASHCAT}, mode 6100")),
    # Application formats
    "MySQL 4.1+": (
        P,
        Computed(
            lambda: "*" + hashlib.sha1(hashlib.sha1(PASSWORD).digest()).hexdigest().upper()
        ),
    ),
    # crypt(3) formats
    "md5crypt": (P, Published(f"{HASHCAT}, mode 500")),
    "sha512crypt": (P, Published(f"{HASHCAT}, mode 1800")),
    "bcrypt": (P, Published(f"{HASHCAT}, mode 3200")),
}


def _of_kind(kind: type) -> list[str]:
    return [name for name, (_, origin) in VECTORS.items() if isinstance(origin, kind)]


def test_every_signature_has_a_vector_and_nothing_else_does():
    assert sorted(VECTORS) == sorted(sig.name for sig in SIGNATURES)


@pytest.mark.parametrize("name", _of_kind(Computed))
def test_computed_example_is_the_hash_of_hashcat(name):
    origin = VECTORS[name][1]

    assert get_signature(name).example == origin.compute()


def test_ripemd160_example_is_the_hash_of_hashcat():
    # Published, but checked too where this Python's OpenSSL still has RIPEMD-160.
    if "ripemd160" not in hashlib.algorithms_available:
        pytest.skip("this Python's OpenSSL has no RIPEMD-160")

    assert get_signature("RIPEMD-160").example == hashlib.new("ripemd160", PASSWORD).hexdigest()


def test_truncated_tiger_examples_are_prefixes_of_tiger_192():
    full = get_signature("Tiger-192").example

    assert get_signature("Tiger-160").example == full[:40]
    assert get_signature("Tiger-128").example == full[:32]


@pytest.mark.parametrize("name", list(VECTORS))
def test_vector_lands_in_the_expected_tier(name):
    expected_tier = VECTORS[name][0]
    sig = get_signature(name)

    found = {cand.signature.name: cand.tier for cand in identify(sig.example).candidates}

    assert name in found, f"{name} did not match its own example"
    assert found[name] is expected_tier


@pytest.mark.parametrize("name", list(VECTORS))
def test_registry_tier_agrees_with_the_expected_tier(name):
    # A prefix match is always "possible", so the check above cannot see a
    # wrong tier on a prefixed format; this one can.
    assert get_signature(name).tier is VECTORS[name][0]
