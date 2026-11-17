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

import base64
import binascii
import hashlib
import hmac
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


def mysql323(password: bytes) -> str:
    """MySQL's pre-4.1 PASSWORD(), also called OLD_PASSWORD()."""
    nr, add, nr2 = 1345345333, 7, 0x12345671
    for byte in password:
        if byte in b" \t":
            continue
        nr ^= ((((nr & 63) + add) * byte) + (nr << 8)) & 0xFFFFFFFF
        nr2 = (nr2 + ((nr2 << 8) ^ nr)) & 0xFFFFFFFF
        add += byte
    return f"{nr & 0x7FFFFFFF:08x}{nr2 & 0x7FFFFFFF:08x}"


def dcc(password: bytes, username: str) -> bytes:
    """Domain Cached Credentials: MD4(NT hash + lowercased UTF-16 username)."""
    nt_hash = bytes.fromhex(md4(password.decode().encode("utf-16-le")))
    return bytes.fromhex(md4(nt_hash + username.lower().encode("utf-16-le")))


def dcc2(password: bytes, username: str, rounds: int) -> str:
    salt = username.lower().encode("utf-16-le")
    return hashlib.pbkdf2_hmac("sha1", dcc(password, username), salt, rounds, 16).hex()


CISCO7_KEY = b"dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87"


def cisco7(password: bytes, seed: int) -> str:
    """Cisco type 7: a two-digit offset into a fixed key, then the XORed bytes."""
    body = "".join(
        f"{byte ^ CISCO7_KEY[(seed + i) % len(CISCO7_KEY)]:02X}" for i, byte in enumerate(password)
    )
    return f"{seed:02d}{body}"


def test_cisco7_reference_gives_the_well_known_encoding_of_cisco():
    assert cisco7(b"cisco", 8) == "0822455D0A16"


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


def _hex(algorithm: str, data: bytes = PASSWORD) -> bytes:
    """The lowercase hex digest as bytes, for hashing a hash."""
    return hashlib.new(algorithm, data).hexdigest().encode()


def salted(algorithm: str, salt: str, *, salt_first: bool = False) -> Computed:
    """``hash:salt`` for a salt joined to the password on either side."""
    data = salt.encode() + PASSWORD if salt_first else PASSWORD + salt.encode()
    return Computed(lambda: f"{hashlib.new(algorithm, data).hexdigest()}:{salt}")


def keyed(algorithm: str, salt: str, *, key_is_password: bool) -> Computed:
    """``hash:salt`` for an HMAC keyed with the password, or with the salt."""
    key, message = (PASSWORD, salt.encode()) if key_is_password else (salt.encode(), PASSWORD)
    return Computed(lambda: f"{hmac.new(key, message, algorithm).hexdigest()}:{salt}")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


JOHN = "John the Ripper test vector"


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
    # Salted and nested hashes
    "md5(md5($pass))": (L, Computed(lambda: hashlib.md5(_hex("md5")).hexdigest())),
    "md5(sha1($pass))": (L, Computed(lambda: hashlib.md5(_hex("sha1")).hexdigest())),
    "md5($pass.$salt)": (P, salted("md5", "7050461")),
    "md5($salt.$pass)": (P, salted("md5", "4225637426", salt_first=True)),
    "md5($salt.md5($pass))": (
        L,
        Computed(lambda: hashlib.md5(b"1234" + _hex("md5")).hexdigest() + ":1234"),
    ),
    "HMAC-MD5 (key = $pass)": (L, keyed("md5", "1234", key_is_password=True)),
    "HMAC-MD5 (key = $salt)": (L, keyed("md5", "1234", key_is_password=False)),
    "sha1(sha1($pass))": (L, Computed(lambda: hashlib.sha1(_hex("sha1")).hexdigest())),
    "sha1(md5($pass))": (L, Computed(lambda: hashlib.sha1(_hex("md5")).hexdigest())),
    "sha1($pass.$salt)": (P, salted("sha1", "2014")),
    "sha1($salt.$pass)": (P, salted("sha1", "5363620024", salt_first=True)),
    "HMAC-SHA1 (key = $pass)": (L, keyed("sha1", "1234", key_is_password=True)),
    "HMAC-SHA1 (key = $salt)": (L, keyed("sha1", "1234", key_is_password=False)),
    "sha256($pass.$salt)": (P, salted("sha256", "53743528")),
    "sha256($salt.$pass)": (P, salted("sha256", "560407001617", salt_first=True)),
    "HMAC-SHA256 (key = $pass)": (L, keyed("sha256", "1234", key_is_password=True)),
    "HMAC-SHA256 (key = $salt)": (L, keyed("sha256", "1234", key_is_password=False)),
    "sha512($pass.$salt)": (P, salted("sha512", "6352283260")),
    "sha512($salt.$pass)": (P, salted("sha512", "2613516180127", salt_first=True)),
    "HMAC-SHA512 (key = $pass)": (L, keyed("sha512", "1234", key_is_password=True)),
    "HMAC-SHA512 (key = $salt)": (L, keyed("sha512", "1234", key_is_password=False)),
    # Application formats
    "MySQL323": (P, Computed(lambda: mysql323(PASSWORD))),
    "WordPress (phpass)": (P, Published(f"{HASHCAT}, mode 400")),
    "phpBB3 (phpass)": (P, Published(f"{HASHCAT}, mode 400")),
    "MD5(HMAC(Wordpress))": (L, ShapeOnly(UNDOCUMENTED)),
    "Joomla": (P, salted("md5", "54718031842521651757785603028777")),
    "Django SHA-1": (
        P,
        Computed(lambda: "sha1$fe76b$" + hashlib.sha1(b"fe76b" + PASSWORD).hexdigest()),
    ),
    "Django SHA-256": (
        P,
        Computed(lambda: "sha256$fe76b$" + hashlib.sha256(b"fe76b" + PASSWORD).hexdigest()),
    ),
    "Django SHA-384": (
        P,
        Computed(lambda: "sha384$fe76b$" + hashlib.sha384(b"fe76b" + PASSWORD).hexdigest()),
    ),
    "Django PBKDF2-SHA256": (
        P,
        Computed(
            lambda: "pbkdf2_sha256$20000$H0dPx8NeajVu$"
            + _b64(hashlib.pbkdf2_hmac("sha256", PASSWORD, b"H0dPx8NeajVu", 20000))
        ),
    ),
    "SAM (LM:NT)": (
        P,
        Computed(
            lambda: get_signature("LM").example
            + ":"
            + md4(PASSWORD.decode().encode("utf-16-le"))
        ),
    ),
    "Domain Cached Credentials": (
        P,
        Computed(lambda: dcc(PASSWORD, "3060147285011").hex() + ":3060147285011"),
    ),
    "Domain Cached Credentials 2": (
        P,
        Computed(lambda: "$DCC2$10240#tom#" + dcc2(PASSWORD, "tom", 10240)),
    ),
    "RAdmin v2.x": (L, Computed(lambda: hashlib.md5(PASSWORD.ljust(100, b"\0")).hexdigest())),
    "Lineage II C4": (L, ShapeOnly(UNDOCUMENTED)),
    "SHA-1(MaNGOS)": (L, Computed(lambda: hashlib.sha1(b"HASHCAT:HASHCAT").hexdigest())),
    "pwdump": (
        P,
        Computed(
            lambda: "Administrator:500:"
            + get_signature("LM").example
            + ":"
            + md4(PASSWORD.decode().encode("utf-16-le"))
            + ":::"
        ),
    ),
    # Databases
    "MSSQL 2000": (P, Published(f"{HASHCAT}, mode 131")),
    "MSSQL 2005": (P, Published(f"{HASHCAT}, mode 132")),
    "MSSQL 2012": (P, Published(f"{HASHCAT}, mode 1731")),
    "Oracle 11g": (
        P,
        Computed(
            lambda: "S:"
            + hashlib.sha1(PASSWORD + bytes.fromhex("38445748184477378130")).hexdigest().upper()
            + "38445748184477378130"
        ),
    ),
    "Oracle 12c": (P, Published(f"{HASHCAT}, mode 12300, with Oracle's T: marker")),
    "PostgreSQL MD5": (
        P,
        Computed(lambda: "md5" + hashlib.md5(PASSWORD + b"postgres").hexdigest()),
    ),
    "PostgreSQL SCRAM-SHA-256": (P, Published(f"{HASHCAT}, mode 28600")),
    # Network devices and protocols
    "Cisco type 4": (P, Published(f"{HASHCAT}, mode 5700")),
    "Cisco type 7": (P, Computed(lambda: cisco7(PASSWORD, 8))),
    "Cisco type 8": (P, Published(f"{HASHCAT}, mode 9200")),
    "Cisco type 9": (P, Published(f"{HASHCAT}, mode 9300")),
    "Cisco-PIX MD5": (P, Published(f"{HASHCAT}, mode 2400")),
    "Cisco-ASA MD5": (P, Published(f"{HASHCAT}, mode 2410")),
    "NetNTLMv1": (P, Published(f"{HASHCAT}, mode 5500")),
    "NetNTLMv2": (P, Published(f"{HASHCAT}, mode 5600")),
    "Kerberos 5 TGS-REP etype 23": (P, Published(f"{HASHCAT}, mode 13100")),
    "Kerberos 5 TGS-REP AES": (P, Published(f"{HASHCAT}, mode 19700")),
    "Kerberos 5 AS-REP etype 23": (P, Published(f"{HASHCAT}, mode 18200")),
    "Kerberos 5 AS-REP AES": (P, Published(f"{HASHCAT}, mode 32200")),
    "Kerberos 5 Pre-Auth etype 23": (P, Published(f"{HASHCAT}, mode 7500")),
    "Kerberos 5 Pre-Auth AES": (P, Published(f"{HASHCAT}, mode 19900")),
    "WPA PMKID/EAPOL": (P, Published(f"{HASHCAT}, mode 22000")),
    "WPA PMKID (legacy)": (P, Published(f"{HASHCAT}, mode 16800")),
    "MySQL 4.1+": (
        P,
        Computed(
            lambda: "*" + hashlib.sha1(hashlib.sha1(PASSWORD).digest()).hexdigest().upper()
        ),
    ),
    # crypt(3) formats
    "md5crypt": (P, Published(f"{HASHCAT}, mode 500")),
    "MD5(APR)": (P, Published(f"{HASHCAT}, mode 1600")),
    "descrypt": (P, Published(f"{HASHCAT}, mode 1500")),
    "sha256crypt": (P, Published(f"{HASHCAT}, mode 7400")),
    "Argon2": (P, Published(f"{HASHCAT}, mode 34000")),
    "scrypt": (
        P,
        Computed(
            lambda: "SCRYPT:1024:1:1:MDIwMzMwNTQwNDQyNQ==:"
            + _b64(
                hashlib.scrypt(
                    PASSWORD,
                    salt=base64.b64decode("MDIwMzMwNTQwNDQyNQ=="),
                    n=1024,
                    r=1,
                    p=1,
                    dklen=32,
                )
            )
        ),
    ),
    "scrypt (Unix)": (P, Published(f"{JOHN}, scrypt format (plaintext: pleaseletmein)")),
    "yescrypt": (P, Published(f"{HASHCAT}, mode 36100")),
    "gost-yescrypt": (P, Published(f"{HASHCAT}, mode 36200")),
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
