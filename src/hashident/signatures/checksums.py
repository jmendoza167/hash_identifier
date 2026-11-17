"""Checksums: error-detecting codes, not cryptographic hashes.

They are here because short hex strings turn up next to real hashes and are
worth naming. Every view labels them as checksums. That includes FNV, a
hash-table hash, which is no more a password hash than a CRC is. With 4, 8
or 16 hex characters there is nothing but the length to go on, so these are
always shape matches.
"""

from __future__ import annotations

from hashident.models import Category, Charset, Signature, Strength, Tier

_P, _L = Tier.POSSIBLE, Tier.LEAST_POSSIBLE

_NOTE = "A checksum, not a password hash: it only catches errors and is trivial to match."


def _checksum(
    name: str,
    length: int,
    tier: Tier,
    popularity: float,
    example: str,
    *,
    summary: str = "",
    hashcat: int | None = None,
    john: str | None = None,
    notes: tuple[str, ...] = (),
) -> Signature:
    """One checksum written as ``length`` hex characters."""
    return Signature(
        name=name,
        category=Category.CHECKSUM,
        tier=tier,
        length=length,
        charset=Charset.HEX,
        summary=summary,
        strength=Strength.WEAK,
        strength_note=_NOTE,
        example=example,
        hashcat_mode=hashcat,
        john_format=john,
        notes=notes,
        popularity=popularity,
    )


# --- 4 hex characters ---------------------------------------------------------

CRC16 = _checksum("CRC-16", 4, _P, 60, "b521", summary="CRC-16/ARC")

CRC16_CCITT = _checksum("CRC-16-CCITT", 4, _P, 50, "20b7", summary="CRC-16/CCITT-FALSE")

FCS16 = _checksum("FCS-16", 4, _L, 20, "a287", summary="CRC-16/X-25, used by PPP")

# --- 8 hex characters ---------------------------------------------------------

# Hashcat and John both crack the zlib CRC-32, and both want a second field:
# the CRC to start from, which is zero for a plain checksum.
CRC32B = _checksum(
    "CRC-32B",
    8,
    _P,
    80,
    "c762de4a",
    summary="zlib, PNG, PHP crc32b",
    hashcat=11500,
    john="crc32",
    notes=(
        "For hashcat, add ':00000000' after the checksum (mode 11500 expects hash:salt).",
        "For john, write it as '$crc32$00000000.' followed by the checksum.",
    ),
)

CRC32 = _checksum("CRC-32", 8, _P, 60, "62e08f6a", summary="CRC-32/BZIP2")

ADLER32 = _checksum("Adler-32", 8, _P, 40, "0b6302dd", summary="zlib")

# The next three are listed by classic hash identifiers, but no specification
# or test vector for them could be found. Their examples are placeholders
# with the right shape, not verified values.
GHASH32_3 = _checksum("GHash-32-3", 8, _L, 10, "6a2b1c0d")

GHASH32_5 = _checksum("GHash-32-5", 8, _L, 10, "9e3f7a15")

XOR32 = _checksum("XOR-32", 8, _L, 10, "0000003f")

FNV32 = _checksum("FNV-32", 8, _L, 8, "bec89813", summary="FNV-1 or FNV-1a")

# --- 16 hex characters --------------------------------------------------------

CRC64 = _checksum(
    "CRC-64",
    16,
    _L,
    10,
    "b679f6ae9523df03",
    summary="ECMA-182, Jones",
    hashcat=28000,
    notes=(
        "Hashcat mode 28000 is the Jones variant (used by Redis) and wants ':' and "
        "the starting value after the checksum.",
    ),
)

FNV64 = _checksum("FNV-64", 16, _L, 8, "4e95d388486c8013", summary="FNV-1 or FNV-1a")

SIGNATURES: tuple[Signature, ...] = (
    CRC16,
    CRC16_CCITT,
    FCS16,
    CRC32B,
    CRC32,
    ADLER32,
    GHASH32_3,
    GHASH32_5,
    XOR32,
    FNV32,
    CRC64,
    FNV64,
)
