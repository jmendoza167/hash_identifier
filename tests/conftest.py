"""Fixtures shared by the test modules."""

import pytest

from hashident.models import Category, Charset, Signature, Strength, Tier
from hashident.signatures import MD5, NTLM

RARE32 = Signature(
    name="Rare-128",
    category=Category.RAW,
    tier=Tier.LEAST_POSSIBLE,
    length=32,
    charset=Charset.HEX,
    strength=Strength.WEAK,
    strength_note="Made up for the tests.",
    example=MD5.example,
    hashcat_mode=99999,
    john_format="rare-128",
    popularity=20,
)


@pytest.fixture
def tiered_signatures() -> tuple[Signature, ...]:
    """MD5 and NTLM (possible) plus a made-up least-possible 32-hex format."""
    return (MD5, NTLM, RARE32)


@pytest.fixture
def tiered_cli(monkeypatch, tiered_signatures):
    """Make the command line identify hashes against ``tiered_signatures``."""
    import functools

    from hashident import cli
    from hashident.engine import identify

    monkeypatch.setattr(cli, "identify", functools.partial(identify, signatures=tiered_signatures))
