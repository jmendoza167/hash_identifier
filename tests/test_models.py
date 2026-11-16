"""Tests for the core data structures."""

import dataclasses

import pytest

from hashident.models import (
    Candidate,
    Category,
    Charset,
    Confidence,
    Context,
    Result,
    Signature,
    Strength,
    Tier,
)

MD5_OF_PASSWORD = "5f4dcc3b5aa765d61d8327deb882cf99"


@pytest.fixture
def md5() -> Signature:
    return Signature(
        name="MD5",
        category=Category.RAW,
        tier=Tier.POSSIBLE,
        pattern=r"(?i)[0-9a-f]{32}",
        strength=Strength.WEAK,
        strength_note="Fast and unsalted; cracked at billions of guesses per second.",
        example=MD5_OF_PASSWORD,
        hashcat_mode=0,
        john_format="raw-md5",
        popularity=10.0,
        contexts=frozenset({Context.WEB, Context.DB}),
    )


def test_signature_matches_its_format(md5):
    assert md5.matches(MD5_OF_PASSWORD)
    assert md5.matches(MD5_OF_PASSWORD.upper())


@pytest.mark.parametrize(
    "value",
    [
        "",
        MD5_OF_PASSWORD[:-1],  # too short
        MD5_OF_PASSWORD + "0",  # too long
        "z" + MD5_OF_PASSWORD[1:],  # not hex
        f" {MD5_OF_PASSWORD} ",  # matches() does not strip; Result does
    ],
)
def test_signature_rejects_other_formats(md5, value):
    assert not md5.matches(value)


def test_signature_is_immutable(md5):
    with pytest.raises(dataclasses.FrozenInstanceError):
        md5.name = "SHA-1"


def test_signature_rejects_example_that_does_not_match_pattern():
    with pytest.raises(ValueError, match="example"):
        Signature(
            name="Broken",
            category=Category.RAW,
            tier=Tier.POSSIBLE,
            pattern=r"[0-9a-f]{32}",
            strength=Strength.WEAK,
            strength_note="n/a",
            example="not-a-hash",
        )


def test_result_with_no_candidates():
    result = Result(raw="  not a hash \n")

    assert result.raw == "  not a hash \n"
    assert result.normalized == "not a hash"
    assert result.candidates == ()
    assert result.best is None


def test_result_best_is_first_candidate(md5):
    top = Candidate(signature=md5, score=0.9, confidence=Confidence.HIGH, reasons=("32 hex chars",))
    other = Candidate(signature=md5, score=0.2, confidence=Confidence.LOW)

    assert Result(raw=MD5_OF_PASSWORD, candidates=(top, other)).best is top


# --- Shape metadata: length, charset, prefixes --------------------------------


def _shaped(**overrides) -> Signature:
    fields = dict(
        name="Shaped",
        category=Category.RAW,
        tier=Tier.LEAST_POSSIBLE,
        strength=Strength.WEAK,
        strength_note="n/a",
        example=MD5_OF_PASSWORD,
        length=32,
        charset=Charset.HEX,
    )
    fields.update(overrides)
    return Signature(**fields)


def test_pattern_is_derived_from_length_and_charset():
    sig = _shaped()

    assert sig.matches(MD5_OF_PASSWORD)
    assert sig.matches(MD5_OF_PASSWORD.upper())
    assert not sig.matches(MD5_OF_PASSWORD[:-1])
    assert not sig.matches("z" + MD5_OF_PASSWORD[1:])
    assert sig.pattern == "[0-9a-fA-F]{32}"


@pytest.mark.parametrize(
    ("charset", "example", "rejected"),
    [
        (Charset.HEX_LOWER, "0a1b2c3d", "0A1B2C3D"),
        (Charset.HEX_UPPER, "0A1B2C3D", "0a1b2c3d"),
        (Charset.BASE64, "aZ09+/aZ", "aZ09._aZ"),
        (Charset.CRYPT64, "aZ09./aZ", "aZ09+=aZ"),
    ],
)
def test_derived_pattern_is_limited_to_the_charset(charset, example, rejected):
    sig = _shaped(length=8, charset=charset, example=example)

    assert sig.matches(example)
    assert not sig.matches(rejected)


def test_explicit_pattern_wins_over_length_and_charset():
    sig = _shaped(pattern=r"x[0-9a-f]{31}", example="x" + MD5_OF_PASSWORD[1:])

    assert not sig.matches(MD5_OF_PASSWORD)


@pytest.mark.parametrize(
    "overrides",
    [{"length": None}, {"charset": Charset.MIXED}],
    ids=["no-length", "mixed-charset"],
)
def test_signature_needs_a_pattern_or_a_derivable_shape(overrides):
    with pytest.raises(ValueError, match="pattern"):
        _shaped(**overrides)


def test_signature_rejects_example_of_the_wrong_length():
    with pytest.raises(ValueError, match="length"):
        _shaped(pattern=r"[0-9a-f]+", length=40)


def test_signature_rejects_example_without_a_declared_prefix():
    with pytest.raises(ValueError, match="prefix"):
        _shaped(pattern=r"\*?[0-9a-f]{32}", length=None, prefixes=("*",))


def test_example_may_start_with_any_declared_prefix():
    sig = _shaped(
        pattern=r"\$2[ab]\$[0-9a-f]{4}",
        length=None,
        prefixes=("$2a$", "$2b$"),
        example="$2b$0a1b",
    )

    assert sig.prefixes == ("$2a$", "$2b$")
