"""Tests for the core data structures."""

import dataclasses

import pytest

from hashident.models import Candidate, Confidence, Context, Result, Signature, Strength

MD5_OF_PASSWORD = "5f4dcc3b5aa765d61d8327deb882cf99"


@pytest.fixture
def md5() -> Signature:
    return Signature(
        name="MD5",
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
