"""Tests for the identification engine."""

import pytest

from hashident.engine import MEDIUM_MAX_GAP, identify
from hashident.models import Confidence, Signature, Strength
from hashident.signatures import BCRYPT, MD5, SIGNATURES


def names(result):
    return [c.signature.name for c in result.candidates]


def test_md5_example_ranks_md5_then_ntlm_and_neither_is_high():
    result = identify(MD5.example)

    assert names(result) == ["MD5", "NTLM"]
    md5, ntlm = result.candidates
    assert md5.confidence is Confidence.MEDIUM
    assert ntlm.confidence is Confidence.LOW
    assert md5.score > ntlm.score


def test_md5_reasons_explain_shape_and_ambiguity():
    md5 = identify(MD5.example).best

    assert "32 hexadecimal characters" in md5.reasons
    assert "most common format with this shape" in md5.reasons
    assert "also matches NTLM: same length and charset" in md5.reasons


def test_bcrypt_example_is_single_high_confidence_candidate():
    result = identify(BCRYPT.example)

    assert names(result) == ["bcrypt"]
    assert result.best.confidence is Confidence.HIGH
    assert "starts with bcrypt prefix $2a$ (cost 5)" in result.best.reasons


def test_uppercase_md5_still_ranks_md5_first():
    assert identify(MD5.example.upper()).best.signature.name == "MD5"


def test_surrounding_whitespace_is_ignored():
    result = identify(f"  {MD5.example}\n")

    assert result.normalized == MD5.example
    assert names(result) == ["MD5", "NTLM"]


@pytest.mark.parametrize("raw", ["hello world", "", "   ", "\t\n"])
def test_garbage_and_empty_input_return_no_candidates(raw):
    result = identify(raw)

    assert result.candidates == ()
    assert result.best is None


def test_ranking_is_stable_across_runs():
    assert identify(MD5.example) == identify(MD5.example)


@pytest.mark.parametrize("sig", SIGNATURES, ids=lambda s: s.name)
def test_every_candidate_has_a_reason(sig):
    for candidate in identify(sig.example).candidates:
        assert candidate.reasons, candidate.signature.name


def _fake(name, popularity):
    return Signature(
        name=name,
        pattern=r"x+",
        strength=Strength.WEAK,
        strength_note="test",
        example="xxx",
        popularity=popularity,
    )


def test_equal_scores_are_ordered_by_name():
    result = identify("xxx", signatures=[_fake("Beta", 50), _fake("Alpha", 50)])

    assert names(result) == ["Alpha", "Beta"]
    assert all(c.confidence is Confidence.MEDIUM for c in result.candidates)


@pytest.mark.parametrize(
    ("gap", "expected"),
    [(MEDIUM_MAX_GAP, Confidence.MEDIUM), (MEDIUM_MAX_GAP + 1, Confidence.LOW)],
)
def test_runner_up_confidence_depends_on_gap_from_top(gap, expected):
    result = identify("xxx", signatures=[_fake("Top", 80), _fake("Runner", 80 - gap)])

    assert result.candidates[0].confidence is Confidence.MEDIUM
    assert result.candidates[1].confidence is expected
