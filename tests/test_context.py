"""Tests for context hints (--from)."""

import pytest

from hashident.context import CONTEXT_BOOST, parse_context
from hashident.engine import identify
from hashident.models import Confidence, Context
from hashident.signatures import BCRYPT, MD5, NTLM

HEX32 = MD5.example


def names(result):
    return [c.signature.name for c in result.candidates]


def by_name(result):
    return {c.signature.name: c for c in result.candidates}


def test_windows_ranks_ntlm_above_md5():
    result = identify(HEX32, context="windows")

    assert names(result) == ["NTLM", "MD5"]
    ntlm, md5 = result.candidates
    assert ntlm.score == NTLM.popularity + CONTEXT_BOOST
    assert md5.score == MD5.popularity


def test_windows_reasons_reflect_final_ranking():
    c = by_name(identify(HEX32, context="windows"))

    assert "common in Windows environments (--from windows)" in c["NTLM"].reasons
    assert "ranked above MD5 by the context hint" in c["NTLM"].reasons
    assert "more common than NTLM with this shape, but NTLM matches the context hint" in c[
        "MD5"
    ].reasons
    for reason in c["NTLM"].reasons + c["MD5"].reasons:
        assert "less common than MD5" not in reason
    assert "most common format with this shape" not in c["MD5"].reasons


def test_web_keeps_md5_first_and_grows_its_lead():
    plain = by_name(identify(HEX32))
    web = by_name(identify(HEX32, context="web"))

    assert names(identify(HEX32, context="web")) == ["MD5", "NTLM"]
    assert web["MD5"].score - web["NTLM"].score > plain["MD5"].score - plain["NTLM"].score
    assert "common in web applications (--from web)" in web["MD5"].reasons
    assert "most common format with this shape" in web["MD5"].reasons
    assert "less common than MD5 with this shape" in web["NTLM"].reasons


@pytest.mark.parametrize("context", list(Context), ids=lambda c: c.value)
def test_ambiguous_match_is_never_high_with_any_context(context):
    result = identify(HEX32, context=context)

    assert len(result.candidates) == 2
    assert all(c.confidence is not Confidence.HIGH for c in result.candidates)


def test_windows_flip_leaves_both_medium():
    result = identify(HEX32, context="windows")

    assert [c.confidence for c in result.candidates] == [Confidence.MEDIUM] * 2


@pytest.mark.parametrize("context", list(Context), ids=lambda c: c.value)
def test_string_and_enum_context_give_identical_results(context):
    assert identify(HEX32, context=context.value) == identify(HEX32, context=context)
    assert identify(HEX32, context=context.value.upper()) == identify(HEX32, context=context)


@pytest.mark.parametrize("bad", ["mac", "", "win"])
def test_invalid_context_raises_value_error_listing_options(bad):
    with pytest.raises(ValueError, match="windows, linux, web, db"):
        identify(HEX32, context=bad)


def test_invalid_context_raises_even_for_empty_input():
    with pytest.raises(ValueError):
        identify("", context="mac")


def test_parse_context_accepts_none_and_padding():
    assert parse_context(None) is None
    assert parse_context("  DB ") is Context.DB


@pytest.mark.parametrize("context", [None, *Context], ids=lambda c: getattr(c, "value", "none"))
def test_bcrypt_stays_high_with_any_context(context):
    result = identify(BCRYPT.example, context=context)

    assert names(result) == ["bcrypt"]
    assert result.best.confidence is Confidence.HIGH


def test_no_context_matches_step_5_results():
    result = identify(HEX32)

    assert result == identify(HEX32, context=None)
    assert [(c.signature.name, c.score, c.confidence, c.reasons) for c in result.candidates] == [
        (
            "MD5",
            100.0,
            Confidence.MEDIUM,
            (
                "32 hexadecimal characters",
                "most common format with this shape",
                "also matches NTLM: same length and charset",
            ),
        ),
        (
            "NTLM",
            60.0,
            Confidence.LOW,
            (
                "32 hexadecimal characters",
                "less common than MD5 with this shape",
                "also matches MD5: same length and charset",
            ),
        ),
    ]
