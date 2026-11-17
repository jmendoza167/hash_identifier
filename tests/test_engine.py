"""Tests for the identification engine."""

import pytest

from hashident.context import CONTEXT_BOOST
from hashident.engine import identify
from hashident.models import Category, Confidence, Context, Signature, Strength, Tier
from hashident.signatures import (
    BCRYPT,
    MD5,
    MD5CRYPT,
    MYSQL41,
    NTLM,
    SHA1,
    SHA512CRYPT,
    SIGNATURES,
)


PAIR = (MD5, NTLM)
"""The two possible formats for 32 hex characters, without the rarer ones."""


def names(result):
    return [c.signature.name for c in result.candidates]


def possible(result):
    return [c.signature.name for c in result.candidates if c.tier is Tier.POSSIBLE]


def test_md5_example_ranks_md5_then_ntlm_and_neither_is_high():
    result = identify(MD5.example)

    assert possible(result) == ["MD5", "NTLM"]
    assert names(result)[:2] == ["MD5", "NTLM"]
    md5, ntlm = result.candidates[:2]
    # Both are usual answers for 32 hex characters, so both are "possible".
    assert (md5.tier, ntlm.tier) == (Tier.POSSIBLE, Tier.POSSIBLE)
    assert (md5.confidence, ntlm.confidence) == (Confidence.MEDIUM, Confidence.MEDIUM)
    assert md5.score > ntlm.score


def test_md5_reasons_explain_shape_and_ambiguity():
    md5 = identify(MD5.example, signatures=PAIR).best

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
    assert possible(result) == ["MD5", "NTLM"]


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


def _fake(
    name,
    popularity=50,
    *,
    tier=Tier.POSSIBLE,
    pattern=r"x+",
    example="xxx",
    prefixes=(),
    structure=None,
    contexts=(),
):
    return Signature(
        name=name,
        category=Category.RAW,
        tier=tier,
        pattern=pattern,
        prefixes=prefixes,
        structure=structure,
        strength=Strength.WEAK,
        strength_note="test",
        example=example,
        popularity=popularity,
        contexts=frozenset(contexts),
    )


def tiers(result):
    return [c.tier for c in result.candidates]


def test_equal_scores_are_ordered_by_name():
    result = identify("xxx", signatures=[_fake("Beta", 50), _fake("Alpha", 50)])

    assert names(result) == ["Alpha", "Beta"]
    assert all(c.confidence is Confidence.MEDIUM for c in result.candidates)


# --- Tiers ----------------------------------------------------------------------


def test_possible_tier_ranks_above_least_possible_whatever_the_popularity():
    rare = _fake("Rare", 90, tier=Tier.LEAST_POSSIBLE)
    common = _fake("Common", 50)

    result = identify("xxx", signatures=[rare, common])

    assert names(result) == ["Common", "Rare"]
    assert tiers(result) == [Tier.POSSIBLE, Tier.LEAST_POSSIBLE]


def test_candidates_are_ordered_by_score_within_each_tier():
    sigs = [
        _fake("Rare-low", 10, tier=Tier.LEAST_POSSIBLE),
        _fake("Common-low", 40),
        _fake("Rare-high", 30, tier=Tier.LEAST_POSSIBLE),
        _fake("Common-high", 80),
    ]

    assert names(identify("xxx", signatures=sigs)) == [
        "Common-high",
        "Common-low",
        "Rare-high",
        "Rare-low",
    ]


def test_confidence_follows_the_tier_when_several_formats_match():
    sigs = [_fake("A", 90), _fake("B", 10), _fake("C", 80, tier=Tier.LEAST_POSSIBLE)]

    result = identify("xxx", signatures=sigs)

    assert [c.confidence for c in result.candidates] == [
        Confidence.MEDIUM,
        Confidence.MEDIUM,  # far behind A on popularity, but still "possible"
        Confidence.LOW,
    ]


def test_a_sole_match_is_high_confidence():
    result = identify("xxx", signatures=[_fake("Only", 20)])

    assert result.best.confidence is Confidence.HIGH
    assert "no other known format has this shape" in result.best.reasons


def test_least_possible_candidate_says_it_is_less_common_than_the_leader():
    sigs = [_fake("Common", 50), _fake("Rare", 20, tier=Tier.LEAST_POSSIBLE)]

    rare = identify("xxx", signatures=sigs).candidates[1]

    assert "less common than Common with this shape" in rare.reasons


def test_context_hint_reorders_within_a_tier_but_never_across_tiers():
    common = _fake("Common", 50)
    rare = _fake("Rare", 20, tier=Tier.LEAST_POSSIBLE, contexts=[Context.WINDOWS])

    result = identify("xxx", context="windows", signatures=[common, rare])

    assert names(result) == ["Common", "Rare"]
    top, runner_up = result.candidates
    assert runner_up.score > top.score  # boosted, but still in the lower tier
    assert "most common format with this shape" in top.reasons
    assert "common in Windows environments (--from windows)" in runner_up.reasons
    assert "less common than Common with this shape" in runner_up.reasons


# --- Prefix > structure > bare shape --------------------------------------------------

LOOSE = dict(pattern=r".+", example="anything")


def test_prefix_match_wins_outright_over_shape_lookalikes():
    prefixed = _fake("Prefixed", 10, pattern=r"\$p\$x+", prefixes=("$p$",), example="$p$xxx")
    lookalike = _fake("Lookalike", 90, **LOOSE)

    result = identify("$p$xxx", signatures=[lookalike, prefixed])

    assert names(result) == ["Prefixed"]
    assert result.best.confidence is Confidence.HIGH


def test_structure_match_beats_bare_shape():
    structured = _fake("Salted", 10, pattern=r"x+:y+", structure="hash:salt", example="xx:yy")
    lookalike = _fake("Lookalike", 90, **LOOSE)

    assert names(identify("xx:yy", signatures=[lookalike, structured])) == ["Salted"]


def test_prefix_match_beats_structure_match():
    prefixed = _fake("Prefixed", 10, pattern=r"\$p\$.+", prefixes=("$p$",), example="$p$x")
    structured = _fake("Salted", 90, pattern=r".+:.+", structure="hash:salt", example="x:y")

    assert names(identify("$p$xx:yy", signatures=[structured, prefixed])) == ["Prefixed"]


def test_formats_sharing_a_prefix_are_all_kept():
    one = _fake("One", 60, pattern=r"\$p\$x+", prefixes=("$p$",), example="$p$x")
    two = _fake("Two", 40, pattern=r"\$p\$x+", prefixes=("$p$", "$q$"), example="$p$x")

    result = identify("$p$xxx", signatures=[two, one])

    assert names(result) == ["One", "Two"]
    assert [c.confidence for c in result.candidates] == [Confidence.MEDIUM] * 2


OPTIONAL_STAR = dict(pattern=r"\*?x+", prefixes=("*",), example="*xxx")


def test_optional_prefix_counts_only_when_the_input_has_it():
    starred = _fake("Starred", 10, **OPTIONAL_STAR)
    lookalike = _fake("Lookalike", 90, **LOOSE)

    assert names(identify("*xxx", signatures=[lookalike, starred])) == ["Starred"]
    assert names(identify("xxx", signatures=[lookalike, starred])) == ["Lookalike", "Starred"]


def test_prefix_match_is_possible_even_for_a_least_possible_format():
    starred = _fake("Starred", 10, tier=Tier.LEAST_POSSIBLE, **OPTIONAL_STAR)

    assert tiers(identify("*xxx", signatures=[starred])) == [Tier.POSSIBLE]
    assert tiers(identify("xxx", signatures=[starred])) == [Tier.LEAST_POSSIBLE]


# --- Whitespace inside the input ---------------------------------------------------

WHITESPACE_REASON = "ignoring whitespace inside the input"


@pytest.mark.parametrize(
    "raw",
    [
        "8743b520 63cd8409 7a65d163 3f5c74f5",
        "8743b52063cd8409\n7a65d1633f5c74f5",
        " 8743b52063cd8409\t7a65d1633f5c74f5\r\n",
    ],
    ids=["spaces", "newline", "tab-and-padding"],
)
def test_whitespace_inside_the_input_is_ignored_when_nothing_matches_as_is(raw):
    result = identify(raw)

    assert possible(result) == ["MD5", "NTLM"]
    assert result.normalized == MD5.example
    for candidate in result.candidates:
        assert WHITESPACE_REASON in candidate.reasons


def test_whitespace_retry_is_not_used_when_the_input_matches_as_is():
    spaced = _fake("Spaced", pattern=r"x+ x+", example="x x")
    joined = _fake("Joined")

    result = identify("xx xx", signatures=[joined, spaced])

    assert names(result) == ["Spaced"]
    assert result.normalized == "xx xx"
    assert WHITESPACE_REASON not in result.best.reasons


def test_input_without_inner_whitespace_has_no_whitespace_reason():
    assert WHITESPACE_REASON not in identify(f"  {MD5.example}\n").best.reasons


def test_unmatched_input_keeps_its_inner_whitespace():
    result = identify("hello  world")

    assert result.candidates == ()
    assert result.normalized == "hello  world"


# --- Step 7: SHA family, crypt formats, MySQL --------------------------------


@pytest.mark.parametrize("name", ["SHA-224", "SHA-256", "SHA-384", "SHA-512"])
def test_sha2_is_the_best_guess_for_its_length_but_not_the_only_one(name):
    sig = next(s for s in SIGNATURES if s.name == name)
    result = identify(sig.example)

    assert result.best.signature is sig
    assert len(result.candidates) > 1
    assert result.best.confidence is Confidence.MEDIUM


@pytest.mark.parametrize(
    ("value", "first", "rest"),
    [
        (MD5.example, ["MD5", "NTLM"], {"LM", "MD4", "RIPEMD-128", "HAVAL-128"}),
        (SHA1.example, ["SHA-1", "MySQL 4.1+"], {"RIPEMD-160", "Tiger-160", "HAVAL-160"}),
    ],
    ids=["32-hex", "40-hex"],
)
def test_common_formats_are_possible_and_rarer_ones_least_possible(value, first, rest):
    result = identify(value)

    assert possible(result) == first
    least = {c.signature.name for c in result.candidates if c.tier is Tier.LEAST_POSSIBLE}
    assert rest <= least
    assert all(c.confidence is Confidence.LOW for c in result.candidates[len(first) :])


def test_ntlm_is_the_best_guess_for_32_hex_from_windows_and_lm_leads_the_rest():
    result = identify(NTLM.example, context=Context.WINDOWS)

    assert possible(result) == ["NTLM", "MD5"]
    assert names(result)[2] == "LM"


@pytest.mark.parametrize(
    "value",
    [
        MD5CRYPT.example,
        SHA512CRYPT.example,
        SHA512CRYPT.example.replace("$6$", "$6$rounds=5000$", 1),
    ],
    ids=["md5crypt", "sha512crypt", "sha512crypt-rounds"],
)
def test_crypt_prefixes_are_high_confidence(value):
    result = identify(value)

    assert len(result.candidates) == 1
    assert result.best.confidence is Confidence.HIGH
    prefix = value.split("$")[1]
    assert f"starts with {result.best.signature.name} prefix ${prefix}$" in result.best.reasons


def test_mysql_with_asterisk_is_high_confidence():
    result = identify(MYSQL41.example)

    assert names(result) == ["MySQL 4.1+"]
    assert result.best.confidence is Confidence.HIGH
    assert "'*' followed by 40 hexadecimal characters" in result.best.reasons


def test_bare_40_hex_is_sha1_first_with_mysql_as_runner_up():
    result = identify(MYSQL41.example[1:].lower())  # Hashcat's mode 300 example

    assert possible(result) == ["SHA-1", "MySQL 4.1+"]
    assert [c.confidence for c in result.candidates[:2]] == [Confidence.MEDIUM, Confidence.MEDIUM]


@pytest.mark.parametrize("sig", [MD5CRYPT, SHA512CRYPT], ids=lambda s: s.name)
def test_linux_context_boosts_crypt_formats(sig):
    result = identify(sig.example, context="linux")

    assert result.best.score == sig.popularity + CONTEXT_BOOST
    assert "common in Linux environments (--from linux)" in result.best.reasons
    assert result.best.confidence is Confidence.HIGH


def test_db_context_boosts_mysql():
    result = identify(MYSQL41.example, context="db")

    assert result.best.score == MYSQL41.popularity + CONTEXT_BOOST
    assert "common in databases (--from db)" in result.best.reasons


def test_db_context_boosts_both_for_bare_40_hex_so_sha1_stays_first():
    result = identify(SHA1.example, context="db")

    assert possible(result) == ["SHA-1", "MySQL 4.1+"]
    assert all(
        c.score == c.signature.popularity + CONTEXT_BOOST for c in result.candidates[:2]
    )


# --- Registry invariants the engine relies on -----------------------------------------


@pytest.mark.parametrize("sig", SIGNATURES, ids=lambda s: s.name)
def test_every_example_has_a_possible_candidate(sig):
    # Each shape needs a "usual" format, or its report would have no best guess.
    assert Tier.POSSIBLE in tiers(identify(sig.example))


@pytest.mark.parametrize("sig", SIGNATURES, ids=lambda s: s.name)
def test_possible_candidates_always_come_first(sig):
    found = tiers(identify(sig.example))

    assert found == sorted(found, key=[Tier.POSSIBLE, Tier.LEAST_POSSIBLE].index)


# --- "also matches" stays readable when many formats share a shape ----------------------


def _also_matches(candidate):
    return next(r for r in candidate.reasons if r.startswith("also matches "))


def test_also_matches_names_up_to_three_other_formats():
    sigs = [_fake(name, pop) for name, pop in [("A", 90), ("B", 80), ("C", 70), ("D", 60)]]

    top = identify("xxx", signatures=sigs).best

    assert _also_matches(top) == "also matches B, C, D: same format"


def test_also_matches_counts_the_rest_beyond_three():
    sigs = [_fake(name, 90 - i) for i, name in enumerate("ABCDEF")]

    result = identify("xxx", signatures=sigs)

    assert _also_matches(result.best) == "also matches B, C, D and 2 more: same format"
    assert _also_matches(result.candidates[-1]) == "also matches A, B, C and 2 more: same format"
