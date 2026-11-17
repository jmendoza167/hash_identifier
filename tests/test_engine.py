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
        (
            SHA1.example,
            ["SHA-1", "MySQL 4.1+"],
            {"RIPEMD-160", "Tiger-160", "HAVAL-160", "sha1($pass.$salt)", "sha1(md5($pass))"},
        ),
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


# --- Optional structure: a salted hash seen with or without its salt --------------------

SALTED = dict(pattern=r"x+(?P<structure>:y+)?", structure="hash:salt", example="xx:yy")


def test_optional_structure_counts_only_when_the_input_has_it():
    salted = _fake("Salted", 10, **SALTED)
    lookalike = _fake("Lookalike", 90, **LOOSE)

    assert names(identify("xx:yy", signatures=[lookalike, salted])) == ["Salted"]
    assert names(identify("xx", signatures=[lookalike, salted])) == ["Lookalike", "Salted"]


def test_format_seen_without_its_structure_is_least_possible():
    salted = _fake("Salted", 90, **SALTED)  # a possible format, when the salt is there
    plain = _fake("Plain", 10)

    assert tiers(identify("xx:yy", signatures=[salted])) == [Tier.POSSIBLE]
    result = identify("xx", signatures=[salted, plain])
    assert names(result) == ["Plain", "Salted"]
    assert tiers(result) == [Tier.POSSIBLE, Tier.LEAST_POSSIBLE]


def test_structure_match_keeps_the_signature_tier():
    rare = _fake("Rare", 10, tier=Tier.LEAST_POSSIBLE, **SALTED)
    common = _fake("Common", 50, **SALTED)

    result = identify("xx:yy", signatures=[rare, common])

    assert names(result) == ["Common", "Rare"]
    assert tiers(result) == [Tier.POSSIBLE, Tier.LEAST_POSSIBLE]


def test_structure_reason_names_the_layout():
    salted = _fake("Salted", **SALTED)

    assert "has the hash:salt layout" in identify("xx:yy", signatures=[salted]).best.reasons
    assert "has the hash:salt layout" not in identify("xx", signatures=[salted]).best.reasons


def test_prefix_reason_names_a_prefix_without_dollar_signs():
    sig = _fake("Tagged", pattern=r"tag:x+", prefixes=("tag:",), example="tag:x")

    assert "starts with Tagged prefix tag:" in identify("tag:xxx", signatures=[sig]).best.reasons


# --- The registry: salted and prefixed formats ------------------------------------------


def least(result):
    return [c.signature.name for c in result.candidates if c.tier is Tier.LEAST_POSSIBLE]


def test_bare_md5_lists_salted_and_nested_variants_as_least_possible():
    found = least(identify(MD5.example))

    for name in ("md5(md5($pass))", "md5($pass.$salt)", "HMAC-MD5 (key = $pass)", "RAdmin v2.x"):
        assert name in found, name
    assert "Joomla" not in names(identify(MD5.example))  # needs its salt to be told apart


def test_md5_with_a_salt_is_a_salted_md5_not_a_raw_one():
    result = identify("01dfae6e5d4d90d9892622325959afbe:7050461")

    assert possible(result) == [
        "md5($pass.$salt)",
        "md5($salt.$pass)",
        "Domain Cached Credentials",
    ]
    assert "HMAC-MD5 (key = $pass)" in least(result)
    assert "MD5" not in names(result)
    assert "NTLM" not in names(result)


def test_joomla_is_first_for_a_32_character_alphanumeric_salt():
    result = identify("19e0e8d91c722e7091ca7a6a6fb0f4fa:UzW4fKkPqXn2MHs9tGyLbR3cJdV7ZaEo")

    assert possible(result)[0] == "Joomla"
    assert "md5($pass.$salt)" in possible(result)
    assert "SAM (LM:NT)" not in names(result)


def test_a_32_hex_salt_could_also_be_the_nt_half_of_a_sam_entry():
    # Hashcat's Joomla example has an all-digit salt, which is valid hex too.
    result = identify("19e0e8d91c722e7091ca7a6a6fb0f4fa:54718031842521651757785603028777")

    assert possible(result)[:2] == ["SAM (LM:NT)", "Joomla"]


def test_lm_nt_pair_is_a_sam_entry_first():
    pair = "299bd128c1101fd6aad3b435b51404ee:b4b9b02e6f09a9bd760f388b67351e2b"

    result = identify(pair)

    assert possible(result)[0] == "SAM (LM:NT)"
    assert "has the LM:NT layout" in result.best.reasons


def test_sha1_with_a_salt_lists_salted_sha1_first():
    result = identify("2fc5a684737ce1bf7b3b239df432416e0dd07357:2014")

    assert possible(result) == ["sha1($pass.$salt)", "sha1($salt.$pass)"]
    assert "SHA-1" not in names(result)


def test_sixteen_hex_is_old_mysql_first():
    assert possible(identify("7196759210defdc0")) == ["MySQL323", "MD5(Half)"]


@pytest.mark.parametrize(
    "word", ["administrator", "password12345", "Hello, World!"], ids=["word", "alnum", "text"]
)
def test_thirteen_ordinary_characters_are_not_des_crypt(word):
    assert len(word) == 13
    assert identify(word).candidates == ()


PREFIXED = [sig for sig in SIGNATURES if sig.prefixes]


@pytest.mark.parametrize("sig", PREFIXED, ids=lambda s: s.name)
def test_prefixed_format_brings_no_lookalikes(sig):
    result = identify(sig.example)

    assert sig in [c.signature for c in result.candidates]
    for candidate in result.candidates:
        prefixes = candidate.signature.prefixes
        assert prefixes and sig.example.startswith(prefixes), candidate.signature.name
        assert candidate.tier is Tier.POSSIBLE


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("$2b$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6", ["bcrypt"]),
        ("$1$ehAsHC4t$4IbK3fHS/H1YGtNYBrIEB1", ["md5crypt"]),
        ("$apr1$71850310$gh9m4xcAn3MGxogwX/ztb.", ["MD5(APR)"]),
        ("$P$9d2OMJEOHyPg11MeSv46hashcatG.F1", ["WordPress (phpass)"]),
        ("$H$984478476IagS59wHZvyQMArzfx58u.", ["phpBB3 (phpass)"]),
        ("*FCF7C1B8749CF99D88E5F34271D636178FB5D130", ["MySQL 4.1+"]),
        ("sha1$fe76b$02d5916550edf7fc8c886f044887f4b1abf9b013", ["Django SHA-1"]),
        ("$DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f", ["Domain Cached Credentials 2"]),
    ],
    ids=["bcrypt", "md5crypt", "apr1", "wordpress", "phpbb3", "mysql", "django", "dcc2"],
)
def test_prefix_pins_the_format_down_to_one(value, expected):
    result = identify(value)

    assert names(result) == expected
    assert result.best.confidence is Confidence.HIGH


# --- "0x" in front of hex ------------------------------------------------------------------

HEX_PREFIX_REASON = "ignoring the 0x in front"


def _hex4(name="Hex", **overrides):
    fields = dict(pattern=r"[0-9a-fA-F]{4}", example="abcd")
    fields.update(overrides)
    return _fake(name, **fields)


def by_name(result):
    return {c.signature.name: c for c in result.candidates}


def test_hex_after_0x_is_tried_as_well_as_the_input_itself():
    tagged = _fake("Tagged", 10, tier=Tier.LEAST_POSSIBLE, pattern=r"0x[0-9a-f]{4}", example="0xabcd")

    found = by_name(identify("0xabcd", signatures=[tagged, _hex4()]))

    assert list(found) == ["Hex", "Tagged"]
    assert found["Hex"].ignored_prefix == "0x"
    assert HEX_PREFIX_REASON in found["Hex"].reasons
    assert found["Tagged"].ignored_prefix == ""
    assert HEX_PREFIX_REASON not in found["Tagged"].reasons


def test_shape_reason_describes_the_hex_without_the_0x():
    best = identify("0xabcd", signatures=[_hex4()]).best

    assert best.reasons[:2] == ("4 hexadecimal characters", HEX_PREFIX_REASON)


def test_result_keeps_the_input_as_typed():
    assert identify("0xabcd", signatures=[_hex4()]).normalized == "0xabcd"


def test_uppercase_0x_counts_too():
    best = identify("0XABCD", signatures=[_hex4()]).best

    assert best.ignored_prefix == "0X"


def test_a_prefix_that_starts_with_0x_still_wins_outright():
    pinned = _fake("Pinned", 10, pattern=r"0x01[0-9a-f]{2}", prefixes=("0x01",), example="0x01ab")

    result = identify("0x01ab", signatures=[_hex4(), pinned])

    assert names(result) == ["Pinned"]
    assert result.best.ignored_prefix == ""


@pytest.mark.parametrize("raw", ["0xzzzz", "0x", "x0abcd", "0xab:cd"])
def test_0x_is_only_dropped_in_front_of_plain_hex(raw):
    assert identify(raw, signatures=[_hex4()]).candidates == ()


def test_hex_without_0x_is_not_reported_as_prefixed():
    best = identify("abcd", signatures=[_hex4()]).best

    assert best.ignored_prefix == ""
    assert HEX_PREFIX_REASON not in best.reasons


def test_whitespace_and_0x_can_both_be_ignored():
    result = identify("0x ab cd", signatures=[_hex4()])

    assert result.normalized == "0xabcd"
    assert WHITESPACE_REASON in result.best.reasons
    assert HEX_PREFIX_REASON in result.best.reasons


def test_0x_and_32_hex_is_md5_or_ntlm_before_lineage():
    result = identify("0x" + MD5.example)

    assert possible(result) == ["MD5", "NTLM"]
    assert "Lineage II C4" in least(result)
    found = by_name(result)
    assert found["MD5"].ignored_prefix == "0x"
    assert found["Lineage II C4"].ignored_prefix == ""


def test_0x_and_40_hex_is_sha1_first():
    assert possible(identify("0x" + SHA1.example)) == ["SHA-1", "MySQL 4.1+"]


@pytest.mark.parametrize(
    "name", ["MSSQL 2000", "MSSQL 2005", "MSSQL 2012"], ids=["2000", "2005", "2012"]
)
def test_mssql_hash_is_pinned_by_its_0x_header(name):
    sig = next(s for s in SIGNATURES if s.name == name)

    result = identify(sig.example)

    assert names(result) == [name]
    assert result.best.confidence is Confidence.HIGH
    assert result.best.ignored_prefix == ""


def test_0x0100_with_another_length_is_not_mssql():
    # 0x, then 32 hex characters that happen to begin with 0100.
    result = identify("0x0100" + MD5.example[4:])

    assert possible(result) == ["MD5", "NTLM"]
    assert not any(name.startswith("MSSQL") for name in names(result))


def test_netntlm_versions_are_told_apart_by_their_fields():
    v1 = next(s for s in SIGNATURES if s.name == "NetNTLMv1")
    v2 = next(s for s in SIGNATURES if s.name == "NetNTLMv2")

    assert names(identify(v1.example)) == ["NetNTLMv1"]
    assert names(identify(v2.example)) == ["NetNTLMv2"]


def test_cisco_type_7_is_recognised_by_decoding_it():
    assert possible(identify("0822455D0A16")) == ["Cisco type 7"]  # "cisco"
    # The same shape with bytes that do not decode to text is not type 7.
    assert "Cisco type 7" not in names(identify("08FFFFFFFFFF"))
    assert "Cisco type 7" not in names(identify(MD5.example.upper()))


def test_cisco_pix_needs_a_character_that_is_not_hex():
    assert names(identify("dRRVnUmUHXOTt9nk")) == ["Cisco-PIX MD5"]
    assert "Cisco-PIX MD5" not in names(identify("7196759210defdc0"))


def test_oracle_11g_with_its_marker_is_pinned_and_without_it_is_a_salted_sha1():
    marked = "S:AC5F1E62D21FD0529428B84D42E8955B0496670338445748184477378130"
    split = "ac5f1e62d21fd0529428b84d42e8955b04966703:38445748184477378130"

    assert names(identify(marked)) == ["Oracle 11g"]
    assert possible(identify(split)) == ["sha1($pass.$salt)", "sha1($salt.$pass)", "Oracle 11g"]


def test_pwdump_line_is_recognised_whole():
    line = "Administrator:500:299bd128c1101fd6aad3b435b51404ee:b4b9b02e6f09a9bd760f388b67351e2b:::"

    assert names(identify(line)) == ["pwdump"]
    assert names(identify("guest:501:NO PASSWORD*********************:" + NTLM.example + ":::")) == [
        "pwdump"
    ]
