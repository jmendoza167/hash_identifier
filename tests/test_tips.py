"""Tests for --from re-run tips."""

from hashident.engine import identify
from hashident.models import Category, Context, Signature, Strength, Tier
from hashident.signatures import BCRYPT, MD5, NTLM, SHA1
from hashident.tips import ContextTip, context_tips


def test_md5_example_suggests_only_windows():
    assert context_tips(identify(MD5.example)) == (ContextTip(Context.WINDOWS, NTLM),)


def test_no_tips_when_context_already_given():
    for context in Context:
        assert context_tips(identify(MD5.example, context)) == ()


def test_no_tips_for_high_confidence_result():
    assert context_tips(identify(BCRYPT.example)) == ()


def test_no_tips_when_nothing_matched():
    assert context_tips(identify("hello world")) == ()
    assert context_tips(identify("")) == ()


def test_no_tips_when_no_context_changes_the_top():
    # --from db boosts both SHA-1 and MySQL, so SHA-1 stays first.
    assert context_tips(identify(SHA1.example)) == ()


def _fake(name, popularity, contexts=()):
    return Signature(
        name=name,
        category=Category.RAW,
        tier=Tier.POSSIBLE,
        pattern=r"x+",
        strength=Strength.WEAK,
        strength_note="test",
        example="xxx",
        popularity=popularity,
        contexts=frozenset(contexts),
    )


def test_tips_are_computed_from_the_signatures():
    common = _fake("Common", 100)
    niche = _fake("Niche", 70, {Context.LINUX, Context.DB})
    sigs = [common, niche]

    tips = context_tips(identify("xxx", signatures=sigs), signatures=sigs)

    assert tips == (ContextTip(Context.LINUX, niche), ContextTip(Context.DB, niche))
