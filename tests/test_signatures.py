"""Tests for the signature database."""

import hashlib

import pytest

from hashident.signatures import SIGNATURES, get_signature

HEX32 = "8743b52063cd84097a65d1633f5c74f5"


@pytest.mark.parametrize("sig", SIGNATURES, ids=lambda s: s.name)
def test_example_matches_own_pattern(sig):
    assert sig.matches(sig.example)


def test_names_are_unique():
    names = [sig.name.casefold() for sig in SIGNATURES]
    assert len(names) == len(set(names))


def test_database_is_immutable():
    assert isinstance(SIGNATURES, tuple)


def test_md5_and_ntlm_are_ambiguous():
    assert get_signature("MD5").matches(HEX32)
    assert get_signature("NTLM").matches(HEX32)


def test_md5_outranks_ntlm_by_default():
    assert get_signature("MD5").popularity > get_signature("NTLM").popularity


def test_bcrypt_and_md5_do_not_cross_match():
    md5, bcrypt = get_signature("MD5"), get_signature("bcrypt")
    assert not bcrypt.matches(HEX32)
    assert not md5.matches(bcrypt.example)


def test_uppercase_md5_matches():
    assert get_signature("MD5").matches(HEX32.upper())


@pytest.mark.parametrize("prefix", ["$2a$", "$2b$", "$2y$"])
def test_bcrypt_accepts_all_prefixes(prefix):
    bcrypt = get_signature("bcrypt")
    assert bcrypt.matches(prefix + bcrypt.example[4:])


@pytest.mark.parametrize("cost", ["03", "32", "5"])
def test_bcrypt_rejects_invalid_cost(cost):
    bcrypt = get_signature("bcrypt")
    assert not bcrypt.matches(bcrypt.example.replace("$05$", f"${cost}$"))


def test_md5_example_is_md5_of_hashcat():
    # Hashcat's example hashes all use the plaintext "hashcat".
    assert get_signature("MD5").example == hashlib.md5(b"hashcat").hexdigest()


def test_get_signature_is_case_insensitive():
    assert get_signature("BCRYPT") is get_signature("bcrypt")


def test_get_signature_unknown_name_raises():
    with pytest.raises(KeyError, match="Unknown signature"):
        get_signature("sha-512")
