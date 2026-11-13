"""Tests for the signature database."""

import hashlib

import pytest

from hashident.signatures import (
    MD5CRYPT,
    MYSQL41,
    SHA512CRYPT,
    SIGNATURES,
    get_signature,
)

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
        get_signature("whirlpool")


# --- Step 7: SHA family, crypt formats, MySQL --------------------------------

PASSWORD = b"hashcat"


@pytest.mark.parametrize(
    ("name", "algorithm"),
    [("SHA-1", "sha1"), ("SHA-224", "sha224"), ("SHA-256", "sha256"), ("SHA-512", "sha512")],
)
def test_sha_examples_are_digests_of_hashcat(name, algorithm):
    assert get_signature(name).example == hashlib.new(algorithm, PASSWORD).hexdigest()


def test_mysql_example_is_double_sha1_of_hashcat():
    digest = hashlib.sha1(hashlib.sha1(PASSWORD).digest()).hexdigest()
    assert MYSQL41.example == "*" + digest.upper()


@pytest.mark.parametrize(
    ("length", "expected"),
    [
        (32, {"MD5", "NTLM"}),
        (40, {"SHA-1", "MySQL 4.1+"}),  # bare MySQL, as in Hashcat's mode 300 example
        (56, {"SHA-224"}),
        (64, {"SHA-256"}),
        (128, {"SHA-512"}),
        (31, set()),
        (48, set()),
        (96, set()),  # SHA-384 is not in the database yet
    ],
)
def test_hex_length_matches_only_expected_formats(length, expected):
    value = ("0123456789abcdef" * 8)[:length]
    assert {sig.name for sig in SIGNATURES if sig.matches(value)} == expected


def test_mysql_matches_with_and_without_asterisk_in_either_case():
    bare = MYSQL41.example[1:]
    for value in (MYSQL41.example, MYSQL41.example.lower(), bare, bare.lower()):
        assert MYSQL41.matches(value), value


def test_mysql_rejects_wrong_lengths_and_double_asterisk():
    assert not MYSQL41.matches(MYSQL41.example[:-1])
    assert not MYSQL41.matches(MYSQL41.example + "0")
    assert not MYSQL41.matches("*" + MYSQL41.example)


def test_sha512crypt_accepts_optional_rounds():
    with_rounds = SHA512CRYPT.example.replace("$6$", "$6$rounds=5000$", 1)
    assert SHA512CRYPT.matches(with_rounds)


def test_sha512crypt_rejects_wrong_hash_length():
    assert not SHA512CRYPT.matches(SHA512CRYPT.example[:-1])
    assert not SHA512CRYPT.matches(SHA512CRYPT.example + "a")


def test_md5crypt_salt_is_at_most_8_chars():
    assert MD5CRYPT.matches("$1$$4IbK3fHS/H1YGtNYBrIEB1")  # empty salt is valid
    assert not MD5CRYPT.matches("$1$ehAsHC4tX$4IbK3fHS/H1YGtNYBrIEB1")


def test_crypt_prefixes_do_not_cross_match():
    assert not MD5CRYPT.matches(SHA512CRYPT.example)
    assert not SHA512CRYPT.matches(MD5CRYPT.example)
