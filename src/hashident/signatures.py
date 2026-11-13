"""The signature database: every hash format hashident knows how to recognise.

Example hashes are taken from the Hashcat example hashes list
(https://hashcat.net/wiki/doku.php?id=example_hashes); the plaintext for all
of them is "hashcat".

Popularity scale
----------------
``popularity`` is a prior on a 0-100 scale: how likely this format is to be
the right answer, before any context hint, when an input matches it.
Signatures that match the same input are ranked by it, so only the relative
order between overlapping formats really matters.

    100  ubiquitous  - the default guess for its shape (MD5 for 32 hex)
     80  very common - widely deployed, often seen in leaks and audits
     60  common      - regularly seen, but usually needs context to win
     40  uncommon    - specific products or niches
     20  rare        - legacy or exotic formats

Keep gaps between overlapping formats modest, so that a --from context hint
(added later) can still lift a lower-ranked format to the top, e.g. NTLM over
MD5 with --from windows.
"""

from __future__ import annotations

from hashident.models import Context, Signature, Strength

_HEX32 = r"[0-9a-fA-F]{32}"

MD5 = Signature(
    name="MD5",
    pattern=_HEX32,
    strength=Strength.WEAK,
    strength_note="Fast and unsalted: GPUs test billions of guesses per second.",
    example="8743b52063cd84097a65d1633f5c74f5",
    hashcat_mode=0,
    john_format="raw-md5",
    popularity=100,
    contexts=frozenset({Context.WEB, Context.DB}),
)

NTLM = Signature(
    name="NTLM",
    pattern=_HEX32,
    strength=Strength.WEAK,
    strength_note="Unsalted MD4 of the password: even faster to crack than MD5.",
    example="b4b9b02e6f09a9bd760f388b67351e2b",
    hashcat_mode=1000,
    john_format="nt",
    popularity=60,
    contexts=frozenset({Context.WINDOWS}),
)

BCRYPT = Signature(
    name="bcrypt",
    # $2a$/$2b$/$2y$, a cost of 04-31, then 22 salt + 31 hash chars of bcrypt base64.
    pattern=r"\$2[aby]\$(?:0[4-9]|[12][0-9]|3[01])\$[./A-Za-z0-9]{53}",
    strength=Strength.STRONG,
    strength_note="Salted and deliberately slow, with a tunable cost factor per guess.",
    example="$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6",
    hashcat_mode=3200,
    john_format="bcrypt",
    popularity=80,
    contexts=frozenset({Context.WEB, Context.DB}),
)

SIGNATURES: tuple[Signature, ...] = (MD5, NTLM, BCRYPT)

_BY_NAME: dict[str, Signature] = {sig.name.casefold(): sig for sig in SIGNATURES}


def get_signature(name: str) -> Signature:
    """Look up a signature by name, ignoring case.

    Raises KeyError if no signature has that name.
    """
    try:
        return _BY_NAME[name.casefold()]
    except KeyError:
        known = ", ".join(sig.name for sig in SIGNATURES)
        raise KeyError(f"Unknown signature {name!r}; known: {known}") from None
