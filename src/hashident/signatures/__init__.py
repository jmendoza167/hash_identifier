"""The signature database: every hash format hashident knows how to recognise.

``SIGNATURES`` is the one registry the rest of the program reads. It is put
together from one module per category (``raw``, ``salted``, ``application``,
``crypt``, ``checksums``), each holding plain ``Signature`` entries.

Adding a format
---------------
Write one ``Signature`` in the module for its category and add it to that
module's ``SIGNATURES`` tuple. A bare digest needs only ``length`` and
``charset``; anything with structure gives a ``pattern``. Nothing else needs
to change: matching, ranking and every output format read the registry.

Example hashes are taken from the Hashcat example hashes list
(https://hashcat.net/wiki/doku.php?id=example_hashes); the plaintext for all
of them is "hashcat". The one exception is MySQL 4.1+, whose example is
Hashcat's mode 300 hash written in MySQL's own format (see ``application``).

Tiers
-----
``tier`` says how a format is presented when an input has its shape:

    POSSIBLE        pinned by a prefix or structure, or the usual format for
                    the shape (MD5 and NTLM for 32 hex, SHA-1 for 40)
    LEAST_POSSIBLE  same shape, but rarer

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
can still lift a lower-ranked format to the top, e.g. NTLM over MD5 with
--from windows.
"""

from __future__ import annotations

from hashident.models import Signature
from hashident.signatures import application, checksums, crypt, raw, salted
from hashident.signatures.application import MYSQL41
from hashident.signatures.crypt import BCRYPT, MD5CRYPT, SHA512CRYPT
from hashident.signatures.raw import MD5, NTLM, SHA1, SHA224, SHA256, SHA512

__all__ = [
    "BCRYPT",
    "MD5",
    "MD5CRYPT",
    "MYSQL41",
    "NTLM",
    "SHA1",
    "SHA224",
    "SHA256",
    "SHA512",
    "SHA512CRYPT",
    "SIGNATURES",
    "get_signature",
]

# The order here is not significant: results are ranked by tier and score.
SIGNATURES: tuple[Signature, ...] = (
    raw.SIGNATURES
    + salted.SIGNATURES
    + application.SIGNATURES
    + crypt.SIGNATURES
    + checksums.SIGNATURES
)

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
