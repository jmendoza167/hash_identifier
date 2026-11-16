"""Pattern fragments and context sets shared by the signature modules."""

from __future__ import annotations

from hashident.models import Charset, Context

B64 = Charset.CRYPT64.char_class  # crypt(3) base64 alphabet
SALT = r"[^$:\s]"  # crypt salts may hold any character except these


def hex_chars(length: int) -> str:
    """A pattern for exactly ``length`` hex characters of either case."""
    return f"{Charset.HEX.char_class}{{{length}}}"


WEB_DB = frozenset({Context.WEB, Context.DB})
LINUX = frozenset({Context.LINUX})
