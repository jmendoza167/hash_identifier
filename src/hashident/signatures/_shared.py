"""Pattern fragments and context sets shared by the signature modules."""

from __future__ import annotations

from hashident.models import Charset, Context

B64 = Charset.CRYPT64.char_class  # crypt(3) base64 alphabet
SALT = r"[^$:\s]"  # crypt salts may hold any character except these
BASE64 = Charset.BASE64.char_class  # standard base64 alphabet, without padding
COLON_FIELD = r"[^:\s]{1,256}"  # one field of a colon-separated line, e.g. a salt


def hex_chars(length: int) -> str:
    """A pattern for exactly ``length`` hex characters of either case."""
    return f"{Charset.HEX.char_class}{{{length}}}"


WEB_DB = frozenset({Context.WEB, Context.DB})
WEB = frozenset({Context.WEB})
DB = frozenset({Context.DB})
LINUX = frozenset({Context.LINUX})
WINDOWS = frozenset({Context.WINDOWS})
