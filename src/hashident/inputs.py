"""Collecting the values to identify: arguments, a file, or standard input.

Order of the values, and where they come from:

1. Positional arguments, in the order given, exactly as typed.
2. Then the lines of ``-f PATH`` (``-f -`` reads standard input).
3. With neither, standard input is read if it is piped or redirected. On a
   terminal there is nothing to read, and ``gather`` returns None.

Lines (but not arguments) are cleaned up: surrounding whitespace and the
``\\r`` of Windows line endings are stripped, and blank lines and lines
starting with ``#`` are skipped.

Bytes are decoded as UTF-8 unless they start with a UTF-16 byte order mark,
which is what ``>`` redirection writes in Windows PowerShell 5.1. A UTF-8
BOM is dropped. Invalid bytes become U+FFFD instead of raising.

Input is decoded in chunks and yielded one line at a time, so memory use
depends on the longest line, not on the size of the input.
"""

from __future__ import annotations

import codecs
import sys
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import BinaryIO, TextIO

STDIN = "-"
ARGUMENT_SOURCE = "argument"
STDIN_SOURCE = "<stdin>"

_COMMENT = "#"
_CHUNK_SIZE = 64 * 1024
_TEXT_BOM = "﻿"
# (byte order mark, encoding of what follows it)
_BOMS = (
    (codecs.BOM_UTF8, "utf-8"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
)
_LONGEST_BOM = max(len(bom) for bom, _ in _BOMS)


class InputError(Exception):
    """Input could not be read. The message is short and meant for the user."""


@dataclass(frozen=True)
class InputItem:
    """One value to identify, and where it came from."""

    value: str
    source: str
    """``ARGUMENT_SOURCE``, ``STDIN_SOURCE``, or the path given to ``-f``."""
    position: int
    """1-based argument index, or 1-based line number within ``source``."""


def gather(values: Sequence[str], file: str | None = None) -> Iterator[InputItem] | None:
    """The values to identify, in order, or None if no input was given at all.

    ``file`` is opened here rather than on first iteration, so a missing or
    unreadable file raises ``InputError`` before anything has been yielded.
    Errors while reading raise ``InputError`` during iteration.
    """
    if file is None and not values:
        if not _is_piped(sys.stdin):
            return None
        file = STDIN
    if file is None:
        return _items(values, "", iter(()))
    source, lines = _open_lines(file)
    return _items(values, source, lines)


def _items(values: Sequence[str], source: str, lines: Iterator[str]) -> Iterator[InputItem]:
    for index, value in enumerate(values, start=1):
        yield InputItem(value, ARGUMENT_SOURCE, index)
    try:
        for number, line in enumerate(lines, start=1):
            value = line.strip()
            if value and not value.startswith(_COMMENT):
                yield InputItem(value, source, number)
    except OSError as exc:
        raise InputError(_cannot_read(source, exc)) from exc


def _is_piped(stream: TextIO | None) -> bool:
    """Whether ``stream`` exists and is not a terminal (a pipe or a file)."""
    if stream is None:
        return False
    try:
        return not stream.isatty()
    except (AttributeError, ValueError):  # no isatty, or stream closed
        return False


def _open_lines(file: str) -> tuple[str, Iterator[str]]:
    """``(source name, raw lines)`` for a path, or for stdin if it is ``-``."""
    if file == STDIN:
        stream = sys.stdin
        if stream is None or stream.closed:
            raise InputError("cannot read standard input: it is not available")
        binary = getattr(stream, "buffer", None)
        # A replacement stdin such as io.StringIO has text only, no bytes.
        lines = _text_lines(stream) if binary is None else _decoded_lines(binary)
        return STDIN_SOURCE, lines
    try:
        handle = open(file, "rb")
    except OSError as exc:
        raise InputError(_cannot_read(file, exc)) from exc
    return file, _file_lines(handle)


def _file_lines(handle: BinaryIO) -> Iterator[str]:
    with handle:
        yield from _decoded_lines(handle)


def _text_lines(stream: TextIO) -> Iterator[str]:
    for number, line in enumerate(stream):
        yield line.removeprefix(_TEXT_BOM) if number == 0 else line


def _decoded_lines(binary: BinaryIO) -> Iterator[str]:
    """Decode ``binary`` chunk by chunk and yield its lines, without the ``\\n``."""
    chunk = binary.read(_LONGEST_BOM)
    encoding = "utf-8"
    for bom, bom_encoding in _BOMS:
        if chunk.startswith(bom):
            encoding, chunk = bom_encoding, chunk[len(bom) :]
            break
    decoder = codecs.getincrementaldecoder(encoding)(errors="replace")

    pending = ""
    while True:
        pending += decoder.decode(chunk)
        *complete, pending = pending.split("\n")
        yield from complete
        # read1 returns what is available, so piped lines are not held back
        # until a whole chunk has arrived.
        chunk = binary.read1(_CHUNK_SIZE)
        if not chunk:
            break
    pending += decoder.decode(b"", final=True)
    if pending:
        yield pending


def _cannot_read(source: str, exc: OSError) -> str:
    name = "standard input" if source == STDIN_SOURCE else source
    return f"cannot read {name}: {exc.strerror or exc}"
