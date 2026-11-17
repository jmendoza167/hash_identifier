"""Deciding whether to emit color, and enabling ANSI on Windows consoles.

Precedence, highest first:

1. ``--color always`` / ``--color never`` (or ``--no-color``).
2. The NO_COLOR environment variable, when set to a non-empty value
   (https://no-color.org): disables color in auto mode.
3. Auto-detection: color only if stdout is a terminal.

On Windows, color also requires turning on virtual terminal processing for
the console (Windows 10+). If that fails, no color is used, so raw escape
codes are never printed to a console that cannot interpret them.
"""

from __future__ import annotations

import io
import sys
from collections.abc import Mapping
from typing import Any, TextIO

COLOR_MODES = ("auto", "always", "never")

ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004


def use_color(mode: str, stream: TextIO, environ: Mapping[str, str]) -> bool:
    """Whether output written to ``stream`` should be colored."""
    if mode == "never":
        return False
    if mode == "always":
        # Not a terminal (e.g. piped into `less -R`): emit codes as asked.
        # A Windows console that cannot do ANSI still gets plain text.
        return enable_windows_ansi(stream) if _isatty(stream) else True
    if environ.get("NO_COLOR"):
        return False
    return _isatty(stream) and enable_windows_ansi(stream)


def is_terminal(stream: TextIO) -> bool:
    """Whether ``stream`` is a terminal, as opposed to a pipe or a file."""
    return _isatty(stream)


def _isatty(stream: TextIO) -> bool:
    try:
        return stream.isatty()
    except (AttributeError, ValueError):  # no isatty, or stream closed
        return False


def enable_windows_ansi(stream: TextIO) -> bool:
    """Make a Windows console interpret ANSI codes; True if it can.

    Always True on other platforms, where terminals handle ANSI natively.
    """
    if sys.platform != "win32":
        return True
    try:
        import ctypes

        handle = _os_handle(stream)
        kernel32 = _kernel32()
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False  # not a console, e.g. a pipe or mintty
        if mode.value & ENABLE_VIRTUAL_TERMINAL_PROCESSING:
            return True
        new_mode = mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return bool(kernel32.SetConsoleMode(handle, new_mode))
    except (AttributeError, OSError, ValueError, io.UnsupportedOperation):
        return False


def _os_handle(stream: TextIO) -> int:
    import msvcrt

    return msvcrt.get_osfhandle(stream.fileno())


def _kernel32() -> Any:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_uint32)]
    kernel32.GetConsoleMode.restype = wintypes.BOOL
    kernel32.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.SetConsoleMode.restype = wintypes.BOOL
    return kernel32
