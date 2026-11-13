"""Tests for colored output, color selection, and Windows ANSI enabling."""

import ctypes
import io
import sys

import pytest

from hashident import terminal
from hashident.cli import main
from hashident.engine import identify
from hashident.models import Context
from hashident.output import format_result
from hashident.signatures import MD5, SIGNATURES
from hashident.style import ANSI, PLAIN, strip_ansi, visible_len
from hashident.terminal import ENABLE_VIRTUAL_TERMINAL_PROCESSING, enable_windows_ansi, use_color
from hashident.tips import context_tips

ESC = "\x1b["
CONTEXTS = [None, *(c.value for c in Context)]


def run(capsys, *argv):
    main(list(argv))
    return capsys.readouterr().out


@pytest.fixture(autouse=True)
def no_color_env(monkeypatch):
    """Tests start without NO_COLOR, whatever the developer's shell has."""
    monkeypatch.delenv("NO_COLOR", raising=False)


@pytest.fixture
def fake_tty(monkeypatch):
    """Make the CLI believe stdout is a terminal that supports ANSI."""
    monkeypatch.setattr(terminal, "_isatty", lambda stream: True)
    monkeypatch.setattr(terminal, "enable_windows_ansi", lambda stream: True)


# --- CLI flags and NO_COLOR ----------------------------------------------------


def test_captured_output_has_no_ansi_by_default(capsys):
    assert ESC not in run(capsys, MD5.example)


def test_color_always_produces_ansi(capsys):
    assert ESC in run(capsys, "--color", "always", MD5.example)


@pytest.mark.parametrize("flags", [["--no-color"], ["--color", "never"]])
def test_no_color_flags_produce_no_ansi(capsys, fake_tty, flags):
    assert ESC not in run(capsys, *flags, MD5.example)


def test_auto_colors_on_a_terminal(capsys, fake_tty):
    assert ESC in run(capsys, MD5.example)


def test_no_color_env_disables_auto(capsys, fake_tty, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert ESC not in run(capsys, MD5.example)


def test_empty_no_color_env_is_ignored(capsys, fake_tty, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "")
    assert ESC in run(capsys, MD5.example)


def test_color_always_beats_no_color_env(capsys, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert ESC in run(capsys, "--color", "always", MD5.example)


def test_color_and_no_color_together_are_rejected(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--color", "always", "--no-color", MD5.example])
    assert exc_info.value.code == 2


def test_help_documents_color_precedence(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    assert "NO_COLOR" in out
    assert "--color/--no-color, then NO_COLOR, then terminal detection" in " ".join(out.split())
    assert ESC not in out
    assert all(len(line) <= 80 for line in out.splitlines())


# --- Colored layout --------------------------------------------------------------


@pytest.mark.parametrize("sig", SIGNATURES, ids=lambda s: s.name)
@pytest.mark.parametrize("context", CONTEXTS)
def test_colored_output_fits_80_visible_columns(capsys, sig, context):
    argv = ["--color", "always", sig.example]
    if context:
        argv[:0] = ["--from", context]
    out = run(capsys, *argv)

    assert ESC in out
    for line in out.splitlines():
        assert visible_len(line) <= 80, strip_ansi(line)


@pytest.mark.parametrize("sig", SIGNATURES, ids=lambda s: s.name)
@pytest.mark.parametrize("context", CONTEXTS)
def test_stripping_ansi_gives_plain_output(sig, context):
    result = identify(sig.example, context)
    tips = context_tips(result)

    colored = format_result(result, tips, style=ANSI)
    assert strip_ansi(colored) == format_result(result, tips, style=PLAIN)


@pytest.mark.parametrize("raw", ["hello world", ""])
def test_stripping_ansi_gives_plain_no_match_output(raw):
    result = identify(raw)
    assert strip_ansi(format_result(result, style=ANSI)) == format_result(result)


def test_input_cannot_inject_ansi_codes():
    text = format_result(identify("\x1b[31mred"), style=ANSI)
    assert "\x1b[31mred" not in text


def test_color_scheme():
    text = format_result(identify(MD5.example), context_tips(identify(MD5.example)), style=ANSI)

    assert "\x1b[1mMD5\x1b[0m" in text  # format name bold
    assert "\x1b[33mMEDIUM\x1b[0m" in text  # MEDIUM yellow
    assert "\x1b[2mLOW\x1b[0m" in text  # LOW dim
    assert "\x1b[31mWEAK\x1b[0m" in text  # WEAK red
    assert "\x1b[36mhashcat -m 0" in text  # commands cyan
    assert "\x1b[2mTip: " in text  # tips dim
    assert "\x1b[33mNo known hash format" in format_result(identify("zz"), style=ANSI)


def test_plain_styler_is_identity():
    for method in ("name", "command", "muted", "tip", "warning"):
        assert getattr(PLAIN, method)("text") == "text"


# --- use_color decision ---------------------------------------------------------


class Stream(io.StringIO):
    def __init__(self, tty):
        super().__init__()
        self._tty = tty

    def isatty(self):
        return self._tty


@pytest.mark.parametrize(
    ("mode", "tty", "env", "vt_ok", "expected"),
    [
        ("never", True, {}, True, False),
        ("always", False, {"NO_COLOR": "1"}, False, True),  # pipe: codes as asked
        ("always", True, {"NO_COLOR": "1"}, True, True),
        ("always", True, {}, False, False),  # console without ANSI: stay plain
        ("auto", False, {}, True, False),
        ("auto", True, {}, True, True),
        ("auto", True, {"NO_COLOR": "1"}, True, False),
        ("auto", True, {"NO_COLOR": ""}, True, True),
        ("auto", True, {}, False, False),
    ],
)
def test_use_color_precedence(monkeypatch, mode, tty, env, vt_ok, expected):
    monkeypatch.setattr(terminal, "enable_windows_ansi", lambda stream: vt_ok)
    assert use_color(mode, Stream(tty), env) is expected


def test_use_color_handles_closed_stream():
    stream = io.StringIO()
    stream.close()
    assert use_color("auto", stream, {}) is False


# --- Windows VT enabling ---------------------------------------------------------


def _forbid_windows_calls(monkeypatch):
    def boom(*args):
        raise AssertionError("Windows console API must not be called")

    monkeypatch.setattr(terminal, "_os_handle", boom)
    monkeypatch.setattr(terminal, "_kernel32", boom)


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_windows_code_is_skipped_on_other_platforms(monkeypatch, platform):
    monkeypatch.setattr(sys, "platform", platform)
    _forbid_windows_calls(monkeypatch)

    assert enable_windows_ansi(io.StringIO()) is True


def test_real_call_never_raises():
    # On Windows a StringIO has no console handle (False); elsewhere True.
    assert enable_windows_ansi(io.StringIO()) is (sys.platform != "win32")


class FakeKernel32:
    def __init__(self, mode=0x3, get_ok=True, set_ok=True):
        self.mode, self.get_ok, self.set_ok = mode, get_ok, set_ok
        self.set_calls = []

    def GetConsoleMode(self, handle, mode_ref):  # noqa: N802 (Win32 name)
        mode_ref._obj.value = self.mode
        return self.get_ok

    def SetConsoleMode(self, handle, mode):  # noqa: N802
        self.set_calls.append(mode)
        return self.set_ok


@pytest.fixture
def fake_windows(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(terminal, "_os_handle", lambda stream: 42)

    def install(kernel):
        monkeypatch.setattr(terminal, "_kernel32", lambda: kernel)
        return kernel

    return install


def test_windows_enables_virtual_terminal_processing(fake_windows):
    kernel = fake_windows(FakeKernel32(mode=0x3))

    assert enable_windows_ansi(io.StringIO()) is True
    assert kernel.set_calls == [0x3 | ENABLE_VIRTUAL_TERMINAL_PROCESSING]


def test_windows_already_enabled_skips_set(fake_windows):
    kernel = fake_windows(FakeKernel32(mode=ENABLE_VIRTUAL_TERMINAL_PROCESSING))

    assert enable_windows_ansi(io.StringIO()) is True
    assert kernel.set_calls == []


def test_windows_not_a_console_falls_back(fake_windows):
    kernel = fake_windows(FakeKernel32(get_ok=False))

    assert enable_windows_ansi(io.StringIO()) is False
    assert kernel.set_calls == []


def test_windows_set_mode_failure_falls_back(fake_windows):
    fake_windows(FakeKernel32(set_ok=False))
    assert enable_windows_ansi(io.StringIO()) is False


def test_windows_handle_error_falls_back(fake_windows, monkeypatch):
    def no_fileno(stream):
        raise io.UnsupportedOperation("fileno")

    monkeypatch.setattr(terminal, "_os_handle", no_fileno)
    assert enable_windows_ansi(io.StringIO()) is False


@pytest.mark.skipif(sys.platform != "win32", reason="needs the real Windows API")
def test_real_kernel32_has_typed_console_functions():
    kernel = terminal._kernel32()
    assert kernel.GetConsoleMode.argtypes[1] is ctypes.POINTER(ctypes.c_uint32)
