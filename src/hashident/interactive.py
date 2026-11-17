"""Interactive mode: a ``HASH:`` prompt that identifies each line entered.

Started by the command line when there is no input at all and standard
input is a terminal. The loop ends on an empty line, Ctrl+C or end of input
(Ctrl+D, or Ctrl+Z then Enter on Windows), and says goodbye.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

PROMPT = "HASH: "
GOODBYE = "Bye!"
HOW_TO_QUIT = "Enter a hash to identify it. An empty line or Ctrl+C quits."


def run(
    render: Callable[[str], str],
    *,
    intro: Sequence[str] = (),
    read: Callable[[str], str] | None = None,
) -> None:
    """Print ``intro``, then prompt until the user quits.

    ``render`` turns one entered line into the text to print for it.
    ``read`` shows a prompt and returns the line typed; it defaults to the
    built-in ``input``, looked up on each call.
    """
    read_line = input if read is None else read
    for line in intro:
        print(line)
    while True:
        try:
            entered = read_line(PROMPT)
        except (EOFError, KeyboardInterrupt):
            print()  # finish the prompt line the cursor was left on
            break
        if not entered.strip():
            break
        print()
        print(render(entered))
        print()
    print(GOODBYE)
