#!/usr/bin/env python3

"""
A fun little script to work with Morse code.  Inspired by the following
Mastodon post:

    Lennart Poettering
    @pid_eins@mastodon.social
    Nov 03, 2023, 05:03

    Did you know you could control brightness of the red dot on the i of the
    "ThinkPad" on the top-side of your thinkpad? I sure didn't:

    this turns it off:

    echo 0 | sudo tee /sys/class/leds/tpacpi\:\:lid_logo_dot/brightness

    and this turns it on:

    echo 255 | sudo tee /sys/class/leds/tpacpi\:\:lid_logo_dot/brightness

    I don't really know what this information is good for, but hey, isn't it
    awesome to have a 1px display on the outside of your laptop?
"""

import argparse
import asyncio
import enum
import textwrap

from typing import Awaitable, Callable, Sequence


@enum.unique
class Symbol(enum.Enum):
    DOT = "."
    DASH = "-"

    def time_units(self) -> int:
        return 1 if self == Symbol.DOT else 3


Dot = Symbol.DOT
Dash = Symbol.DASH

Char = Sequence[Symbol]
Word = Sequence[Char]
Text = Sequence[Word]


LETTER_MAP: Sequence[Char] = (
    (Dot, Dash),
    (Dash, Dot, Dot, Dot),
    (Dash, Dot, Dash, Dot),
    (Dash, Dot, Dot),
    (Dot,),
    (Dot, Dot, Dash, Dot),
    (Dash, Dash, Dot),
    (Dot, Dot, Dot, Dot),
    (Dot, Dot),
    (Dot, Dash, Dash, Dash),
    (Dash, Dot, Dash),
    (Dot, Dash, Dot, Dot),
    (Dash, Dash),
    (Dash, Dot),
    (Dash, Dash, Dash),
    (Dot, Dash, Dash, Dot),
    (Dash, Dash, Dot, Dash),
    (Dot, Dash, Dot),
    (Dot, Dot, Dot),
    (Dash,),
    (Dot, Dot, Dash),
    (Dot, Dot, Dot, Dash),
    (Dot, Dash, Dash),
    (Dash, Dot, Dot, Dash),
    (Dash, Dot, Dash, Dash),
    (Dash, Dash, Dot, Dot),
)


NUMBER_MAP: Sequence[Char] = (
    (Dash, Dash, Dash, Dash, Dash),
    (Dot, Dash, Dash, Dash, Dash),
    (Dot, Dot, Dash, Dash, Dash),
    (Dot, Dot, Dot, Dash, Dash),
    (Dot, Dot, Dot, Dot, Dash),
    (Dot, Dot, Dot, Dot, Dot),
    (Dash, Dot, Dot, Dot, Dot),
    (Dash, Dash, Dot, Dot, Dot),
    (Dash, Dash, Dash, Dot, Dot),
    (Dash, Dash, Dash, Dash, Dot),
)


def digit_to_morse(n: int) -> Char:
    """Convert an integer digit into Morse code."""
    if n < 0 or n > 9:
        raise ValueError(f"digit_to_morse: Invalid digit '{n}'")
    return NUMBER_MAP[n]


def letter_to_morse(c: str) -> Char:
    """Convert an ASCII alphabetical letter into Morse code."""
    if len(c) != 1 or not c.isascii() or not c.isalpha():
        raise ValueError(f"letter_to_morse: Invalid letter '{c}'")
    return LETTER_MAP[ord(c.upper()) - ord("A")]


def char_to_morse(c: str) -> Char:
    """Convert an ASCII character into Morse code."""
    return digit_to_morse(ord(c) - ord("0")) if c.isdigit() else letter_to_morse(c)


def word_to_morse(s: str) -> Word:
    """
    Convert a word (multiple ASCII characters without whitespace) to Morse code.
    """
    return [char_to_morse(c) for c in s]


def text_to_morse(s: str) -> Text:
    """Convert ASCII text to Morse code."""
    return [word_to_morse(word) for word in s.split()]


def set_thinkpad_led(on: bool) -> None:
    """Turn the Thinkpad LED on or off."""
    # TODO: Ideally this would be asyncio too but that requires threads.
    value = "255" if on else "0"
    with open("/sys/class/leds/tpacpi::lid_logo_dot/brightness", "w") as led:
        led.write(value)


async def display_thinkpad_symbol(symbol: Symbol, time_unit_ms: int) -> None:
    """Display a Morse code symbol on the Thinkpad LED."""
    time_unit_s = time_unit_ms / 1000
    set_thinkpad_led(True)
    await asyncio.sleep(symbol.time_units() * time_unit_s)
    set_thinkpad_led(False)


async def print_symbol(symbol: Symbol, time_unit_ms: int) -> None:
    """Print a Morse code symbol to stdout."""
    time_unit_s = time_unit_ms / 1000
    print(symbol.value)
    await asyncio.sleep(symbol.time_units() * time_unit_s)


async def process_morse(
    fn: Callable[[Symbol, int], Awaitable[None]], text: Text, time_unit_ms: int
) -> None:
    """
    Process text represented by Morse code.  The processing function is given a
    Morse code symbol at a time, along with the number of milliseconds that
    make up a Morse code time unit.
    """
    time_unit_s = time_unit_ms / 1000

    for word in text:
        for char in word:
            for symbol in char:
                await fn(symbol, time_unit_ms)
                await asyncio.sleep(time_unit_s)
            await asyncio.sleep(3 * time_unit_s)
        await asyncio.sleep(7 * time_unit_s)


def get_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="morse_code.py",
        description="""
        Converts text into Morse code.

        The default behavior is to print to the screen, but it can
        optionally be displayed via the Thinkpad LED.
        """,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--thinkpad-led",
        action="store_true",
        help="Display Morse code on the machine's Thinkpad LED",
    )
    parser.add_argument(
        "--time-unit-ms",
        default=500,
        type=int,
        help="The duration of a Morse code time unit in milliseconds",
    )
    parser.add_argument(
        "text",
        nargs="+",
        help="Text to convert into Morse code",
    )
    return parser.parse_args()


async def main() -> None:
    args = get_args()
    fn = display_thinkpad_symbol if args.thinkpad_led else print_symbol
    for text in args.text:
        await process_morse(fn, text_to_morse(text), args.time_unit_ms)


if __name__ == "__main__":
    asyncio.run(main())
