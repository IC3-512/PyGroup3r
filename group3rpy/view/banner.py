"""Port of Group3r/View/Banner.cs.

Class for printing the all important ASCII art.

PORT NOTE: `Console.ForegroundColor` / `Console.ResetColor` are Windows console
APIs; they become ANSI SGR escapes here, written straight to stdout in the same
order and in the same chunks as the original writes them.
"""

import sys
from enum import Enum


class ConsoleColor(Enum):
    """PORT NOTE: the subset of System.ConsoleColor the banner uses, mapped to
    the ANSI foreground code with the same appearance on a default terminal."""

    Black = 30
    DarkBlue = 34
    DarkRed = 31
    DarkGray = 90
    Gray = 37
    Blue = 94
    Green = 92
    Cyan = 96
    Red = 91
    Magenta = 95
    Yellow = 93
    White = 97


_RESET = "\x1b[0m"


def _write_color(text_to_write: str, fg_color: ConsoleColor) -> None:
    sys.stdout.write("\x1b[" + str(fg_color.value) + "m")

    sys.stdout.write(text_to_write)

    sys.stdout.write(_RESET)


def _write_color_line(text_to_write: str, fg_color: ConsoleColor) -> None:
    sys.stdout.write("\x1b[" + str(fg_color.value) + "m")

    sys.stdout.write(text_to_write + "\r\n")

    sys.stdout.write(_RESET)


def print_banner() -> None:
    barf_lines = [
        '  .,-:::::/ :::::::..       ...      ...    :::::::::::::.  .::.   :::::::..  ',
        ",;;-'````'  ;;;;``;;;;   .;;;;;;;.   ;;     ;;; `;;;```.;;;;'`';;, ;;;;``;;;; ",
        "[[[   [[[[[[/[[[,/[[['  ,[[     \\[[,[['     [[[  `]]nnn]]'    .n[[  [[[,/[[[' ",
        "'$$c.    '$$ $$$$$$c    $$$,     $$$$$      $$$   $$$''      ``'$$$ $$$$$$c   ",
        " `Y8bo,,,o88o888b '88bo,'888,_ _,88P88    .d888   888o       ,,o888 888b'''8b,",
        "   `'YMUP'YMMMMMM  'W'   'YMMMMMP'  'YmmMMMM''   YMMMb      YMMP'  MMMM   'WM;",
        '                                                    github.com/Group3r/Group3r',
        '                                                            @mikeloss         ',
        '                                                                              ',
        'Gaze not into the abyss, lest you become recognized as an abyss domain expert,',
        'and they expect you keep gazing into the damn thing... - @nickm_tor           '
    ]

    pattern_one = [
        ConsoleColor.White,
        ConsoleColor.Yellow,
        ConsoleColor.Red,
        ConsoleColor.Red,
        ConsoleColor.DarkRed,
        ConsoleColor.DarkRed,
        ConsoleColor.White,
        ConsoleColor.White,
        ConsoleColor.White,
        ConsoleColor.White,
    ]

    pattern_two = [
        ConsoleColor.White,
        ConsoleColor.White,
        ConsoleColor.White,
        ConsoleColor.Cyan,
        ConsoleColor.Blue,
        ConsoleColor.DarkBlue,
        ConsoleColor.White,
        ConsoleColor.White,
        ConsoleColor.White,
        ConsoleColor.White,
    ]

    i = 0
    for barf_line in barf_lines:
        if i <= 7:
            barf_one = barf_line
            _write_color(barf_one[0:59], pattern_one[i])
            _write_color(barf_one[59 : 59 + 8], pattern_two[i])
            _write_color(barf_one[67 : 67 + 11] + "\r\n", pattern_one[i])
        else:
            _write_color_line(barf_line, ConsoleColor.Green)
        i += 1

    sys.stdout.write("\r\n" + "\r\n")


class Banner:
    """Static class in the C#; kept so call sites read like the original."""

    print_banner = staticmethod(print_banner)
