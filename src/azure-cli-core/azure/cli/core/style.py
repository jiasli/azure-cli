# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

"""
Support styled output.

Currently, only color is supported, underline/bold/italic may be supported in the future.

Design spec:
https://devdivdesignguide.azurewebsites.net/command-line-interface/color-guidelines-for-command-line-interface/

For a complete demo, see `src/azure-cli/azure/cli/command_modules/util/custom.py` and run `az demo style`.
"""

import re
from enum import Enum
from colorama import Fore

current_color = None


class Style(str, Enum):
    PRIMARY = "primary"
    SECONDARY = "secondary"
    IMPORTANT = "important"
    ACTION = "action"
    HYPERLINK = "hyperlink"
    # Message colors
    ERROR = "error"
    SUCCESS = "success"
    WARNING = "warning"
    # reserved
    HINT = "hint"
    STATUS = "status"
    COMMAND = "command"
    COMMAND_NAME = "command_name"
    COMMAND_PARAM = "command_param"


THEME = {
    # Style to ANSI escape sequence mapping
    # https://docs.microsoft.com/en-us/windows/console/console-virtual-terminal-sequences
    Style.PRIMARY: Fore.LIGHTWHITE_EX,
    Style.SECONDARY: Fore.LIGHTBLACK_EX,  # may use WHITE, but will lose contrast to LIGHTWHITE_EX
    Style.IMPORTANT: Fore.LIGHTMAGENTA_EX,
    Style.ACTION: Fore.LIGHTBLUE_EX,
    Style.HYPERLINK: Fore.LIGHTCYAN_EX,
    # Message colors
    Style.ERROR: Fore.LIGHTRED_EX,
    Style.SUCCESS: Fore.LIGHTGREEN_EX,
    Style.WARNING: Fore.LIGHTYELLOW_EX,
    # reserved
    Style.HINT: Fore.WHITE,
    Style.STATUS: Fore.LIGHTGREEN_EX,
    Style.COMMAND: Fore.LIGHTWHITE_EX,
    Style.COMMAND_NAME: Fore.BLUE,
    Style.COMMAND_PARAM: Fore.LIGHTBLUE_EX,
}


# unused
def highlight_command(cmd):
    # az account list --output table
    # Replace 'az account list '
    cmd = re.sub(r"^([^-]+)", THEME[Style.COMMAND_NAME] + r"\1" + THEME[Style.COMMAND], cmd)
    # Replace '--output'
    cmd = re.sub(r"(-[^\s]+)", THEME[Style.COMMAND_PARAM] + r"\1" + THEME[Style.COMMAND], cmd)
    return '`' + THEME[Style.COMMAND] + cmd + THEME[Style.PRIMARY_TEXT] + '`'


# unused
def print_with_color(message_type, text, highlight_hyperlinks=True):
    link_regex = r"http[^\s,.]+"
    # ** ** quoted text is marked as IMPORTANT
    text = re.sub(r"\*\*(.+?)\*\*", THEME[Style.IMPORTANT_TEXT] + r"\1" + THEME[Style.PRIMARY_TEXT], text)
    color_seq = THEME[message_type]
    print(color_seq + text + Fore.RESET)


def print_styled_text(styled):
    formatted = format_styled_text(styled)
    import sys
    print(formatted, file=sys.stderr)


def format_styled_text(styled_text):
    # https://python-prompt-toolkit.readthedocs.io/en/stable/pages/printing_text.html#style-text-tuples
    formatted_parts = []
    for text in styled_text:
        formatted_parts.append(THEME[text[0]] + text[1])
    formatted_parts.append(Fore.RESET)
    return ''.join(formatted_parts)
