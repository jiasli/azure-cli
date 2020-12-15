# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from azure.cli.core.style import print_styled_text, Style
from azure.cli.core.decorators import suppress_all_exceptions


@suppress_all_exceptions()
def login_hinter(cli_ctx, result):  # pylint: disable=unused-argument
    selected_account = next(s for s in result if s['isDefault'] is True)
    command_placeholder = '{:40s}'
    selected_sub = [
        (Style.PRIMARY, 'Your default subscription is '),
        (Style.IMPORTANT, '{} {}'.format(selected_account['name'], selected_account['id'])),
    ]
    print_styled_text(selected_sub)
    print_styled_text()

    # TRY
    try_commands = [
        (Style.PRIMARY, 'TRY\n'),
        (Style.PRIMARY, command_placeholder.format('az upgrade')),
        (Style.SECONDARY, 'Upgrade to the latest CLI version in tool\n'),
        (Style.PRIMARY, command_placeholder.format('az account set -s <sub_id or sub_name>')),
        (Style.SECONDARY, 'Set your default subscription account\n'),
        (Style.PRIMARY, command_placeholder.format('az config set output=table')),
        (Style.SECONDARY, 'Set your default output to be in table format\n'),
        (Style.PRIMARY, command_placeholder.format('az feedback')),
        (Style.SECONDARY, 'File us your latest issue encountered\n'),
        (Style.PRIMARY, command_placeholder.format('az next')),
        (Style.SECONDARY, 'Get some ideas on next steps\n'),
    ]
    print_styled_text(try_commands)


@suppress_all_exceptions()
def demo_hint_hinter(cli_ctx, result):  # pylint: disable=unused-argument
    key_placeholder = '{:>25s}'  # right alignment, 25 width
    command_placeholder = '{:40s}'
    projection = [
        (Style.PRIMARY, 'The hinter can parse the output to show a "projection" of the output, like\n\n'),
        (Style.PRIMARY, key_placeholder.format('Subscription name: ')),
        (Style.IMPORTANT, result['name']),
        (Style.PRIMARY, '\n'),
        (Style.PRIMARY, key_placeholder.format('Subscription ID: ')),
        (Style.IMPORTANT, result['id']),
        (Style.PRIMARY, '\n'),
        (Style.PRIMARY, key_placeholder.format('User: ')),
        (Style.IMPORTANT, result['user']['name']),
    ]
    print_styled_text(projection)
    print_styled_text()

    # TRY
    try_commands = [
        (Style.PRIMARY, 'TRY\n'),
        (Style.PRIMARY, command_placeholder.format('az upgrade')),
        (Style.SECONDARY, 'Upgrade to the latest CLI version in tool\n'),
        (Style.PRIMARY, command_placeholder.format('az account set -s <sub_id or sub_name>')),
        (Style.SECONDARY, 'Set your default subscription account\n'),
        (Style.PRIMARY, command_placeholder.format('az config set output=table')),
        (Style.SECONDARY, 'Set your default output to be in table format\n'),
        (Style.PRIMARY, command_placeholder.format('az feedback')),
        (Style.SECONDARY, 'File us your latest issue encountered\n'),
        (Style.PRIMARY, command_placeholder.format('az next')),
        (Style.SECONDARY, 'Get some ideas on next steps\n'),
    ]
    print_styled_text(try_commands)

    hyperlink = [
        (Style.PRIMARY, 'You may also show a hyperlink for more detail: '),
        (Style.HYPERLINK, 'https://docs.microsoft.com/cli/azure/'),
    ]
    print_styled_text(hyperlink)
