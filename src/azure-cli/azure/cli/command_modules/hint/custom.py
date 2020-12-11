# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from azure.cli.core.style import print_styled_text, Style


def login_hinter(cli_ctx, result):  # pylint: disable=unused-argument
    selected_account = next(s for s in result if s['isDefault'] is True)
    command_placeholder = '{:30s}'
    hint = [
        (Style.PRIMARY, 'Your default subscription is '),
        (Style.IMPORTANT, '{} {}'.format(selected_account['name'], selected_account['id'])),
        (Style.PRIMARY, '\n\n'),
        (Style.PRIMARY, 'TRY\n'),
        (Style.PRIMARY, command_placeholder.format('az account set <X>')),
        (Style.SECONDARY, 'Set your default subscription account\n'),
        (Style.PRIMARY, command_placeholder.format('az config set output=table')),
        (Style.SECONDARY, 'Set your default output to be in table format\n'),
        (Style.PRIMARY, command_placeholder.format('az feedback')),
        (Style.SECONDARY, 'File us your latest issue encountered\n'),
        (Style.PRIMARY, command_placeholder.format('az next')),
        (Style.SECONDARY, 'Get some ideas on next steps\n'),
        (Style.PRIMARY, command_placeholder.format('az upgrade')),
        (Style.SECONDARY, 'Set your default subscription account'),
    ]
    print_styled_text(hint)


def demo_hint_hinter(cli_ctx, result):  # pylint: disable=unused-argument
    key_placeholder = '{:>25s}'  # right alignment, 25 width
    command_placeholder = '{:30s}'
    hint = [
        (Style.PRIMARY, 'The hinter can parse the output to show a "projection" of the output, like\n\n'),
        (Style.PRIMARY, key_placeholder.format('Subscription name: ')),
        (Style.IMPORTANT, result['name']),
        (Style.PRIMARY, '\n'),
        (Style.PRIMARY, key_placeholder.format('Subscription ID: ')),
        (Style.IMPORTANT, result['id']),
        (Style.PRIMARY, '\n'),
        (Style.PRIMARY, key_placeholder.format('User: ')),
        (Style.IMPORTANT, result['user']['name']),
        (Style.PRIMARY, '\n\n'),
        (Style.PRIMARY, 'You may then instruct the user to run additional commands:\n\n'),
        (Style.PRIMARY, command_placeholder.format('az account set <X>')),
        (Style.SECONDARY, 'Set your default subscription account\n'),
        (Style.PRIMARY, command_placeholder.format('az config set output=table')),
        (Style.SECONDARY, 'Set your default output to be in table format\n'),
        (Style.PRIMARY, command_placeholder.format('az feedback')),
        (Style.SECONDARY, 'File us your latest issue encountered\n'),
        (Style.PRIMARY, command_placeholder.format('az next')),
        (Style.SECONDARY, 'Get some ideas on next steps\n'),
        (Style.PRIMARY, command_placeholder.format('az upgrade')),
        (Style.SECONDARY, 'Set your default subscription account'),
        (Style.PRIMARY, '\n\n'),
        (Style.PRIMARY, 'You may also show a hyperlink for more detail: '),
        (Style.HYPERLINK, 'https://docs.microsoft.com/cli/azure/'),
    ]
    print_styled_text(hint)
