# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from azure.cli.core._profile import _SUBSCRIPTION_NAME, _SUBSCRIPTION_ID, _TENANT_DISPLAY_NAME, _TENANT_ID
from knack.log import get_logger

logger = get_logger(__name__)


class SubscriptionSelector:
    DEFAULT_ROW_MARKER = '*'

    def __init__(self, subscriptions, active_one):
        self._subscriptions = subscriptions
        self._active_one = active_one
        self._format_subscription_table()

    def __call__(self):
        print(f'\n[Tenant and subscription selection]\n\n{self._table_str}\n')
        active_one = self._active_one
        tenant_string = self._get_tenant_string(active_one)
        print(f"The default is marked with an {self.DEFAULT_ROW_MARKER}; "
              f"the default tenant is '{tenant_string}' and subscription is "
              f"'{active_one[_SUBSCRIPTION_NAME]}' ({active_one[_SUBSCRIPTION_ID]}).\n")

        from knack.prompting import prompt, NoTTYException

        # Keep prompting until the user inputs a valid index
        while True:
            try:
                select_index = prompt('Select a subscription and tenant (Type a number or Enter for no changes): ')
            except NoTTYException:
                # This is a good example showing interactive and non-TTY are not contradictory
                logger.warning("No TTY to select the default subscription.")
                break

            # Nothing is typed, keep current selection
            if select_index == '':
                break

            if select_index in self._index_to_subscription_map:
                active_one = self._index_to_subscription_map[select_index]
                break

            logger.warning("Invalid selection.")
            # Let retry

        # Echo the selection
        tenant_string = self._get_tenant_string(active_one)

        print(f"\nTenant: {tenant_string}\n"
              f"Subscription: {active_one[_SUBSCRIPTION_NAME]} ({active_one[_SUBSCRIPTION_ID]})\n")
        return active_one

    def _format_subscription_table(self):
        from azure.cli.core.style import format_styled_text, Style
        index_to_subscription_map = {}
        table_data = []

        subscription_name_length_limit = 36

        # Sort by subscription name
        subscriptions_sorted = sorted(self._subscriptions, key=lambda s: s[_SUBSCRIPTION_NAME].lower())

        def highlight_text(text, row_is_default):
            return format_styled_text((Style.HIGHLIGHT, text)) if row_is_default else text

        for index, sub in enumerate(subscriptions_sorted, start=1):
            # There is no need to use int, as int requires parsing. str match is sufficient.
            index_str = str(index)  # '1', '2', ...
            index_to_subscription_map[index_str] = sub

            is_default = sub is self._active_one
            # Trim subscription name if it is too long
            subscription_name = sub[_SUBSCRIPTION_NAME]
            if len(subscription_name) > subscription_name_length_limit:
                subscription_name = subscription_name[:subscription_name_length_limit - 3] + '...'

            row = {
                'No': f'[{index_str}]' + (' ' + self.DEFAULT_ROW_MARKER if is_default else ''),
                'Subscription name': highlight_text(subscription_name, is_default),
                'Subscription ID': highlight_text(sub[_SUBSCRIPTION_ID], is_default),
                'Tenant': highlight_text(self._get_tenant_string(sub), is_default)
            }
            table_data.append(row)

        from tabulate import tabulate
        table_str = tabulate(table_data, headers="keys", tablefmt="simple", disable_numparse=True)

        self._index_to_subscription_map = index_to_subscription_map
        self._table_str = table_str

    @staticmethod
    def _get_tenant_string(subscription):
        try:
            return subscription[_TENANT_DISPLAY_NAME]
        except KeyError:
            return subscription[_TENANT_ID]
