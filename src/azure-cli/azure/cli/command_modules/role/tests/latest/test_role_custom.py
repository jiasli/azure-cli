# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
import unittest
import mock

from azure.cli.command_modules.role.custom import _resolve_role_id, _to_valid_identifier_uri

# pylint: disable=line-too-long


class TestRoleCustomCommands(unittest.TestCase):

    def test_resolve_role_id(self):
        mock_client = mock.Mock()
        mock_client.config.subscription_id = '123'
        test_role_id = 'b24988ac-6180-42a0-ab88-20f738123456'

        # action(using a logical name)
        result = _resolve_role_id(test_role_id, 'foobar', mock_client)

        # assert
        self.assertEqual('/subscriptions/123/providers/Microsoft.Authorization/roleDefinitions/{}'.format(test_role_id), result)

        # action (using a full id)
        test_full_id = '/subscriptions/0b1f6471-1bf0-4dda-aec3-cb9272123456/providers/microsoft.authorization/roleDefinitions/5370bbf4-6b73-4417-969b-8f2e6e123456'
        self.assertEqual(test_full_id, _resolve_role_id(test_full_id, 'foobar', mock_client))

    def test_to_valid_identifier_uri(self):
        domain = "myorg.onmicrosoft.com"

        # name provided as old URL
        assert _to_valid_identifier_uri("http://myapp", domain) == ("http://myapp", "myapp")

        # name provided as verified domain URL
        assert _to_valid_identifier_uri("https://myorg.onmicrosoft.com/myapp", domain) == ("https://myorg.onmicrosoft.com/myapp", "myapp")

        # name provided as display name
        assert _to_valid_identifier_uri("myapp", domain) == ("https://myorg.onmicrosoft.com/myapp", "myapp")

        # name not provided
        identifier_uri, display_name = _to_valid_identifier_uri(None, domain)
        assert identifier_uri.startswith("https://myorg.onmicrosoft.com/azure-cli-")
        assert display_name.startswith("azure-cli-")
