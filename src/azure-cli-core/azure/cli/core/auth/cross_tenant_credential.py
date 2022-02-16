# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

"""
Credentials defined in this module are alternative implementations of credentials provided by Azure Identity.

These credentials implements azure.core.credentials.TokenCredential by exposing get_token method for Track 2
SDK invocation.
"""

from knack.log import get_logger
from knack.util import CLIError
from msal import PublicClientApplication, ConfidentialClientApplication

from .util import check_result, AccessToken

# OAuth 2.0 client credentials flow parameter
# https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow
_TENANT = 'tenant'
_CLIENT_ID = 'client_id'
_CLIENT_SECRET = 'client_secret'
_CERTIFICATE = 'certificate'
_CLIENT_ASSERTION = 'client_assertion'
_USE_CERT_SN_ISSUER = 'use_cert_sn_issuer'

logger = get_logger(__name__)


class CrossTenantCredential:

    def __init__(self, get_raw_token_callback, **kwargs):
        """User credential implementing get_token interface.

        :param client_id: Client ID of the CLI.
        :param username: The username for user credential.
        """
        super().__init__(**kwargs)
        self._get_raw_token_callback = get_raw_token_callback

    def get_token(self, *scopes, **kwargs):
        logger.debug("CrossTenantCredential.get_token: scopes=%r, kwargs=%r", scopes, kwargs)
        tenant_id = kwargs.pop('tenant_id', None)
        result = self._get_raw_token_callback(scopes=scopes, tenant=tenant_id)
        return result
