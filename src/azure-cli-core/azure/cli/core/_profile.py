# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from __future__ import print_function

import collections
import errno
import json
import os
import os.path
import re
import string
from copy import deepcopy
from enum import Enum
from six.moves import BaseHTTPServer

from azure.cli.core._environment import get_config_dir
from azure.cli.core._session import ACCOUNT
from azure.cli.core.util import get_file_json, in_cloud_console, open_page_in_browser, can_launch_browser,\
    is_windows, is_wsl
from azure.cli.core.cloud import get_active_cloud, set_cloud_subscription

from knack.log import get_logger
from knack.util import CLIError

logger = get_logger(__name__)

# Names below are used by azure-xplat-cli to persist account information into
# ~/.azure/azureProfile.json or osx/keychainer or windows secure storage,
# which azure-cli will share.
# Please do not rename them unless you know what you are doing.
_IS_DEFAULT_SUBSCRIPTION = 'isDefault'
_SUBSCRIPTION_ID = 'id'
_SUBSCRIPTION_NAME = 'name'
# Tenant of the token which is used to list the subscription
_TENANT_ID = 'tenantId'
# Home tenant of the subscription, which maps to tenantId in 'Subscriptions - List REST API'
# https://docs.microsoft.com/en-us/rest/api/resources/subscriptions/list
_HOME_TENANT_ID = 'homeTenantId'
_MANAGED_BY_TENANTS = 'managedByTenants'
_USER_ENTITY = 'user'
_USER_NAME = 'name'
_USER_HOME_ACCOUNT_ID = 'homeAccountId'
_CLOUD_SHELL_ID = 'cloudShellID'
_SUBSCRIPTIONS = 'subscriptions'
_INSTALLATION_ID = 'installationId'
_ENVIRONMENT_NAME = 'environmentName'
_STATE = 'state'
_USER_TYPE = 'type'
_USER = 'user'
_SERVICE_PRINCIPAL = 'servicePrincipal'
_SERVICE_PRINCIPAL_ID = 'servicePrincipalId'
_SERVICE_PRINCIPAL_SECRET = 'servicePrincipalSecret'
_SERVICE_PRINCIPAL_TENANT = 'servicePrincipalTenant'
_SERVICE_PRINCIPAL_CERT_FILE = 'certificateFile'
_SERVICE_PRINCIPAL_CERT_THUMBPRINT = 'thumbprint'
_SERVICE_PRINCIPAL_CERT_SN_ISSUER_AUTH = 'useCertSNIssuerAuth'
_TOKEN_ENTRY_USER_ID = 'userId'
_TOKEN_ENTRY_TOKEN_TYPE = 'tokenType'
# This could mean either real access token, or client secret of a service principal
# This naming is no good, but can't change because xplat-cli does so.
_ACCESS_TOKEN = 'accessToken'
_REFRESH_TOKEN = 'refreshToken'

TOKEN_FIELDS_EXCLUDED_FROM_PERSISTENCE = ['familyName',
                                          'givenName',
                                          'isUserIdDisplayable',
                                          'tenantId']

_CLIENT_ID = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
_COMMON_TENANT = 'common'

_TENANT_LEVEL_ACCOUNT_NAME = 'N/A(tenant level account)'

_SYSTEM_ASSIGNED_IDENTITY = 'systemAssignedIdentity'
_USER_ASSIGNED_IDENTITY = 'userAssignedIdentity'
_ASSIGNED_IDENTITY_INFO = 'assignedIdentityInfo'

_AZ_LOGIN_MESSAGE = "Please run 'az login' to setup account."


def load_subscriptions(cli_ctx, all_clouds=False, refresh=False):
    profile = Profile(cli_ctx=cli_ctx)
    if refresh:
        profile.refresh_accounts()
    subscriptions = profile.load_cached_subscriptions(all_clouds)
    return subscriptions


def _get_authority_url(cli_ctx, tenant):
    authority_url = cli_ctx.cloud.endpoints.active_directory
    is_adfs = bool(re.match('.+(/adfs|/adfs/)$', authority_url, re.I))
    if is_adfs:
        authority_url = authority_url.rstrip('/')  # workaround: ADAL is known to reject auth urls with trailing /
    else:
        authority_url = authority_url.rstrip('/') + '/' + (tenant or _COMMON_TENANT)
    return authority_url, is_adfs


def _authentication_context_factory(cli_ctx, tenant, cache):
    import adal
    authority_url, is_adfs = _get_authority_url(cli_ctx, tenant)
    return adal.AuthenticationContext(authority_url, cache=cache, api_version=None, validate_authority=(not is_adfs))


def _msal_authentication_context_factory(cli_ctx, tenant, cache):
    #import MSAL
    authority_url, is_adfs = _get_authority_url(cli_ctx, tenant)
    return adal.AuthenticationContext(authority_url, cache=cache, api_version=None, validate_authority=(not is_adfs))

_AUTH_CTX_FACTORY = _authentication_context_factory


def _load_tokens_from_file(file_path):
    if os.path.isfile(file_path):
        try:
            return get_file_json(file_path, throw_on_empty=False) or []
        except (CLIError, ValueError) as ex:
            raise CLIError("Failed to load token files. If you have a repro, please log an issue at "
                           "https://github.com/Azure/azure-cli/issues. At the same time, you can clean "
                           "up by running 'az account clear' and then 'az login'. (Inner Error: {})".format(ex))
    return []


def _delete_file(file_path):
    try:
        os.remove(file_path)
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise


def get_credential_types(cli_ctx):

    class CredentialType(Enum):  # pylint: disable=too-few-public-methods
        cloud = get_active_cloud(cli_ctx)
        management = cli_ctx.cloud.endpoints.management
        rbac = cli_ctx.cloud.endpoints.active_directory_graph_resource_id

    return CredentialType


def _get_cloud_console_token_endpoint():
    return os.environ.get('MSI_ENDPOINT')


# pylint: disable=too-many-lines,too-many-instance-attributes
class Profile(object):
    _global_creds_cache = None

    def __init__(self, storage=None, auth_ctx_factory=None, use_global_creds_cache=True,
                 async_persist=True, cli_ctx=None):
        from azure.cli.core import get_default_cli

        self.cli_ctx = cli_ctx or get_default_cli()
        self._storage = storage or ACCOUNT
        self.auth_ctx_factory = auth_ctx_factory or _AUTH_CTX_FACTORY

        if use_global_creds_cache:
            # for perf, use global cache
            if not Profile._global_creds_cache:
                Profile._global_creds_cache = CredsCache(self.cli_ctx, self.auth_ctx_factory,
                                                         async_persist=async_persist)
            self._creds_cache = Profile._global_creds_cache
        else:
            self._creds_cache = CredsCache(self.cli_ctx, self.auth_ctx_factory, async_persist=async_persist)

        self._management_resource_uri = self.cli_ctx.cloud.endpoints.management
        self._ad_resource_uri = self.cli_ctx.cloud.endpoints.active_directory_resource_id
        self._msal_scope = self.cli_ctx.cloud.endpoints.active_directory_resource_id + '/.default'
        self._ad = self.cli_ctx.cloud.endpoints.active_directory
        self._msi_creds = None

    def login(self,
              interactive,
              username,
              password,
              is_service_principal,
              tenant,
              use_device_code=False,
              allow_no_subscriptions=False,
              subscription_finder=None,
              use_cert_sn_issuer=None,
              find_subscriptions=True):
        # TODO: allow disabling SSL verification in MSAL
        from azure.cli.core._debug import allow_debug_adal_connection
        allow_debug_adal_connection()

        credential=None
        auth_profile=None

        if not subscription_finder:
            subscription_finder = SubscriptionFinder(self.cli_ctx,
                                                     self.auth_ctx_factory,
                                                     self._creds_cache.adal_token_cache)
        if interactive:
            if not use_device_code and (in_cloud_console() or not can_launch_browser()):
                logger.info('Detect no GUI is available, so fall back to device code')
                use_device_code = True

            if not use_device_code:
                from azure.identity import CredentialUnavailableError
                try:
                    credential, auth_profile = self.login_with_interactive_browser(tenant)
                except CredentialUnavailableError:
                    use_device_code = True
                    logger.warning('Not able to launch a browser to log you in, falling back to device code...')

            if use_device_code:
                credential, auth_profile = self.login_with_device_code(tenant)
        else:
            if is_service_principal:
                if not tenant:
                    raise CLIError('Please supply tenant using "--tenant"')
                sp_auth = ServicePrincipalAuth(password, use_cert_sn_issuer)
                credential = self.login_with_service_principal_secret(username, password, tenant)
            else:
                credential, auth_profile = self.login_with_username_password(username, password, tenant)

        # List tenants and find subscriptions by calling ARM
        subscriptions = []
        if find_subscriptions:
            if tenant and credential:
                subscriptions = subscription_finder.find_using_specific_tenant(tenant, credential)
            elif credential and auth_profile:
                subscriptions = subscription_finder.find_using_common_tenant(auth_profile, credential)
            if not allow_no_subscriptions and not subscriptions:
                if username:
                    msg = "No subscriptions found for {}.".format(username)
                else:
                    # Don't show username if bare 'az login' is used
                    msg = "No subscriptions found."
                raise CLIError(msg)

            if is_service_principal:
                self._creds_cache.save_service_principal_cred(sp_auth.get_entry_to_persist(username,
                                                                                           tenant))
            if self._creds_cache.adal_token_cache.has_state_changed:
                self._creds_cache.persist_cached_creds()

            if allow_no_subscriptions:
                t_list = [s.tenant_id for s in subscriptions]
                bare_tenants = [t for t in subscription_finder.tenants if t not in t_list]
                profile = Profile(cli_ctx=self.cli_ctx)
                tenant_accounts = profile._build_tenant_level_accounts(bare_tenants)  # pylint: disable=protected-access
                subscriptions.extend(tenant_accounts)
                if not subscriptions:
                    return []
        else:
            bare_tenant = tenant or auth_profile.tenant_id
            subscriptions = self._build_tenant_level_accounts([bare_tenant])

        consolidated = self._normalize_properties(auth_profile.username, subscriptions,
                                                  is_service_principal, bool(use_cert_sn_issuer),
                                                  home_account_id=auth_profile.home_account_id)

        self._set_subscriptions(consolidated)
        # use deepcopy as we don't want to persist these changes to file.
        return deepcopy(consolidated)

    def login_with_interactive_browser(self, tenant):
        # InteractiveBrowserCredential
        from azure.identity import AuthenticationRequiredError, InteractiveBrowserCredential
        if tenant:
            credential, auth_profile = InteractiveBrowserCredential.authenticate(
                client_id=_CLIENT_ID,
                silent_auth_only=True,
                scope=self._msal_scope,
                tenant_id=tenant
            )
        else:
            credential, auth_profile = InteractiveBrowserCredential.authenticate(
                client_id=_CLIENT_ID,
                silent_auth_only=True,
                scope=self._msal_scope
            )
        return credential, auth_profile

    def login_with_device_code(self, tenant):
        from azure.identity import AuthenticationRequiredError, DeviceCodeCredential
        message = 'To sign in, use a web browser to open the page {} and enter the code {} to authenticate.'
        prompt_callback=lambda verification_uri, user_code, expires_on: \
            logger.warning(message.format(verification_uri, user_code))
        if tenant:
            cred, auth_profile = DeviceCodeCredential.authenticate(client_id=_CLIENT_ID,
                                                                   scope=self._msal_scope,
                                                                   tenant_id=tenant,
                                                                   prompt_callback=prompt_callback)
        else:
            cred, auth_profile = DeviceCodeCredential.authenticate(client_id=_CLIENT_ID,
                                                                   scope=self._msal_scope,
                                                                   prompt_callback=prompt_callback)
        return cred, auth_profile

    def login_with_username_password(self, username, password, tenant):
        from azure.identity import AuthenticationRequiredError, UsernamePasswordCredential, AuthProfile
        if tenant:
            credential, auth_profile = UsernamePasswordCredential.authenticate(_CLIENT_ID, username, password,
                                                                               tenant_id=tenant,
                                                                               scope=self._msal_scope)
        else:
            credential, auth_profile = UsernamePasswordCredential.authenticate(_CLIENT_ID, username, password,
                                                                               scope=self._msal_scope)
        return credential, auth_profile

    def login_with_service_principal_secret(self, client_id, client_secret, tenant):
        # ClientSecretCredential
        from azure.identity import AuthenticationRequiredError, ClientSecretCredential
        credential = ClientSecretCredential(tenant, client_id, client_secret)

        entry = {
            _SERVICE_PRINCIPAL_ID: client_id,
            _ACCESS_TOKEN: client_secret,
            _SERVICE_PRINCIPAL_TENANT: tenant,
        }
        self._creds_cache.save_service_principal_cred(entry)
        return credential

    def login_with_service_principal_certificate(self):
        # CertificateCredential
        pass

    def login_with_msi(self):
        # ManagedIdentityCredential
        pass

    def _normalize_properties(self, user, subscriptions, is_service_principal, cert_sn_issuer_auth=None,
                              user_assigned_identity_id=None, home_account_id=None):
        import sys
        consolidated = []
        for s in subscriptions:
            display_name = s.display_name
            if display_name is None:
                display_name = ''
            try:
                display_name.encode(sys.getdefaultencoding())
            except (UnicodeEncodeError, UnicodeDecodeError):  # mainly for Python 2.7 with ascii as the default encoding
                display_name = re.sub(r'[^\x00-\x7f]', lambda x: '?', display_name)

            subscription_dict = {
                _SUBSCRIPTION_ID: s.id.rpartition('/')[2],
                _SUBSCRIPTION_NAME: display_name,
                _STATE: s.state.value,
                _USER_ENTITY: {
                    _USER_NAME: user,
                    _USER_TYPE: _SERVICE_PRINCIPAL if is_service_principal else _USER,
                    _USER_HOME_ACCOUNT_ID: home_account_id
                },
                _IS_DEFAULT_SUBSCRIPTION: False,
                _TENANT_ID: s.tenant_id,
                _ENVIRONMENT_NAME: self.cli_ctx.cloud.name
            }
            # for Subscriptions - List REST API 2019-06-01's subscription account
            if subscription_dict[_SUBSCRIPTION_NAME] != _TENANT_LEVEL_ACCOUNT_NAME:
                if hasattr(s, 'home_tenant_id'):
                    subscription_dict[_HOME_TENANT_ID] = s.home_tenant_id
                if hasattr(s, 'managed_by_tenants'):
                    subscription_dict[_MANAGED_BY_TENANTS] = [{_TENANT_ID: t.tenant_id} for t in s.managed_by_tenants]

            consolidated.append(subscription_dict)

            if cert_sn_issuer_auth:
                consolidated[-1][_USER_ENTITY][_SERVICE_PRINCIPAL_CERT_SN_ISSUER_AUTH] = True
            if user_assigned_identity_id:
                consolidated[-1][_USER_ENTITY][_ASSIGNED_IDENTITY_INFO] = user_assigned_identity_id
        return consolidated

    def _build_tenant_level_accounts(self, tenants):
        result = []
        for t in tenants:
            s = self._new_account()
            s.id = '/subscriptions/' + t
            s.subscription = t
            s.tenant_id = t
            s.display_name = _TENANT_LEVEL_ACCOUNT_NAME
            result.append(s)
        return result

    def _new_account(self):
        from azure.cli.core.profiles import ResourceType, get_sdk
        SubscriptionType, StateType = get_sdk(self.cli_ctx, ResourceType.MGMT_RESOURCE_SUBSCRIPTIONS, 'Subscription',
                                              'SubscriptionState', mod='models')
        s = SubscriptionType()
        s.state = StateType.enabled
        return s

    def find_subscriptions_in_vm_with_msi(self, identity_id=None, allow_no_subscriptions=None):
        # pylint: disable=too-many-statements

        import jwt
        from requests import HTTPError
        from msrestazure.azure_active_directory import MSIAuthentication
        from msrestazure.tools import is_valid_resource_id
        resource = self.cli_ctx.cloud.endpoints.active_directory_resource_id

        if identity_id:
            if is_valid_resource_id(identity_id):
                msi_creds = MSIAuthentication(resource=resource, msi_res_id=identity_id)
                identity_type = MsiAccountTypes.user_assigned_resource_id
            else:
                authenticated = False
                try:
                    msi_creds = MSIAuthentication(resource=resource, client_id=identity_id)
                    identity_type = MsiAccountTypes.user_assigned_client_id
                    authenticated = True
                except HTTPError as ex:
                    if ex.response.reason == 'Bad Request' and ex.response.status == 400:
                        logger.info('Sniff: not an MSI client id')
                    else:
                        raise

                if not authenticated:
                    try:
                        identity_type = MsiAccountTypes.user_assigned_object_id
                        msi_creds = MSIAuthentication(resource=resource, object_id=identity_id)
                        authenticated = True
                    except HTTPError as ex:
                        if ex.response.reason == 'Bad Request' and ex.response.status == 400:
                            logger.info('Sniff: not an MSI object id')
                        else:
                            raise

                if not authenticated:
                    raise CLIError('Failed to connect to MSI, check your managed service identity id.')

        else:
            # msal : msi
            identity_type = MsiAccountTypes.system_assigned
            from azure.identity import AuthenticationRequiredError, ManagedIdentityCredential
            # msi_cred = MSIAuthentication(resource=resource)
            msi_cred = ManagedIdentityCredential()

        token_entry = msi_cred.get_token('https://management.azure.com/.default')
        token = token_entry.token
        logger.info('MSI: token was retrieved. Now trying to initialize local accounts...')
        decode = jwt.decode(token, verify=False, algorithms=['RS256'])
        tenant = decode['tid']

        subscription_finder = SubscriptionFinder(self.cli_ctx, self.auth_ctx_factory, None)
        subscriptions = subscription_finder.find_from_raw_token(tenant, token)
        base_name = ('{}-{}'.format(identity_type, identity_id) if identity_id else identity_type)
        user = _USER_ASSIGNED_IDENTITY if identity_id else _SYSTEM_ASSIGNED_IDENTITY
        if not subscriptions:
            if allow_no_subscriptions:
                subscriptions = self._build_tenant_level_accounts([tenant])
            else:
                raise CLIError('No access was configured for the VM, hence no subscriptions were found. '
                               "If this is expected, use '--allow-no-subscriptions' to have tenant level access.")

        consolidated = self._normalize_properties(user, subscriptions, is_service_principal=True,
                                                  user_assigned_identity_id=base_name)
        self._set_subscriptions(consolidated)
        return deepcopy(consolidated)

    def find_subscriptions_in_cloud_console(self):
        import jwt

        _, token, _ = self._get_token_from_cloud_shell(self.cli_ctx.cloud.endpoints.active_directory_resource_id)
        logger.info('MSI: token was retrieved. Now trying to initialize local accounts...')
        decode = jwt.decode(token, verify=False, algorithms=['RS256'])
        tenant = decode['tid']

        subscription_finder = SubscriptionFinder(self.cli_ctx, self.auth_ctx_factory, None)
        subscriptions = subscription_finder.find_from_raw_token(tenant, token)
        if not subscriptions:
            raise CLIError('No subscriptions were found in the cloud shell')
        user = decode.get('unique_name', 'N/A')

        consolidated = self._normalize_properties(user, subscriptions, is_service_principal=False)
        for s in consolidated:
            s[_USER_ENTITY][_CLOUD_SHELL_ID] = True
        self._set_subscriptions(consolidated)
        return deepcopy(consolidated)

    def _get_token_from_cloud_shell(self, resource):  # pylint: disable=no-self-use
        from msrestazure.azure_active_directory import MSIAuthentication
        auth = MSIAuthentication(resource=resource)
        auth.set_token()
        token_entry = auth.token
        return (token_entry['token_type'], token_entry['access_token'], token_entry)

    def _set_subscriptions(self, new_subscriptions, merge=True, secondary_key_name=None):

        def _get_key_name(account, secondary_key_name):
            return (account[_SUBSCRIPTION_ID] if secondary_key_name is None
                    else '{}-{}'.format(account[_SUBSCRIPTION_ID], account[secondary_key_name]))

        def _match_account(account, subscription_id, secondary_key_name, secondary_key_val):
            return (account[_SUBSCRIPTION_ID] == subscription_id and
                    (secondary_key_val is None or account[secondary_key_name] == secondary_key_val))

        existing_ones = self.load_cached_subscriptions(all_clouds=True)
        active_one = next((x for x in existing_ones if x.get(_IS_DEFAULT_SUBSCRIPTION)), None)
        active_subscription_id = active_one[_SUBSCRIPTION_ID] if active_one else None
        active_secondary_key_val = active_one[secondary_key_name] if (active_one and secondary_key_name) else None
        active_cloud = self.cli_ctx.cloud
        default_sub_id = None

        # merge with existing ones
        if merge:
            dic = collections.OrderedDict((_get_key_name(x, secondary_key_name), x) for x in existing_ones)
        else:
            dic = collections.OrderedDict()

        dic.update((_get_key_name(x, secondary_key_name), x) for x in new_subscriptions)
        subscriptions = list(dic.values())
        if subscriptions:
            if active_one:
                new_active_one = next(
                    (x for x in new_subscriptions if _match_account(x, active_subscription_id, secondary_key_name,
                                                                    active_secondary_key_val)), None)

                for s in subscriptions:
                    s[_IS_DEFAULT_SUBSCRIPTION] = False

                if not new_active_one:
                    new_active_one = Profile._pick_working_subscription(new_subscriptions)
            else:
                new_active_one = Profile._pick_working_subscription(new_subscriptions)

            new_active_one[_IS_DEFAULT_SUBSCRIPTION] = True
            default_sub_id = new_active_one[_SUBSCRIPTION_ID]

            set_cloud_subscription(self.cli_ctx, active_cloud.name, default_sub_id)
        self._storage[_SUBSCRIPTIONS] = subscriptions

    @staticmethod
    def _pick_working_subscription(subscriptions):
        from azure.mgmt.resource.subscriptions.models import SubscriptionState
        s = next((x for x in subscriptions if x.get(_STATE) == SubscriptionState.enabled.value), None)
        return s or subscriptions[0]

    def is_tenant_level_account(self):
        return self.get_subscription()[_SUBSCRIPTION_NAME] == _TENANT_LEVEL_ACCOUNT_NAME

    def set_active_subscription(self, subscription):  # take id or name
        subscriptions = self.load_cached_subscriptions(all_clouds=True)
        active_cloud = self.cli_ctx.cloud
        subscription = subscription.lower()
        result = [x for x in subscriptions
                  if subscription in [x[_SUBSCRIPTION_ID].lower(),
                                      x[_SUBSCRIPTION_NAME].lower()] and
                  x[_ENVIRONMENT_NAME] == active_cloud.name]

        if len(result) != 1:
            raise CLIError("The subscription of '{}' {} in cloud '{}'.".format(
                subscription, "doesn't exist" if not result else 'has more than one match', active_cloud.name))

        for s in subscriptions:
            s[_IS_DEFAULT_SUBSCRIPTION] = False
        result[0][_IS_DEFAULT_SUBSCRIPTION] = True

        set_cloud_subscription(self.cli_ctx, active_cloud.name, result[0][_SUBSCRIPTION_ID])
        self._storage[_SUBSCRIPTIONS] = subscriptions

    def logout(self, user_or_sp):
        subscriptions = self.load_cached_subscriptions(all_clouds=True)
        result = [x for x in subscriptions
                  if user_or_sp.lower() == x[_USER_ENTITY][_USER_NAME].lower()]
        subscriptions = [x for x in subscriptions if x not in result]

        self._storage[_SUBSCRIPTIONS] = subscriptions
        self._creds_cache.remove_cached_creds(user_or_sp)

    def logout_all(self):
        self._storage[_SUBSCRIPTIONS] = []
        self._creds_cache.remove_all_cached_creds()

    def load_cached_subscriptions(self, all_clouds=False):
        subscriptions = self._storage.get(_SUBSCRIPTIONS) or []
        active_cloud = self.cli_ctx.cloud
        cached_subscriptions = [sub for sub in subscriptions
                                if all_clouds or sub[_ENVIRONMENT_NAME] == active_cloud.name]
        # use deepcopy as we don't want to persist these changes to file.
        return deepcopy(cached_subscriptions)

    def get_current_account_user(self):
        try:
            active_account = self.get_subscription()
        except CLIError:
            raise CLIError('There are no active accounts.')

        return active_account[_USER_ENTITY][_USER_NAME]

    def get_subscription(self, subscription=None):  # take id or name
        subscriptions = self.load_cached_subscriptions()
        if not subscriptions:
            raise CLIError(_AZ_LOGIN_MESSAGE)

        result = [x for x in subscriptions if (
            not subscription and x.get(_IS_DEFAULT_SUBSCRIPTION) or
            subscription and subscription.lower() in [x[_SUBSCRIPTION_ID].lower(), x[
                _SUBSCRIPTION_NAME].lower()])]
        if not result and subscription:
            raise CLIError("Subscription '{}' not found. "
                           "Check the spelling and casing and try again.".format(subscription))
        if not result and not subscription:
            raise CLIError("No subscription found. Run 'az account set' to select a subscription.")
        if len(result) > 1:
            raise CLIError("Multiple subscriptions with the name '{}' found. "
                           "Specify the subscription ID.".format(subscription))
        return result[0]

    def get_subscription_id(self, subscription=None):  # take id or name
        return self.get_subscription(subscription)[_SUBSCRIPTION_ID]

    def get_access_token_for_resource(self, username, tenant, resource):
        tenant = tenant or 'common'
        _, access_token, _ = self._creds_cache.retrieve_token_for_user(
            username, tenant, resource)
        return access_token

    @staticmethod
    def _try_parse_msi_account_name(account):
        msi_info, user = account[_USER_ENTITY].get(_ASSIGNED_IDENTITY_INFO), account[_USER_ENTITY].get(_USER_NAME)

        if user in [_SYSTEM_ASSIGNED_IDENTITY, _USER_ASSIGNED_IDENTITY]:
            if not msi_info:
                msi_info = account[_SUBSCRIPTION_NAME]  # fall back to old persisting way
            parts = msi_info.split('-', 1)
            if parts[0] in MsiAccountTypes.valid_msi_account_types():
                return parts[0], (None if len(parts) <= 1 else parts[1])
        return None, None

    def get_login_credentials(self, resource=None, subscription_id=None, aux_subscriptions=None, aux_tenants=None):
        if aux_tenants and aux_subscriptions:
            raise CLIError("Please specify only one of aux_subscriptions and aux_tenants, not both")

        account = self.get_subscription(subscription_id)
        user_type = account[_USER_ENTITY][_USER_TYPE]
        username_or_sp_id = account[_USER_ENTITY][_USER_NAME]
        resource = resource or self.cli_ctx.cloud.endpoints.active_directory_resource_id

        identity_type, identity_id = Profile._try_parse_msi_account_name(account)

        external_tenants_info = []
        if aux_tenants:
            external_tenants_info = [tenant for tenant in aux_tenants if tenant != account[_TENANT_ID]]
        if aux_subscriptions:
            ext_subs = [aux_sub for aux_sub in aux_subscriptions if aux_sub != subscription_id]
            for ext_sub in ext_subs:
                sub = self.get_subscription(ext_sub)
                if sub[_TENANT_ID] != account[_TENANT_ID]:
                    external_tenants_info.append(sub[_TENANT_ID])

        if identity_type is None:
            def _retrieve_token():
                if in_cloud_console() and account[_USER_ENTITY].get(_CLOUD_SHELL_ID):
                    return self._get_token_from_cloud_shell(resource)
                if user_type == _USER:
                    # msal : get token
                    return self._creds_cache.retrieve_msal_token_for_user(username_or_sp_id,
                                                                          account[_TENANT_ID], account['environment'],
                                                                          account['home_account_id'], resource)
                use_cert_sn_issuer = account[_USER_ENTITY].get(_SERVICE_PRINCIPAL_CERT_SN_ISSUER_AUTH)
                return self._creds_cache.retrieve_token_for_service_principal(username_or_sp_id, resource,
                                                                              account[_TENANT_ID],
                                                                              use_cert_sn_issuer)

            def _retrieve_tokens_from_external_tenants():
                external_tokens = []
                for sub_tenant_id in external_tenants_info:
                    if user_type == _USER:
                        external_tokens.append(self._creds_cache.retrieve_token_for_user(
                            username_or_sp_id, sub_tenant_id, resource))
                    else:
                        external_tokens.append(self._creds_cache.retrieve_token_for_service_principal(
                            username_or_sp_id, resource, sub_tenant_id, resource))
                return external_tokens

            from azure.cli.core.adal_authentication import AdalAuthentication
            auth_object = AdalAuthentication(_retrieve_token,
                                             _retrieve_tokens_from_external_tenants if external_tenants_info else None)
        else:
            if self._msi_creds is None:
                # MSAL : msi
                logger.warning("MSAL : msi")
                def _retrieve_token_msi():
                    from azure.identity import AuthenticationRequiredError, ManagedIdentityCredential
                    # msi_cred = MSIAuthentication(resource=resource)
                    msi_cred = ManagedIdentityCredential()
                    token_entry = msi_cred.get_token('https://management.azure.com/.default')
                    # token_entry = sp_auth.acquire_token(context, resource, sp_id)
                    return 'Bearer', token_entry.token, token_entry
                # self._msi_creds = MsiAccountTypes.msi_auth_factory(identity_type, identity_id, resource)
                from azure.cli.core.adal_authentication import AdalAuthentication
                auth_object = AdalAuthentication(_retrieve_token_msi,
                                                 _retrieve_token_msi if external_tenants_info else None)

        return (auth_object,
                str(account[_SUBSCRIPTION_ID]),
                str(account[_TENANT_ID]))

    def get_refresh_token(self, resource=None,
                          subscription=None):
        account = self.get_subscription(subscription)
        user_type = account[_USER_ENTITY][_USER_TYPE]
        username_or_sp_id = account[_USER_ENTITY][_USER_NAME]
        resource = resource or self.cli_ctx.cloud.endpoints.active_directory_resource_id

        if user_type == _USER:
            _, _, token_entry = self._creds_cache.retrieve_token_for_user(
                username_or_sp_id, account[_TENANT_ID], resource)
            return None, token_entry.get(_REFRESH_TOKEN), token_entry[_ACCESS_TOKEN], str(account[_TENANT_ID])

        sp_secret = self._creds_cache.retrieve_secret_of_service_principal(username_or_sp_id)
        return username_or_sp_id, sp_secret, None, str(account[_TENANT_ID])

    def get_raw_token(self, resource=None, subscription=None, tenant=None):
        if subscription and tenant:
            raise CLIError("Please specify only one of subscription and tenant, not both")
        account = self.get_subscription(subscription)
        user_type = account[_USER_ENTITY][_USER_TYPE]
        username_or_sp_id = account[_USER_ENTITY][_USER_NAME]
        resource = resource or self.cli_ctx.cloud.endpoints.active_directory_resource_id

        identity_type, identity_id = Profile._try_parse_msi_account_name(account)
        if identity_type:
            # MSI
            if tenant:
                raise CLIError("Tenant shouldn't be specified for MSI account")
            msi_creds = MsiAccountTypes.msi_auth_factory(identity_type, identity_id, resource)
            msi_creds.set_token()
            token_entry = msi_creds.token
            creds = (token_entry['token_type'], token_entry['access_token'], token_entry)
        elif in_cloud_console() and account[_USER_ENTITY].get(_CLOUD_SHELL_ID):
            # Cloud Shell
            if tenant:
                raise CLIError("Tenant shouldn't be specified for Cloud Shell account")
            creds = self._get_token_from_cloud_shell(resource)
        else:
            tenant_dest = tenant if tenant else account[_TENANT_ID]
            if user_type == _USER:
                # User
                creds = self._creds_cache.retrieve_token_for_user(username_or_sp_id,
                                                                  tenant_dest, resource)
            else:
                # Service Principal
                creds = self._creds_cache.retrieve_token_for_service_principal(username_or_sp_id,
                                                                               resource,
                                                                               tenant_dest)
        return (creds,
                None if tenant else str(account[_SUBSCRIPTION_ID]),
                str(tenant if tenant else account[_TENANT_ID]))

    def refresh_accounts(self, subscription_finder=None):
        subscriptions = self.load_cached_subscriptions()
        to_refresh = subscriptions

        from azure.cli.core._debug import allow_debug_adal_connection
        allow_debug_adal_connection()
        subscription_finder = subscription_finder or SubscriptionFinder(self.cli_ctx,
                                                                        self.auth_ctx_factory,
                                                                        self._creds_cache.adal_token_cache)
        refreshed_list = set()
        result = []
        for s in to_refresh:
            user_name = s[_USER_ENTITY][_USER_NAME]
            if user_name in refreshed_list:
                continue
            refreshed_list.add(user_name)
            is_service_principal = (s[_USER_ENTITY][_USER_TYPE] == _SERVICE_PRINCIPAL)
            tenant = s[_TENANT_ID]
            subscriptions = []
            try:
                if is_service_principal:
                    sp_auth = ServicePrincipalAuth(self._creds_cache.retrieve_secret_of_service_principal(user_name))
                    subscriptions = subscription_finder.find_from_service_principal_id(user_name, sp_auth, tenant,
                                                                                       self._ad_resource_uri)
                else:
                    subscriptions = subscription_finder.find_from_user_account(user_name, None, None,
                                                                               self._ad_resource_uri)
            except Exception as ex:  # pylint: disable=broad-except
                logger.warning("Refreshing for '%s' failed with an error '%s'. The existing accounts were not "
                               "modified. You can run 'az login' later to explicitly refresh them", user_name, ex)
                result += deepcopy([r for r in to_refresh if r[_USER_ENTITY][_USER_NAME] == user_name])
                continue

            if not subscriptions:
                if s[_SUBSCRIPTION_NAME] == _TENANT_LEVEL_ACCOUNT_NAME:
                    subscriptions = self._build_tenant_level_accounts([s[_TENANT_ID]])

                if not subscriptions:
                    continue

            consolidated = self._normalize_properties(subscription_finder.user_id,
                                                      subscriptions,
                                                      is_service_principal)
            result += consolidated

        if self._creds_cache.adal_token_cache.has_state_changed:
            self._creds_cache.persist_cached_creds()

        self._set_subscriptions(result, merge=False)

    def get_sp_auth_info(self, subscription_id=None, name=None, password=None, cert_file=None):
        from collections import OrderedDict
        account = self.get_subscription(subscription_id)

        # is the credential created through command like 'create-for-rbac'?
        result = OrderedDict()
        if name and (password or cert_file):
            result['clientId'] = name
            if password:
                result['clientSecret'] = password
            else:
                result['clientCertificate'] = cert_file
            result['subscriptionId'] = subscription_id or account[_SUBSCRIPTION_ID]
        else:  # has logged in through cli
            user_type = account[_USER_ENTITY].get(_USER_TYPE)
            if user_type == _SERVICE_PRINCIPAL:
                result['clientId'] = account[_USER_ENTITY][_USER_NAME]
                sp_auth = ServicePrincipalAuth(self._creds_cache.retrieve_secret_of_service_principal(
                    account[_USER_ENTITY][_USER_NAME]))
                secret = getattr(sp_auth, 'secret', None)
                if secret:
                    result['clientSecret'] = secret
                else:
                    # we can output 'clientCertificateThumbprint' if asked
                    result['clientCertificate'] = sp_auth.certificate_file
                result['subscriptionId'] = account[_SUBSCRIPTION_ID]
            else:
                raise CLIError('SDK Auth file is only applicable when authenticated using a service principal')

        result[_TENANT_ID] = account[_TENANT_ID]
        endpoint_mappings = OrderedDict()  # use OrderedDict to control the output sequence
        endpoint_mappings['active_directory'] = 'activeDirectoryEndpointUrl'
        endpoint_mappings['resource_manager'] = 'resourceManagerEndpointUrl'
        endpoint_mappings['active_directory_graph_resource_id'] = 'activeDirectoryGraphResourceId'
        endpoint_mappings['sql_management'] = 'sqlManagementEndpointUrl'
        endpoint_mappings['gallery'] = 'galleryEndpointUrl'
        endpoint_mappings['management'] = 'managementEndpointUrl'

        for e in endpoint_mappings:
            result[endpoint_mappings[e]] = getattr(get_active_cloud(self.cli_ctx).endpoints, e)
        return result

    def get_installation_id(self):
        installation_id = self._storage.get(_INSTALLATION_ID)
        if not installation_id:
            import uuid
            installation_id = str(uuid.uuid1())
            self._storage[_INSTALLATION_ID] = installation_id
        return installation_id


class MsiAccountTypes(object):
    # pylint: disable=no-method-argument,no-self-argument
    system_assigned = 'MSI'
    user_assigned_client_id = 'MSIClient'
    user_assigned_object_id = 'MSIObject'
    user_assigned_resource_id = 'MSIResource'

    @staticmethod
    def valid_msi_account_types():
        return [MsiAccountTypes.system_assigned, MsiAccountTypes.user_assigned_client_id,
                MsiAccountTypes.user_assigned_object_id, MsiAccountTypes.user_assigned_resource_id]

    @staticmethod
    def msi_auth_factory(cli_account_name, identity, resource):
        from msrestazure.azure_active_directory import MSIAuthentication
        if cli_account_name == MsiAccountTypes.system_assigned:
            return MSIAuthentication(resource=resource)
        if cli_account_name == MsiAccountTypes.user_assigned_client_id:
            return MSIAuthentication(resource=resource, client_id=identity)
        if cli_account_name == MsiAccountTypes.user_assigned_object_id:
            return MSIAuthentication(resource=resource, object_id=identity)
        if cli_account_name == MsiAccountTypes.user_assigned_resource_id:
            return MSIAuthentication(resource=resource, msi_res_id=identity)
        raise ValueError("unrecognized msi account name '{}'".format(cli_account_name))


class SubscriptionFinder(object):
    # An ARM client. It finds subscriptions for a user or service principal. It shouldn't do any
    # authentication work, but only find subscriptions
    def __init__(self, cli_ctx, auth_context_factory, adal_token_cache, arm_client_factory=None):

        self._adal_token_cache = adal_token_cache
        self._auth_context_factory = auth_context_factory
        self.user_id = None  # will figure out after log user in
        self.cli_ctx = cli_ctx
        self._auth_profile = None
        self.msal_credential = None
        self.secret = None
        self._graph_resource_id = cli_ctx.cloud.endpoints.active_directory_resource_id
        self._msal_scope = self._graph_resource_id + '.default'

        def create_arm_client_factory(credentials):
            if arm_client_factory:
                return arm_client_factory(credentials)
            from azure.cli.core.profiles._shared import get_client_class
            from azure.cli.core.profiles import ResourceType, get_api_version
            from azure.cli.core.commands.client_factory import configure_common_settings
            client_type = get_client_class(ResourceType.MGMT_RESOURCE_SUBSCRIPTIONS)
            api_version = get_api_version(cli_ctx, ResourceType.MGMT_RESOURCE_SUBSCRIPTIONS)
            client = client_type(credentials, api_version=api_version,
                                 base_url=self.cli_ctx.cloud.endpoints.resource_manager)
            configure_common_settings(cli_ctx, client)
            return client

        self._arm_client_factory = create_arm_client_factory
        self.tenants = []

    def find_from_user_account(self, username, password, tenant, resource):
        # msal : user
        context = self._create_auth_context(tenant)
        if password:
            from azure.identity import AuthenticationRequiredError, UsernamePasswordCredential, AuthProfile
            environment = self.cli_ctx.cloud.endpoints.active_directory.lstrip('https://')
            sp_cred = UsernamePasswordCredential(_CLIENT_ID, username, password,
                                                 authority=environment)
            scope = self._create_scopes(self.cli_ctx, resource)
            token_entry = sp_cred.get_token(scope)
            # self._auth_profile = AuthProfile(environment, home_account_id, tenant, username)
            self.msal_credential = sp_cred
            self.secret = password
            # token_entry = context.acquire_token_with_username_password(resource, username, password, _CLIENT_ID)
        # msal : todo
        else:  # when refresh account, we will leverage local cached tokens
            token_entry = context.acquire_token(resource, username, _CLIENT_ID)

        if not token_entry:
            return []
        self.user_id = username

        if tenant is None:
            result = self.find_using_common_tenant(token_entry.token, resource)
        else:
            result = self.find_using_specific_tenant(tenant, token_entry.token)
        return result

    def find_through_authorization_code_flow(self, tenant, resource, authority_url):
        # launch browser and get the code
        # results = _get_authorization_code(resource, authority_url)
        #
        # if not results.get('code'):
        #     raise CLIError('Login failed')  # error detail is already displayed through previous steps
        #
        # # exchange the code for the token
        # context = self._create_auth_context(tenant)
        # token_entry = context.acquire_token_with_authorization_code(results['code'], results['reply_url'],
        #                                                             resource, _CLIENT_ID, None)

        # MSAL: get token
        # Question: authority url in azure.identity _get_authorization_code
        from azure.identity import AuthenticationRequiredError, InteractiveBrowserCredential
        if tenant:
            credential, auth_profile = InteractiveBrowserCredential.authenticate(
                client_id=_CLIENT_ID,
                silent_auth_only=True,
                scope = 'https://management.azure.com/.default',
                tenant_id = tenant
            )
        else:
            credential, auth_profile = InteractiveBrowserCredential.authenticate(
                client_id=_CLIENT_ID,
                silent_auth_only=True,
                scope='https://management.azure.com/.default'
            )
            auth_profile.tenant_id = 'organizations'
        # serialize the profile to JSON, including all keyword arguments
        profile_json = auth_profile.serialize(extra='args', serialized='also')
        with open(_PROFILE_PATH, 'w') as f:
            f.write(profile_json)

        token_entry = credential.get_token('https://management.azure.com/.default')
        self.user_id = auth_profile.username
        self.msal_credential = credential
        self._auth_profile = auth_profile
        # self.user_id = token_entry[_TOKEN_ENTRY_USER_ID]
        logger.warning("You have logged in. Now let us find all the subscriptions to which you have access...")
        if tenant is None:
            result = self.find_using_common_tenant(token_entry.token, resource)
        else:
            result = self.find_using_specific_tenant(tenant, token_entry.token)
        return result

    def find_through_interactive_flow(self, tenant, resource):
        # msal : device
        from azure.identity import AuthenticationRequiredError, DeviceCodeCredential
        message = 'To sign in, use a web browser to open the page {} and enter the code {} to authenticate.'

        cred, auth_profile = DeviceCodeCredential.authenticate(_CLIENT_ID,
                                                               scope='https://management.azure.com/.default',
                                                               prompt_callback=lambda x, y, z: logger.warning(message.format(x, y)))
        token_entry = cred.get_token('https://management.azure.com/.default')
        # context = self._create_auth_context(tenant)
        # code = context.acquire_user_code(resource, _CLIENT_ID)
        # logger.warning(code['message'])
        # token_entry = context.acquire_token_with_device_code(resource, code, _CLIENT_ID)
        self.user_id = auth_profile.username
        self.msal_credential = cred
        self._auth_profile = auth_profile
        if tenant is None:
            result = self.find_using_common_tenant(token_entry.token, resource)
        else:
            result = self.find_using_specific_tenant(tenant, token_entry.token)
        return result

    def find_from_service_principal_id(self, client_id, sp_auth, tenant, resource):
        # context = self._create_auth_context(tenant, False)
        # msal
        from azure.identity import AuthenticationRequiredError, ClientSecretCredential
        sp_cred = ClientSecretCredential(tenant, client_id, sp_auth.secret)

        token_entry = sp_cred.get_token(resource)

        self.user_id = client_id
        self.msal_credential = sp_cred
        result = self.find_using_specific_tenant(tenant, token_entry.token)
        self.tenants = [tenant]
        return result

    #  only occur inside cloud console or VM with identity
    def find_from_raw_token(self, tenant, token):
        # decode the token, so we know the tenant
        # msal : todo
        result = self.find_using_specific_tenant(tenant, token)
        self.tenants = [tenant]
        return result

    def _create_auth_context(self, tenant, use_token_cache=True):
        token_cache = self._adal_token_cache if use_token_cache else None
        return self._auth_context_factory(self.cli_ctx, tenant, token_cache)

    def find_using_common_tenant(self, auth_profile, credential=None):
        import adal
        from msrest.authentication import BasicTokenAuthentication
        from azure.identity import InteractiveBrowserCredential, AuthProfile, AuthenticationRequiredError, UsernamePasswordCredential

        all_subscriptions = []
        empty_tenants = []
        mfa_tenants = []

        # If credential is not given, try to retrieve it from cache
        if not credential:
            credential = InteractiveBrowserCredential(profile=auth_profile, silent_auth_only=True)
        # Don't use ARM_SCOPE as it only applies to public Azure
        access_token = credential.get_token(self._msal_scope).token
        token_credential = BasicTokenAuthentication({'access_token': access_token})
        client = self._arm_client_factory(token_credential)
        tenants = client.tenants.list()

        for t in tenants:
            tenant_id = t.tenant_id
            from azure.identity import DeviceCodeCredential

            # temp_context = self._create_auth_context(tenant_id)
            # display_name is available since /tenants?api-version=2018-06-01,
            # not available in /tenants?api-version=2016-06-01
            if not hasattr(t, 'display_name'):
                t.display_name = None
            if hasattr(t, 'additional_properties'):  # Remove this line once SDK is fixed
                t.display_name = t.additional_properties.get('displayName')

            try:
                temp_profile = AuthProfile(credential._profile.environment,
                                           credential._profile.home_account_id,
                                           tenant_id,
                                           credential._profile.username)
                # This won't actually launch a browser with silent_auth_only=True
                # There is no difference between DeviceCodeCredential, InteractiveBrowserCredential and
                # UsernamePasswordCredential if they are used this way with profile and silent_auth_only
                specific_tenant_credential = InteractiveBrowserCredential(profile=temp_profile, silent_auth_only=True)
                # else:
                #     # msal : todo
                #     credential = UsernamePasswordCredential(_CLIENT_ID, self.user_id, self.secret, tenant_id=tenant_id,
                #                                             authority=self.cli_ctx.cloud.endpoints.active_directory.lstrip('https://'))
                #     pass
            except adal.AdalError as ex:
                # because user creds went through the 'common' tenant, the error here must be
                # tenant specific, like the account was disabled. For such errors, we will continue
                # with other tenants.
                msg = (getattr(ex, 'error_response', None) or {}).get('error_description') or ''
                if 'AADSTS50076' in msg:
                    # The tenant requires MFA and can't be accessed with home tenant's refresh token
                    mfa_tenants.append(t)
                else:
                    logger.warning("Failed to authenticate '%s' due to error '%s'", t, ex)
                continue
            subscriptions = self.find_using_specific_tenant(
                tenant_id,
                specific_tenant_credential)

            if not subscriptions:
                empty_tenants.append(t)

            # When a subscription can be listed by multiple tenants, only the first appearance is retained
            for sub_to_add in subscriptions:
                add_sub = True
                for sub_to_compare in all_subscriptions:
                    if sub_to_add.subscription_id == sub_to_compare.subscription_id:
                        logger.warning("Subscription %s '%s' can be accessed from tenants %s(default) and %s. "
                                       "To select a specific tenant when accessing this subscription, "
                                       "use 'az login --tenant TENANT_ID'.",
                                       sub_to_add.subscription_id, sub_to_add.display_name,
                                       sub_to_compare.tenant_id, sub_to_add.tenant_id)
                        add_sub = False
                        break
                if add_sub:
                    all_subscriptions.append(sub_to_add)

        # Show warning for empty tenants
        if empty_tenants:
            logger.warning("The following tenants don't contain accessible subscriptions. "
                           "Use 'az login --allow-no-subscriptions' to have tenant level access.")
            for t in empty_tenants:
                if t.display_name:
                    logger.warning("%s '%s'", t.tenant_id, t.display_name)
                else:
                    logger.warning("%s", t.tenant_id)

        # Show warning for MFA tenants
        if mfa_tenants:
            logger.warning("The following tenants require Multi-Factor Authentication (MFA). "
                           "Use 'az login --tenant TENANT_ID' to explicitly login to a tenant.")
            for t in mfa_tenants:
                if t.display_name:
                    logger.warning("%s '%s'", t.tenant_id, t.display_name)
                else:
                    logger.warning("%s", t.tenant_id)
        return all_subscriptions

    def find_using_specific_tenant(self, tenant, credential):
        from msrest.authentication import BasicTokenAuthentication
        scope = self._graph_resource_id + '.default'
        token_credential = BasicTokenAuthentication({'access_token': credential.get_token(scope).token})
        client = self._arm_client_factory(token_credential)
        subscriptions = client.subscriptions.list()
        all_subscriptions = []
        for s in subscriptions:
            # map tenantId from REST API to homeTenantId
            if hasattr(s, "tenant_id"):
                setattr(s, 'home_tenant_id', s.tenant_id)
            setattr(s, 'tenant_id', tenant)
            all_subscriptions.append(s)
        self.tenants.append(tenant)
        return all_subscriptions


class CredsCache(object):
    '''Caches AAD tokena and service principal secrets, and persistence will
    also be handled
    '''

    def __init__(self, cli_ctx, auth_ctx_factory=None, async_persist=True):
        # AZURE_ACCESS_TOKEN_FILE is used by Cloud Console and not meant to be user configured
        self._token_file = (os.environ.get('AZURE_ACCESS_TOKEN_FILE', None) or
                            os.path.join(get_config_dir(), 'accessTokens.json'))
        self._service_principal_creds = []
        self._auth_ctx_factory = auth_ctx_factory
        self._adal_token_cache_attr = None
        self._should_flush_to_disk = False
        self._async_persist = async_persist
        self._ctx = cli_ctx
        if async_persist:
            import atexit
            atexit.register(self.flush_to_disk)

    def persist_cached_creds(self):
        self._should_flush_to_disk = True
        if not self._async_persist:
            self.flush_to_disk()
        self.adal_token_cache.has_state_changed = False

    def flush_to_disk(self):
        if self._should_flush_to_disk:
            with os.fdopen(os.open(self._token_file, os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o600),
                           'w+') as cred_file:
                items = self.adal_token_cache.read_items()
                all_creds = [entry for _, entry in items]

                # trim away useless fields (needed for cred sharing with xplat)
                for i in all_creds:
                    for key in TOKEN_FIELDS_EXCLUDED_FROM_PERSISTENCE:
                        i.pop(key, None)

                all_creds.extend(self._service_principal_creds)
                cred_file.write(json.dumps(all_creds))

    def retrieve_token_for_user(self, username, tenant, resource):
        context = self._auth_ctx_factory(self._ctx, tenant, cache=self.adal_token_cache)
        token_entry = context.acquire_token(resource, username, _CLIENT_ID)
        if not token_entry:
            raise CLIError("Could not retrieve token from local cache.{}".format(
                " Please run 'az login'." if not in_cloud_console() else ''))

        if self.adal_token_cache.has_state_changed:
            self.persist_cached_creds()
        return (token_entry[_TOKEN_ENTRY_TOKEN_TYPE], token_entry[_ACCESS_TOKEN], token_entry)

    def _create_scopes(self, cli_ctx, resource=None):
        resource = resource or cli_ctx.cloud.endpoints.resource_manager
        scope = resource.rstrip('/') + '/.default'
        return scope

    def retrieve_msal_token_for_user(self, username, tenant, environment, home_account_id, resource):
        # context = self._auth_ctx_factory(self._ctx, tenant, cache=self.adal_token_cache)
        # token_entry = context.acquire_token(resource, username, _CLIENT_ID)
        # if not token_entry:
        #     raise CLIError("Could not retrieve token from local cache.{}".format(
        #         " Please run 'az login'." if not in_cloud_console() else ''))
        #
        # if self.adal_token_cache.has_state_changed:
        #     self.persist_cached_creds()
        from azure.identity import (
            AuthenticationRequiredError,
            AuthProfile,
            SharedTokenCacheCredential
        )

        auth_profile = AuthProfile(environment, home_account_id, tenant, username)
        credential = SharedTokenCacheCredential(profile=auth_profile)

        try:
            # pass the credential to some client, which eventually requests a token
            scope = self._create_scopes(self._ctx, resource)
            token_entry = credential.get_token(scope)
        except AuthenticationRequiredError:
            raise CLIError("Could not retrieve token from local cache.{}".format(
                " Please run 'az login'." if not in_cloud_console() else ''))
        return 'Bearer', token_entry.token, token_entry

    def retrieve_token_for_service_principal(self, sp_id, resource, tenant, use_cert_sn_issuer=False):
        self.load_adal_token_cache()
        matched = [x for x in self._service_principal_creds if sp_id == x[_SERVICE_PRINCIPAL_ID]]
        if not matched:
            raise CLIError("Could not retrieve credential from local cache for service principal {}. "
                           "Please run 'az login' for this service principal."
                           .format(sp_id))
        matched_with_tenant = [x for x in matched if tenant == x[_SERVICE_PRINCIPAL_TENANT]]
        if matched_with_tenant:
            cred = matched_with_tenant[0]
        else:
            logger.warning("Could not retrieve credential from local cache for service principal %s under tenant %s. "
                           "Trying credential under tenant %s, assuming that is an app credential.",
                           sp_id, tenant, matched[0][_SERVICE_PRINCIPAL_TENANT])
            cred = matched[0]
        # msal
        # context = self._auth_ctx_factory(self._ctx, tenant, None)
        sp_auth = ServicePrincipalAuth(cred.get(_ACCESS_TOKEN, None) or
                                        cred.get(_SERVICE_PRINCIPAL_CERT_FILE, None),
                                        use_cert_sn_issuer)
        from azure.identity import AuthenticationRequiredError, ClientSecretCredential
        sp_cred = ClientSecretCredential(tenant, sp_id, sp_auth.secret)

        token_entry = sp_cred.get_token('https://management.azure.com/.default')
        # token_entry = sp_auth.acquire_token(context, resource, sp_id)
        return 'Bearer', token_entry.token, token_entry

    def retrieve_secret_of_service_principal(self, sp_id):
        self.load_adal_token_cache()
        matched = [x for x in self._service_principal_creds if sp_id == x[_SERVICE_PRINCIPAL_ID]]
        if not matched:
            raise CLIError("No matched service principal found")
        cred = matched[0]
        return cred.get(_ACCESS_TOKEN, None)

    @property
    def adal_token_cache(self):
        return self.load_adal_token_cache()

    def load_adal_token_cache(self):
        if self._adal_token_cache_attr is None:
            import adal
            all_entries = _load_tokens_from_file(self._token_file)
            self._load_service_principal_creds(all_entries)
            real_token = [x for x in all_entries if x not in self._service_principal_creds]
            self._adal_token_cache_attr = adal.TokenCache(json.dumps(real_token))
        return self._adal_token_cache_attr

    def save_service_principal_cred(self, sp_entry):
        self.load_adal_token_cache()
        matched = [x for x in self._service_principal_creds
                   if sp_entry[_SERVICE_PRINCIPAL_ID] == x[_SERVICE_PRINCIPAL_ID] and
                   sp_entry[_SERVICE_PRINCIPAL_TENANT] == x[_SERVICE_PRINCIPAL_TENANT]]
        state_changed = False
        if matched:
            # pylint: disable=line-too-long
            if (sp_entry.get(_ACCESS_TOKEN, None) != matched[0].get(_ACCESS_TOKEN, None) or
                    sp_entry.get(_SERVICE_PRINCIPAL_CERT_FILE, None) != matched[0].get(_SERVICE_PRINCIPAL_CERT_FILE, None)):
                self._service_principal_creds.remove(matched[0])
                self._service_principal_creds.append(sp_entry)
                state_changed = True
        else:
            self._service_principal_creds.append(sp_entry)
            state_changed = True

        if state_changed:
            self.persist_cached_creds()

    def _load_service_principal_creds(self, creds):
        for c in creds:
            if c.get(_SERVICE_PRINCIPAL_ID):
                self._service_principal_creds.append(c)
        return self._service_principal_creds

    def remove_cached_creds(self, user_or_sp):
        state_changed = False
        # clear AAD tokens
        tokens = self.adal_token_cache.find({_TOKEN_ENTRY_USER_ID: user_or_sp})
        if tokens:
            state_changed = True
            self.adal_token_cache.remove(tokens)

        # clear service principal creds
        matched = [x for x in self._service_principal_creds
                   if x[_SERVICE_PRINCIPAL_ID] == user_or_sp]
        if matched:
            state_changed = True
            self._service_principal_creds = [x for x in self._service_principal_creds
                                             if x not in matched]

        if state_changed:
            self.persist_cached_creds()

    def remove_all_cached_creds(self):
        # we can clear file contents, but deleting it is simpler
        _delete_file(self._token_file)


class ServicePrincipalAuth(object):

    def __init__(self, password_arg_value, use_cert_sn_issuer=None):
        if not password_arg_value:
            raise CLIError('missing secret or certificate in order to '
                           'authnenticate through a service principal')
        if os.path.isfile(password_arg_value):
            certificate_file = password_arg_value
            from OpenSSL.crypto import load_certificate, FILETYPE_PEM
            self.certificate_file = certificate_file
            self.public_certificate = None
            with open(certificate_file, 'r') as file_reader:
                self.cert_file_string = file_reader.read()
                cert = load_certificate(FILETYPE_PEM, self.cert_file_string)
                self.thumbprint = cert.digest("sha1").decode()
                if use_cert_sn_issuer:
                    # low-tech but safe parsing based on
                    # https://github.com/libressl-portable/openbsd/blob/master/src/lib/libcrypto/pem/pem.h
                    match = re.search(r'\-+BEGIN CERTIFICATE.+\-+(?P<public>[^-]+)\-+END CERTIFICATE.+\-+',
                                      self.cert_file_string, re.I)
                    self.public_certificate = match.group('public').strip()
        else:
            self.secret = password_arg_value

    def acquire_token(self, authentication_context, resource, client_id):
        if hasattr(self, 'secret'):
            return authentication_context.acquire_token_with_client_credentials(resource, client_id, self.secret)
        return authentication_context.acquire_token_with_client_certificate(resource, client_id, self.cert_file_string,
                                                                            self.thumbprint, self.public_certificate)

    def get_entry_to_persist(self, sp_id, tenant):
        entry = {
            _SERVICE_PRINCIPAL_ID: sp_id,
            _SERVICE_PRINCIPAL_TENANT: tenant,
        }
        if hasattr(self, 'secret'):
            entry[_ACCESS_TOKEN] = self.secret
        else:
            entry[_SERVICE_PRINCIPAL_CERT_FILE] = self.certificate_file
            entry[_SERVICE_PRINCIPAL_CERT_THUMBPRINT] = self.thumbprint

        return entry


class ClientRedirectServer(BaseHTTPServer.HTTPServer):  # pylint: disable=too-few-public-methods
    query_params = {}


class ClientRedirectHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    # pylint: disable=line-too-long

    def do_GET(self):
        try:
            from urllib.parse import parse_qs
        except ImportError:
            from urlparse import parse_qs  # pylint: disable=import-error

        if self.path.endswith('/favicon.ico'):  # deal with legacy IE
            self.send_response(204)
            return

        query = self.path.split('?', 1)[-1]
        query = parse_qs(query, keep_blank_values=True)
        self.server.query_params = query

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        landing_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'auth_landing_pages',
                                    'ok.html' if 'code' in query else 'fail.html')
        with open(landing_file, 'rb') as html_file:
            self.wfile.write(html_file.read())

    def log_message(self, format, *args):  # pylint: disable=redefined-builtin,unused-argument,no-self-use
        pass  # this prevent http server from dumping messages to stdout


def _get_authorization_code_worker(authority_url, resource, results):
    import socket
    import random

    reply_url = None

    # On Windows, HTTPServer by default doesn't throw error if the port is in-use
    # https://github.com/Azure/azure-cli/issues/10578
    if is_windows():
        logger.debug('Windows is detected. Set HTTPServer.allow_reuse_address to False')
        ClientRedirectServer.allow_reuse_address = False
    elif is_wsl():
        logger.debug('WSL is detected. Set HTTPServer.allow_reuse_address to False')
        ClientRedirectServer.allow_reuse_address = False

    for port in range(8400, 9000):
        try:
            web_server = ClientRedirectServer(('localhost', port), ClientRedirectHandler)
            reply_url = "http://localhost:{}".format(port)
            break
        except socket.error as ex:
            logger.warning("Port '%s' is taken with error '%s'. Trying with the next one", port, ex)

    if reply_url is None:
        logger.warning("Error: can't reserve a port for authentication reply url")
        return

    try:
        request_state = ''.join(random.SystemRandom().choice(string.ascii_lowercase + string.digits) for _ in range(20))
    except NotImplementedError:
        request_state = 'code'

    # launch browser:
    url = ('{0}/oauth2/authorize?response_type=code&client_id={1}'
           '&redirect_uri={2}&state={3}&resource={4}&prompt=select_account')
    url = url.format(authority_url, _CLIENT_ID, reply_url, request_state, resource)
    logger.info('Open browser with url: %s', url)
    succ = open_page_in_browser(url)
    if succ is False:
        web_server.server_close()
        results['no_browser'] = True
        return

    # wait for callback from browser.
    while True:
        web_server.handle_request()
        if 'error' in web_server.query_params or 'code' in web_server.query_params:
            break

    if 'error' in web_server.query_params:
        logger.warning('Authentication Error: "%s". Description: "%s" ', web_server.query_params['error'],
                       web_server.query_params.get('error_description'))
        return

    if 'code' in web_server.query_params:
        code = web_server.query_params['code']
    else:
        logger.warning('Authentication Error: Authorization code was not captured in query strings "%s"',
                       web_server.query_params)
        return

    if 'state' in web_server.query_params:
        response_state = web_server.query_params['state'][0]
        if response_state != request_state:
            raise RuntimeError("mismatched OAuth state")
    else:
        raise RuntimeError("missing OAuth state")

    results['code'] = code[0]
    results['reply_url'] = reply_url


def _get_authorization_code(resource, authority_url):
    import threading
    import time
    results = {}
    t = threading.Thread(target=_get_authorization_code_worker,
                         args=(authority_url, resource, results))
    t.daemon = True
    t.start()
    while True:
        time.sleep(2)  # so that ctrl+c can stop the command
        if not t.is_alive():
            break  # done
    if results.get('no_browser'):
        raise RuntimeError()
    return results
