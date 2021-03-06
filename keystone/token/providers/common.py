# Copyright 2013 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import timeutils
import six
from six.moves.urllib import parse

from keystone.common import dependency
#from keystone.contrib import federation
from keystone import exception
from keystone.i18n import _, _LE
from keystone.openstack.common import versionutils
from keystone import token
from keystone.token import provider


LOG = log.getLogger(__name__)
CONF = cfg.CONF


@dependency.requires('assignment_api', 'catalog_api', 'identity_api',
                    'resource_api', 'role_api')
class V3TokenDataHelper(object):
    """Token data helper."""
    def __init__(self):
        # Keep __init__ around to ensure dependency injection works.
        super(V3TokenDataHelper, self).__init__()

    def _get_filtered_domain(self, domain_id):
        domain_ref = self.resource_api.get_domain(domain_id)
        return {'id': domain_ref['id'], 'name': domain_ref['name']}

    def _get_filtered_project(self, project_id):
        project_ref = self.resource_api.get_project(project_id)
        filtered_project = {
            'id': project_ref['id'],
            'name': project_ref['name']}
        filtered_project['domain'] = self._get_filtered_domain(
            project_ref['domain_id'])
        return filtered_project

    def _populate_scope(self, token_data, domain_id, project_id):
        if 'domain' in token_data or 'project' in token_data:
            # scope already exist, no need to populate it again
            return

        if domain_id:
            token_data['domain'] = self._get_filtered_domain(domain_id)
        if project_id:
            token_data['project'] = self._get_filtered_project(project_id)

    def _get_roles_for_user(self, user_id, domain_id, project_id):
        roles = []
        if domain_id:
            roles = self.assignment_api.get_roles_for_user_and_domain(
                user_id, domain_id)
        if project_id:
            roles = self.assignment_api.get_roles_for_user_and_project(
                user_id, project_id)
        return [self.role_api.get_role(role_id) for role_id in roles]

    def _populate_roles_for_groups(self, group_ids,
                                   project_id=None, domain_id=None,
                                   user_id=None):
        def _check_roles(roles, user_id, project_id, domain_id):
            # User was granted roles so simply exit this function.
            if roles:
                return
            if project_id:
                msg = _('User %(user_id)s has no access '
                        'to project %(project_id)s') % {
                            'user_id': user_id,
                            'project_id': project_id}
            elif domain_id:
                msg = _('User %(user_id)s has no access '
                        'to domain %(domain_id)s') % {
                            'user_id': user_id,
                            'domain_id': domain_id}
            # Since no roles were found a user is not authorized to
            # perform any operations. Raise an exception with
            # appropriate error message.
            raise exception.Unauthorized(msg)

        roles = self.assignment_api.get_roles_for_groups(group_ids,
                                                         project_id,
                                                         domain_id)
        _check_roles(roles, user_id, project_id, domain_id)
        return roles

    def _populate_user(self, token_data, user_id):
        if 'user' in token_data:
            # no need to repopulate user if it already exists
            return

        user_ref = self.identity_api.get_user(user_id)
        filtered_user = {
            'id': user_ref['id'],
            'name': user_ref['name'],
            'domain': self._get_filtered_domain(user_ref['domain_id'])}
        token_data['user'] = filtered_user

    def _populate_roles(self, token_data, user_id, domain_id, project_id,
                        access_token):
        if 'roles' in token_data:
            # no need to repopulate roles
            return

        if access_token:
            filtered_roles = []
            authed_role_ids = jsonutils.loads(access_token['role_ids'])
            all_roles = self.role_api.list_roles()
            for role in all_roles:
                for authed_role in authed_role_ids:
                    if authed_role == role['id']:
                        filtered_roles.append({'id': role['id'],
                                               'name': role['name']})
            token_data['roles'] = filtered_roles
            return

        
        token_user_id = user_id
        token_project_id = project_id
        token_domain_id = domain_id

        if token_domain_id or token_project_id:
            roles = self._get_roles_for_user(token_user_id,
                                             token_domain_id,
                                             token_project_id)
            filtered_roles = []
            
            for role in roles:
                filtered_roles.append({'id': role['id'],
                                           'name': role['name']})

            # user has no project or domain roles, therefore access denied
            if not filtered_roles:
                if token_project_id:
                    msg = _('User %(user_id)s has no access '
                            'to project %(project_id)s') % {
                                'user_id': user_id,
                                'project_id': token_project_id}
                else:
                    msg = _('User %(user_id)s has no access '
                            'to domain %(domain_id)s') % {
                                'user_id': user_id,
                                'domain_id': token_domain_id}
                LOG.debug(msg)
                raise exception.Unauthorized(msg)

            token_data['roles'] = filtered_roles

    def _populate_service_catalog(self, token_data, user_id,
                                  domain_id, project_id):
        if 'catalog' in token_data:
            # no need to repopulate service catalog
            return

        if project_id or domain_id:
            service_catalog = self.catalog_api.get_v3_catalog(
                user_id, project_id)

            token_data['catalog'] = service_catalog

    def _populate_token_dates(self, token_data, expires=None,
                              issued_at=None):
        if not expires:
            expires = provider.default_expire_time()
        if not isinstance(expires, six.string_types):
            expires = timeutils.isotime(expires, subsecond=True)
        token_data['expires_at'] = expires
        token_data['issued_at'] = (issued_at or
                                   timeutils.isotime(subsecond=True))

    def _populate_audit_info(self, token_data, audit_info=None):
        if audit_info is None or isinstance(audit_info, six.string_types):
            token_data['audit_ids'] = provider.audit_info(audit_info)
        elif isinstance(audit_info, list):
            token_data['audit_ids'] = audit_info
        else:
            msg = (_('Invalid audit info data type: %(data)s (%(type)s)') %
                   {'data': audit_info, 'type': type(audit_info)})
            LOG.error(msg)
            raise exception.UnexpectedError(msg)

    def get_token_data(self, user_id, method_names, extras=None,
                       domain_id=None, project_id=None, expires=None,
                       token=None, include_catalog=True,
                       bind=None, access_token=None, issued_at=None,
                       audit_info=None):
        if extras is None:
            extras = {}
        if extras:
            versionutils.deprecated(
                what='passing token data with "extras"',
                as_of=versionutils.deprecated.KILO,
                in_favor_of='well-defined APIs')
        token_data = {'methods': method_names,
                      'extras': extras}

        # We've probably already written these to the token
        if token:
            for x in ('roles', 'user', 'catalog', 'project', 'domain'):
                if x in token:
                    token_data[x] = token[x]

        if bind:
            token_data['bind'] = bind

        self._populate_scope(token_data, domain_id, project_id)
        self._populate_user(token_data, user_id)
        self._populate_roles(token_data, user_id, domain_id, project_id,
                             access_token)
        self._populate_audit_info(token_data, audit_info)

        if include_catalog:
            self._populate_service_catalog(token_data, user_id, domain_id,
                                           project_id)
        self._populate_token_dates(token_data, expires=expires,
                                   issued_at=issued_at)
        return {'token': token_data}


@dependency.requires('catalog_api', 'identity_api', 'resource_api', 'role_api')
class BaseProvider(provider.Provider):
    def __init__(self, *args, **kwargs):
        super(BaseProvider, self).__init__(*args, **kwargs)
        self.v3_token_data_helper = V3TokenDataHelper()

    def get_token_version(self, token_data):
        if token_data and isinstance(token_data, dict):
            if 'token_version' in token_data:
                if token_data['token_version'] in token.provider.VERSIONS:
                    return token_data['token_version']
            # FIXME(morganfainberg): deprecate the following logic in future
            # revisions. It is better to just specify the token_version in
            # the token_data itself. This way we can support future versions
            # that might have the same fields.
            if 'token' in token_data and 'methods' in token_data['token']:
                return token.provider.V3
        raise exception.UnsupportedTokenVersionException()

    def issue_v3_token(self, user_id, method_names, expires_at=None,
                       project_id=None, domain_id=None, auth_context=None,
                       metadata_ref=None, include_catalog=True,
                       parent_audit_id=None):

        token_ref = None

        access_token = None

        token_data = self.v3_token_data_helper.get_token_data(
            user_id,
            method_names,
            auth_context.get('extras') if auth_context else None,
            domain_id=domain_id,
            project_id=project_id,
            expires=expires_at,
            bind=auth_context.get('bind') if auth_context else None,
            token=token_ref,
            include_catalog=include_catalog,
            access_token=access_token,
            audit_info=parent_audit_id)

        token_id = self._get_token_id(token_data)
        return token_id, token_data

    def _verify_token_ref(self, token_ref):
        """Verify and return the given token_ref."""
        if not token_ref:
            raise exception.Unauthorized()
        return token_ref

    def _assert_default_domain(self, token_ref):
        """Make sure we are operating on default domain only."""
        if (token_ref.get('token_data') and
                self.get_token_version(token_ref.get('token_data')) ==
                token.provider.V3):
            # this is a V3 token
            msg = _('Non-default domain is not supported')
            # user in a non-default is prohibited
            if (token_ref['token_data']['token']['user']['domain']['id'] !=
                    CONF.identity.admin_domain_id):
                raise exception.Unauthorized(msg)
            # domain scoping is prohibited
            if token_ref['token_data']['token'].get('domain'):
                raise exception.Unauthorized(
                    _('Domain scoped token is not supported'))
            # project in non-default domain is prohibited
            if token_ref['token_data']['token'].get('project'):
                project = token_ref['token_data']['token']['project']
                project_domain_id = project['domain']['id']
                # scoped to project in non-default domain is prohibited
                if project_domain_id != CONF.identity.admin_domain_id:
                    raise exception.Unauthorized(msg)

            metadata_ref = token_ref['metadata']

    def validate_v3_token(self, token_ref):
        # FIXME(gyee): performance or correctness? Should we return the
        # cached token or reconstruct it? Obviously if we are going with
        # the cached token, any role, project, or domain name changes
        # will not be reflected. One may argue that with PKI tokens,
        # we are essentially doing cached token validation anyway.
        # Lets go with the cached token strategy. Since token
        # management layer is now pluggable, one can always provide
        # their own implementation to suit their needs.

        token_data = token_ref.get('token_data')
        if not token_data or 'token' not in token_data:
            # token ref is created by V2 API
            project_id = None
            project_ref = token_ref.get('tenant')
            if project_ref:
                project_id = project_ref['id']

            issued_at = token_ref['token_data']['access']['token']['issued_at']
            audit = token_ref['token_data']['access']['token'].get('audit_ids')

            token_data = self.v3_token_data_helper.get_token_data(
                token_ref['user']['id'],
                ['password', 'token'],
                project_id=project_id,
                bind=token_ref.get('bind'),
                expires=token_ref['expires'],
                issued_at=issued_at,
                audit_info=audit)
        return token_data
