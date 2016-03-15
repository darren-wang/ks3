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

import sys

from keystone.common import cms
from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import importutils
from oslo_utils import timeutils
import six

from keystone.common import controller
from keystone.common import dependency
from keystone.common import wsgi
from keystone import config
#from keystone.contrib import federation
from keystone import exception
from keystone.i18n import _, _LI, _LW
from keystone.resource import controllers as resource_controllers


LOG = log.getLogger(__name__)

CONF = cfg.CONF

# registry of authentication methods
AUTH_METHODS = {}
AUTH_PLUGINS_LOADED = False


def load_auth_methods():
    global AUTH_PLUGINS_LOADED

    if AUTH_PLUGINS_LOADED:
        # Only try and load methods a single time.
        return
    # config.setup_authentication should be idempotent, call it to ensure we
    # have setup all the appropriate configuration options we may need.
    config.setup_authentication()
    for plugin in CONF.auth.methods:
        if '.' in plugin:
            # NOTE(morganfainberg): if '.' is in the plugin name, it should be
            # imported rather than used as a plugin identifier.
            plugin_class = plugin
            driver = importutils.import_object(plugin)
            if not hasattr(driver, 'method'):
                raise ValueError(_('Cannot load an auth-plugin by class-name '
                                   'without a "method" attribute defined: %s'),
                                 plugin_class)

            LOG.info(_LI('Loading auth-plugins by class-name is deprecated.'))
            plugin_name = driver.method
        else:
            plugin_name = plugin
            plugin_class = CONF.auth.get(plugin)
            driver = importutils.import_object(plugin_class)
        if plugin_name in AUTH_METHODS:
            raise ValueError(_('Auth plugin %(plugin)s is requesting '
                               'previously registered method %(method)s') %
                             {'plugin': plugin_class, 'method': driver.method})
        AUTH_METHODS[plugin_name] = driver
    AUTH_PLUGINS_LOADED = True


def get_auth_method(method_name):
    global AUTH_METHODS
    if method_name not in AUTH_METHODS:
        raise exception.AuthMethodNotSupported()
    return AUTH_METHODS[method_name]


class AuthContext(dict):
    """Retrofitting auth_context to reconcile identity attributes.

    The identity attributes must not have conflicting values among the
    auth plug-ins. The only exception is `expires_at`, which is set to its
    earliest value.

    """

    # identity attributes need to be reconciled among the auth plugins
    IDENTITY_ATTRIBUTES = frozenset(['user_id', 'project_id',
                                     'access_token_id', 'domain_id',
                                     'expires_at'])

    def __setitem__(self, key, val):
        if key in self.IDENTITY_ATTRIBUTES and key in self:
            existing_val = self[key]
            if key == 'expires_at':
                # special treatment for 'expires_at', we are going to take
                # the earliest expiration instead.
                if existing_val != val:
                    LOG.info(_LI('"expires_at" has conflicting values '
                                 '%(existing)s and %(new)s.  Will use the '
                                 'earliest value.'),
                             {'existing': existing_val, 'new': val})
                if existing_val is None or val is None:
                    val = existing_val or val
                else:
                    val = min(existing_val, val)
            elif existing_val != val:
                msg = _('Unable to reconcile identity attribute %(attribute)s '
                        'as it has conflicting values %(new)s and %(old)s') % (
                            {'attribute': key,
                             'new': val,
                             'old': existing_val})
                raise exception.Unauthorized(msg)
        return super(AuthContext, self).__setitem__(key, val)


# TODO(blk-u): this class doesn't use identity_api directly, but makes it
# available for consumers. Consumers should probably not be getting
# identity_api from this since it's available in global registry, then
# identity_api should be removed from this list.
@dependency.requires('identity_api', 'resource_api')
class AuthInfo(object):
    """Encapsulation of "auth" request."""

    @staticmethod
    def create(context, auth=None):
        auth_info = AuthInfo(context, auth=auth)
        auth_info._validate_and_normalize_auth_data()
        return auth_info

    def __init__(self, context, auth=None):
        self.context = context
        self.auth = auth
        self._scope_data = (None, None, None, None)
        # self._scope_data is (domain_id, project_id, unscoped)
        # project scope: (None, project_id, None, None)
        # domain scope: (domain_id, None, None, None)
        # unscoped: (None, None, None, 'unscoped')

    def _assert_project_is_enabled(self, project_ref):
        # ensure the project is enabled
        try:
            self.resource_api.assert_project_enabled(
                project_id=project_ref['id'],
                project=project_ref)
        except AssertionError as e:
            LOG.warning(six.text_type(e))
            six.reraise(exception.Unauthorized, exception.Unauthorized(e),
                        sys.exc_info()[2])

    def _assert_domain_is_enabled(self, domain_ref):
        try:
            self.resource_api.assert_domain_enabled(
                domain_id=domain_ref['id'],
                domain=domain_ref)
        except AssertionError as e:
            LOG.warning(six.text_type(e))
            six.reraise(exception.Unauthorized, exception.Unauthorized(e),
                        sys.exc_info()[2])

    def _lookup_domain(self, domain_info):
        domain_id = domain_info.get('id')
        domain_name = domain_info.get('name')
        domain_ref = None
        if not domain_id and not domain_name:
            raise exception.ValidationError(attribute='id or name',
                                            target='domain')
        try:
            if domain_name:
                domain_ref = self.resource_api.get_domain_by_name(
                    domain_name)
            else:
                domain_ref = self.resource_api.get_domain(domain_id)
        except exception.DomainNotFound as e:
            LOG.exception(six.text_type(e))
            raise exception.Unauthorized(e)
        self._assert_domain_is_enabled(domain_ref)
        return domain_ref

    def _lookup_project(self, project_info):
        project_id = project_info.get('id')
        project_name = project_info.get('name')
        project_ref = None
        if not project_id and not project_name:
            raise exception.ValidationError(attribute='id or name',
                                            target='project')
        try:
            if project_name:
                if 'domain' not in project_info:
                    raise exception.ValidationError(attribute='domain',
                                                    target='project')
                domain_ref = self._lookup_domain(project_info['domain'])
                project_ref = self.resource_api.get_project_by_name(
                    project_name, domain_ref['id'])
            else:
                project_ref = self.resource_api.get_project(project_id)
                # NOTE(morganfainberg): The _lookup_domain method will raise
                # exception.Unauthorized if the domain isn't found or is
                # disabled.
                self._lookup_domain({'id': project_ref['domain_id']})
        except exception.ProjectNotFound as e:
            raise exception.Unauthorized(e)
        self._assert_project_is_enabled(project_ref)
        return project_ref

    def _validate_and_normalize_scope_data(self):
        """Validate and normalize scope data."""
        if 'scope' not in self.auth:
            return
        if sum(['project' in self.auth['scope'],
                'domain' in self.auth['scope'],
                'unscoped' in self.auth['scope']) != 1:
            raise exception.ValidationError(
                attribute='project, domain or unscoped',
                target='scope')
        if 'unscoped' in self.auth['scope']:
            self._scope_data = (None, None, None, 'unscoped')
            return
        if 'project' in self.auth['scope']:
            project_ref = self._lookup_project(self.auth['scope']['project'])
            self._scope_data = (None, project_ref['id'], None, None)
        elif 'domain' in self.auth['scope']:
            domain_ref = self._lookup_domain(self.auth['scope']['domain'])
            self._scope_data = (domain_ref['id'], None, None, None)

    def _validate_auth_methods(self):
        if 'identity' not in self.auth:
            raise exception.ValidationError(attribute='identity',
                                            target='auth')

        # make sure auth methods are provided
        if 'methods' not in self.auth['identity']:
            raise exception.ValidationError(attribute='methods',
                                            target='identity')

        # make sure all the method data/payload are provided
        for method_name in self.get_method_names():
            if method_name not in self.auth['identity']:
                raise exception.ValidationError(attribute=method_name,
                                                target='identity')

        # make sure auth method is supported
        for method_name in self.get_method_names():
            if method_name not in AUTH_METHODS:
                raise exception.AuthMethodNotSupported()

    def _validate_and_normalize_auth_data(self):
        """Make sure "auth" is valid."""
        # make sure "auth" exist
        if not self.auth:
            raise exception.ValidationError(attribute='auth',
                                            target='request body')

        self._validate_auth_methods()
        self._validate_and_normalize_scope_data()

    def get_method_names(self):
        """Returns the identity method names.

        :returns: list of auth method names

        """
        # Sanitizes methods received in request's body
        # Filters out duplicates, while keeping elements' order.
        method_names = []
        for method in self.auth['identity']['methods']:
            if method not in method_names:
                method_names.append(method)
        return method_names

    def get_method_data(self, method):
        """Get the auth method payload.

        :returns: auth method payload

        """
        if method not in self.auth['identity']['methods']:
            raise exception.ValidationError(attribute=method,
                                            target='identity')
        return self.auth['identity'][method]

    def get_scope(self):
        """Get scope information.

        Verify and return the scoping information.

        :returns: (domain_id, project_id, unscoped).
                   If scope to a project, (None, project_id, None)
                   will be returned.
                   If scoped to a domain, (domain_id, None, None)
                   will be returned.
                   If unscoped, (None, None, 'unscoped') will be
                   returned.

        """
        return self._scope_data

    def set_scope(self, domain_id=None, project_id=None, unscoped=None):
        """Set scope information."""
        if domain_id and project_id:
            msg = _('Scoping to both domain and project is not allowed')
            raise ValueError(msg)
        self._scope_data = (domain_id, project_id, unscoped)


@dependency.requires('assignment_api', 'catalog_api', 'identity_api',
                     'resource_api', 'token_provider_api')
class Auth(controller.Controller):

    # Note(atiwari): From V3 auth controller code we are
    # calling protection() wrappers, so we need to setup
    # the member_name and  collection_name attributes of
    # auth controller code.
    # In the absence of these attributes, default 'entity'
    # string will be used to represent the target which is
    # generic. Policy can be defined using 'entity' but it
    # would not reflect the exact entity that is in context.
    # We are defining collection_name = 'tokens' and
    # member_name = 'token' to facilitate policy decisions.
    collection_name = 'tokens'
    member_name = 'token'

    def __init__(self, *args, **kw):
        super(Auth, self).__init__(*args, **kw)
        config.setup_authentication()

    def authenticate_for_token(self, context, auth=None):
        """Authenticate user and issue a token."""
        include_catalog = 'nocatalog' not in context['query_string']

        auth_info = AuthInfo.create(context, auth=auth)
        auth_context = AuthContext(extras={},
                                       method_names=[],
                                       bind={})
        self.authenticate(context, auth_info, auth_context)
        if auth_context.get('access_token_id'):
                auth_info.set_scope(None, auth_context['project_id'], None)
        self._check_and_set_default_scoping(auth_info, auth_context)
        (domain_id, project_id, unscoped) = auth_info.get_scope()

        method_names = auth_info.get_method_names()
        method_names += auth_context.get('method_names', [])
            # make sure the list is unique
        method_names = list(set(method_names))
        expires_at = auth_context.get('expires_at')
            # NOTE(morganfainberg): define this here so it is clear what the
            # argument is during the issue_v3_token provider call.
        metadata_ref = None

        token_audit_id = auth_context.get('audit_id')

        (token_id, token_data) = self.token_provider_api.issue_v3_token(
                auth_context['user_id'], method_names, expires_at, project_id,
                domain_id, auth_context, metadata_ref, include_catalog,
                parent_audit_id=token_audit_id)

        return render_token_data_response(token_id, token_data,
                                              created=True)

    def _check_and_set_default_scoping(self, auth_info, auth_context):
        (domain_id, project_id, unscoped) = auth_info.get_scope()
        if domain_id or project_id:
            # scope is specified
            return

        # Do not scope if request is for explicitly unscoped token
        if unscoped is not None:
            return

    def authenticate(self, context, auth_info, auth_context):
        """Authenticate user."""

        # The 'external' method allows any 'REMOTE_USER' based authentication
        # In some cases the server can set REMOTE_USER as '' instead of
        # dropping it, so this must be filtered out
        if context['environment'].get('REMOTE_USER'):
            try:
                external = get_auth_method('external')
                external.authenticate(context, auth_info, auth_context)
            except exception.AuthMethodNotSupported:
                # This will happen there is no 'external' plugin registered
                # and the container is performing authentication.
                # The 'kerberos'  and 'saml' methods will be used this way.
                # In those cases, it is correct to not register an
                # 'external' plugin;  if there is both an 'external' and a
                # 'kerberos' plugin, it would run the check on identity twice.
                LOG.debug("No 'external' plugin is registered.")
            except exception.Unauthorized:
                # If external fails then continue and attempt to determine
                # user identity using remaining auth methods
                LOG.debug("Authorization failed for 'external' auth method.")

        # need to aggregate the results in case two or more methods
        # are specified
        auth_response = {'methods': []}
        for method_name in auth_info.get_method_names():
            method = get_auth_method(method_name)
            resp = method.authenticate(context,
                                       auth_info.get_method_data(method_name),
                                       auth_context)
            if resp:
                auth_response['methods'].append(method_name)
                auth_response[method_name] = resp

        if auth_response["methods"]:
            # authentication continuation required
            raise exception.AdditionalAuthRequired(auth_response)

        if 'user_id' not in auth_context:
            msg = _('User not found')
            raise exception.Unauthorized(msg)

    @controller.protected()
    def check_token(self, context):
        token_id = context.get('subject_token_id')
        token_data = self.token_provider_api.validate_v3_token(
            token_id)
        # NOTE(morganfainberg): The code in
        # ``keystone.common.wsgi.render_response`` will remove the content
        # body.
        return render_token_data_response(token_id, token_data)

    @controller.protected()
    def revoke_token(self, context):
        token_id = context.get('subject_token_id')
        return self.token_provider_api.revoke_token(token_id)

    @controller.protected()
    def validate_token(self, context):
        token_id = context.get('subject_token_id')
        include_catalog = 'nocatalog' not in context['query_string']
        token_data = self.token_provider_api.validate_v3_token(
            token_id)
        if not include_catalog and 'catalog' in token_data['token']:
            del token_data['token']['catalog']
        return render_token_data_response(token_id, token_data)

    @controller.protected()
    def revocation_list(self, context, auth=None):
        if not CONF.token.revoke_by_id:
            raise exception.Gone()
        tokens = self.token_provider_api.list_revoked_tokens()

        for t in tokens:
            expires = t['expires']
            if not (expires and isinstance(expires, six.text_type)):
                t['expires'] = timeutils.isotime(expires)
        data = {'revoked': tokens}
        json_data = jsonutils.dumps(data)
        signed_text = cms.cms_sign_text(json_data,
                                        CONF.signing.certfile,
                                        CONF.signing.keyfile)

        return {'signed': signed_text}

    def _combine_lists_uniquely(self, a, b):
        # it's most likely that only one of these will be filled so avoid
        # the combination if possible.
        if a and b:
            return {x['id']: x for x in a + b}.values()
        else:
            return a or b

    @controller.protected()
    def get_auth_projects(self, context):
        auth_context = self.get_auth_context(context)

        user_id = auth_context.get('user_id')
        user_refs = []
        if user_id:
            try:
                user_refs = self.assignment_api.list_projects_for_user(user_id)
            except exception.UserNotFound:
                # federated users have an id but they don't link to anything
                pass

        group_ids = auth_context.get('group_ids')
        grp_refs = []
        if group_ids:
            grp_refs = self.assignment_api.list_projects_for_groups(group_ids)

        refs = self._combine_lists_uniquely(user_refs, grp_refs)
        return resource_controllers.Project.wrap_collection(context, refs)

    @controller.protected()
    def get_auth_domains(self, context):
        auth_context = self.get_auth_context(context)

        user_id = auth_context.get('user_id')
        user_refs = []
        if user_id:
            try:
                user_refs = self.assignment_api.list_domains_for_user(user_id)
            except exception.UserNotFound:
                # federated users have an id but they don't link to anything
                pass

        group_ids = auth_context.get('group_ids')
        grp_refs = []
        if group_ids:
            grp_refs = self.assignment_api.list_domains_for_groups(group_ids)

        refs = self._combine_lists_uniquely(user_refs, grp_refs)
        return resource_controllers.Domain.wrap_collection(context, refs)

    @controller.protected()
    def get_auth_catalog(self, context):
        auth_context = self.get_auth_context(context)
        user_id = auth_context.get('user_id')
        project_id = auth_context.get('project_id')

        if not project_id:
            raise exception.Forbidden(
                _('A project-scoped token is required to produce a service '
                  'catalog.'))

        # The Controller base methods mostly assume that you're returning
        # either a collection or a single element from a collection, neither of
        # which apply to the catalog. Because this is a special case, this
        # re-implements a tiny bit of work done by the base controller (such as
        # self-referential link building) to avoid overriding or refactoring
        # several private methods.
        return {
            'catalog': self.catalog_api.get_v3_catalog(user_id, project_id),
            'links': {'self': self.base_url(context, path='auth/catalog')}
        }


# FIXME(gyee): not sure if it belongs here or keystone.common. Park it here
# for now.
def render_token_data_response(token_id, token_data, created=False):
    """Render token data HTTP response.

    Stash token ID into the X-Subject-Token header.

    """
    headers = [('X-Subject-Token', token_id)]

    if created:
        status = (201, 'Created')
    else:
        status = (200, 'OK')

    return wsgi.render_response(body=token_data,
                                status=status, headers=headers)
