# Copyright 2012 OpenStack Foundation
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

"""Main entry point into the Identity service."""

import abc
import functools
import os
import uuid

from oslo_config import cfg
from oslo_log import log
from oslo_utils import importutils
import six

from keystone import clean
from keystone.common import cache
from keystone.common import dependency
from keystone.common import driver_hints
from keystone.common import manager
from keystone import config
from keystone import exception
from keystone.i18n import _, _LW
from keystone import notifications


CONF = cfg.CONF

LOG = log.getLogger(__name__)

MEMOIZE = cache.get_memoization_decorator(section='identity')

DOMAIN_CONF_FHEAD = 'keystone.'
DOMAIN_CONF_FTAIL = '.conf'


def filter_user(user_ref):
    """Filter out private items in a user dict.

    'password', 'tenants' and 'groups' are never returned.

    :returns: user_ref

    """
    if user_ref:
        user_ref = user_ref.copy()
        user_ref.pop('password', None)
        user_ref.pop('projects', None)
        user_ref.pop('groups', None)
        user_ref.pop('domains', None)
        try:
            user_ref['extra'].pop('password', None)
            user_ref['extra'].pop('tenants', None)
        except KeyError:
            pass
    return user_ref


def exception_translated(exception_type):
    """Wraps API calls to map to correct exception."""

    def _exception_translated(f):
        @functools.wraps(f)
        def wrapper(self, *args, **kwargs):
            try:
                return f(self, *args, **kwargs)
            except exception.PublicIDNotFound as e:
                if exception_type == 'user':
                    raise exception.UserNotFound(user_id=str(e))
                elif exception_type == 'group':
                    raise exception.GroupNotFound(group_id=str(e))
                elif exception_type == 'assertion':
                    raise AssertionError(_('Invalid user / password'))
                else:
                    raise
        return wrapper
    return _exception_translated


@dependency.provider('identity_api')
@dependency.requires('assignment_api', 'resource_api', 'revoke_api')
class Manager(manager.Manager):
    """Default pivot point for the Identity backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    This class also handles the support of domain specific backends, by using
    the DomainConfigs class. The setup call for DomainConfigs is called
    from with the @domains_configured wrapper in a lazy loading fashion
    to get around the fact that we can't satisfy the assignment api it needs
    from within our __init__() function since the assignment driver is not
    itself yet initialized.

    Each of the identity calls are pre-processed here to choose, based on
    domain, which of the drivers should be called. The non-domain-specific
    driver is still in place, and is used if there is no specific driver for
    the domain in question (or we are not using multiple domain drivers).

    Starting with Juno, in order to be able to obtain the domain from
    just an ID being presented as part of an API call, a public ID to domain
    and local ID mapping is maintained.  This mapping also allows for the local
    ID of drivers that do not provide simple UUIDs (such as LDAP) to be
    referenced via a public facing ID.  The mapping itself is automatically
    generated as entities are accessed via the driver.

    This mapping is only used when:
    - the entity is being handled by anything other than the default driver, or
    - the entity is being handled by the default LDAP driver and backward
    compatible IDs are not required.

    This means that in the standard case of a single SQL backend or the default
    settings of a single LDAP backend (since backward compatible IDs is set to
    True by default), no mapping is used. An alternative approach would be to
    always use the mapping table, but in the cases where we don't need it to
    make the public and local IDs the same. It is felt that not using the
    mapping by default is a more prudent way to introduce this functionality.

    """
    _USER = 'user'
    _GROUP = 'group'

    def __init__(self):
        super(Manager, self).__init__(CONF.identity.driver)

        self.event_callbacks = {
            notifications.ACTIONS.deleted: {
                'domain': [self._domain_deleted],
            },
        }

    def _domain_deleted(self, service, resource_type, operation,
                        payload):
        domain_id = payload['resource_info']

        user_refs = self.list_users(domain_scope=domain_id)
        group_refs = self.list_groups(domain_scope=domain_id)

        for group in group_refs:
            # Cleanup any existing groups.
            try:
                self.delete_group(group['id'])
            except exception.GroupNotFound:
                LOG.debug(('Group %(groupid)s not found when deleting domain '
                           'contents for %(domainid)s, continuing with '
                           'cleanup.'),
                          {'groupid': group['id'], 'domainid': domain_id})

        # And finally, delete the users themselves
        for user in user_refs:
            try:
                self.delete_user(user['id'])
            except exception.UserNotFound:
                LOG.debug(('User %(userid)s not found when deleting domain '
                           'contents for %(domainid)s, continuing with '
                           'cleanup.'),
                          {'userid': user['id'], 'domainid': domain_id})

    def _ensure_domain_id_in_hints(self, hints, domain_id):
        if (domain_id is not None and
                not hints.get_exact_filter_by_name('domain_id')):
            hints.add_filter('domain_id', domain_id)

    # The actual driver calls - these are pre/post processed here as
    # part of the Manager layer to make sure we:
    #
    # - select the right driver for this domain
    # - clear/set domain_ids for drivers that do not support domains
    # - create any ID mapping that might be required

    @notifications.emit_event('authenticate')
    @exception_translated('assertion')
    def authenticate(self, context, user_id, password):
        return self.driver.authenticate(user_id, password)

    @exception_translated('user')
    def create_user(self, user_ref, initiator=None):
        user = user_ref.copy()
        user['name'] = clean.user_name(user['name'])
        user.setdefault('enabled', True)
        user['enabled'] = clean.user_enabled(user['enabled'])
        domain_id = user['domain_id']
        self.resource_api.get_domain(domain_id)

        # For creating a user, the domain is in the object itself
        domain_id = user_ref['domain_id']

        # Generate a local ID - in the future this might become a function of
        # the underlying driver so that it could conform to rules set down by
        # that particular driver type.
        user['id'] = uuid.uuid4().hex
        ref = self.driver.create_user(user['id'], user)
        notifications.Audit.created(self._USER, user['id'], initiator)
        return ref

    @exception_translated('user')
    @MEMOIZE
    def get_user(self, user_id):
        return self.driver.get_user(user_id)

    def assert_user_enabled(self, user_id, user=None):
        """Assert the user and the user's domain are enabled.

        :raise AssertionError if the user or the user's domain is disabled.
        """
        if user is None:
            user = self.get_user(user_id)
        self.resource_api.assert_domain_enabled(user['domain_id'])
        if not user.get('enabled', True):
            raise AssertionError(_('User is disabled: %s') % user_id)

    @exception_translated('user')
    @MEMOIZE
    def get_user_by_name(self, user_name, domain_id):
        return self.driver.get_user_by_name(user_name, domain_id)

    @manager.response_truncated
    @exception_translated('user')
    def list_users(self, domain_scope=None, hints=None):
        hints = hints or driver_hints.Hints()
        # Force the domain_scope into the hint to ensure that we only get
        # back domains for that scope.
        self._ensure_domain_id_in_hints(hints, domain_scope)

        return self.driver.list_users(hints)
        

    @exception_translated('user')
    def update_user(self, user_id, user_ref, initiator=None):
        old_user_ref = self.get_user(user_id)
        user = user_ref.copy()
        if 'name' in user:
            user['name'] = clean.user_name(user['name'])
        if 'enabled' in user:
            user['enabled'] = clean.user_enabled(user['enabled'])
        if 'domain_id' in user:
            self.resource_api.get_domain(user['domain_id'])
        if 'id' in user:
            if user_id != user['id']:
                raise exception.ValidationError(_('Cannot change user ID'))
            # Since any ID in the user dict is now irrelevant, remove its so as
            # the driver layer won't be confused by the fact the this is the
            # public ID not the local ID
            user.pop('id')

        self.get_user.invalidate(self, old_user_ref['id'])
        self.get_user_by_name.invalidate(self, old_user_ref['name'],
                                         old_user_ref['domain_id'])

        ref = self.driver.update_user(user_id, user)

        notifications.Audit.updated(self._USER, user_id, initiator)

        enabled_change = ((user.get('enabled') is False) and
                          user['enabled'] != old_user_ref.get('enabled'))
        if enabled_change or user.get('password') is not None:
            self.emit_invalidate_user_token_persistence(user_id)

        return ref

    @exception_translated('user')
    def delete_user(self, user_id, initiator=None):
        # Get user details to invalidate the cache.
        user_old = self.get_user(user_id)
        self.driver.delete_user(user_id)
        self.assignment_api.delete_user(user_id)
        self.get_user.invalidate(self, user_id)
        self.get_user_by_name.invalidate(self, user_old['name'],
                                         user_old['domain_id'])
        notifications.Audit.deleted(self._USER, user_id, initiator)

    @notifications.internal(notifications.INVALIDATE_USER_TOKEN_PERSISTENCE)
    def emit_invalidate_user_token_persistence(self, user_id):
        """Emit a notification to the callback system to revoke user tokens.

        This method and associated callback listener removes the need for
        making a direct call to another manager to delete and revoke tokens.

        :param user_id: user identifier
        :type user_id: string
        """
        pass

    @notifications.internal(
        notifications.INVALIDATE_USER_PROJECT_TOKEN_PERSISTENCE)
    def emit_invalidate_grant_token_persistence(self, user_project):
        """Emit a notification to the callback system to revoke grant tokens.
        This method and associated callback listener removes the need for
        making a direct call to another manager to delete and revoke tokens.
        :param user_project: {'user_id': user_id, 'project_id': project_id}
        :type user_project: dict
        """
        pass

    def change_password(self, context, user_id, original_password,
                        new_password):

        # authenticate() will raise an AssertionError if authentication fails
        self.authenticate(context, user_id, original_password)

        update_dict = {'password': new_password}
        self.update_user(user_id, update_dict)

    @exception_translated('group')
    def create_group(self, group_ref, initiator=None):
        group = group_ref.copy()
        group.setdefault('description', '')
        domain_id = group['domain_id']
        self.resource_api.get_domain(domain_id)

        # For creating a group, the domain is in the object itself
        domain_id = group_ref['domain_id']
        driver = self._select_identity_driver(domain_id)
        group = self._clear_domain_id_if_domain_unaware(driver, group)
        # Generate a local ID - in the future this might become a function of
        # the underlying driver so that it could conform to rules set down by
        # that particular driver type.
        group['id'] = uuid.uuid4().hex
        ref = driver.create_group(group['id'], group)

        notifications.Audit.created(self._GROUP, group['id'], initiator)

        return ref

    @exception_translated('group')
    @MEMOIZE
    def get_group(self, group_id):
        ref = self.driver.get_group(group_id)
        return ref

    @exception_translated('group')
    def get_group_by_name(self, group_name, domain_id):
        ref = self.driver.get_group_by_name(group_name, domain_id)
        return ref

    @exception_translated('group')
    def update_group(self, group_id, group, initiator=None):
        if 'domain_id' in group:
            self.resource_api.get_domain(group['domain_id'])
        ref = self.driver.update_group(group_id, group)
        self.get_group.invalidate(self, group_id)
        notifications.Audit.updated(self._GROUP, group_id, initiator)
        return ref

    @exception_translated('group')
    def delete_group(self, group_id, initiator=None):
        user_ids = (u['id'] for u in self.list_users_in_group(group_id))
        self.driver.delete_group(group_id)
        self.get_group.invalidate(self, group_id)
        self.assignment_api.delete_group(group_id)

        notifications.Audit.deleted(self._GROUP, group_id, initiator)

        for uid in user_ids:
            self.emit_invalidate_user_token_persistence(uid)

    @exception_translated('group')
    def add_user_to_group(self, user_id, group_id):
        self.driver.add_user_to_group(user_id, group_id)

    @exception_translated('group')
    def remove_user_from_group(self, user_id, group_id):
        self.driver.remove_user_from_group(user_id, group_id)
        self.emit_invalidate_user_token_persistence(user_id)

    @manager.response_truncated
    @exception_translated('user')
    def list_groups_for_user(self, user_id, hints=None):
        hints = hints or driver_hints.Hints()
        ref_list = self.driver.list_groups_for_user(user_id, hints)
        return ref_list

    @manager.response_truncated
    @exception_translated('group')
    def list_groups(self, domain_scope=None, hints=None):
        hints = hints or driver_hints.Hints()
        self._ensure_domain_id_in_hints(hints, domain_scope)
        ref_list = self.driver.list_groups(hints)
        return ref_list

    @manager.response_truncated
    @exception_translated('group')
    def list_users_in_group(self, group_id, hints=None):
        hints = hints or driver_hints.Hints()
        ref_list = self.driver.list_users_in_group(group_id, hints)
        return ref_list

    @exception_translated('group')
    def check_user_in_group(self, user_id, group_id):
        return self.driver.check_user_in_group(user_id, group_id)


@six.add_metaclass(abc.ABCMeta)
class Driver(object):
    """Interface description for an Identity driver."""

    def _get_list_limit(self):
        return CONF.identity.list_limit or CONF.list_limit

    def is_domain_aware(self):
        """Indicates if Driver supports domains."""
        return True

    @property
    def is_sql(self):
        """Indicates if this Driver uses SQL."""
        return False

    def generates_uuids(self):
        """Indicates if Driver generates UUIDs as the local entity ID."""
        return True

    @abc.abstractmethod
    def authenticate(self, user_id, password):
        """Authenticate a given user and password.
        :returns: user_ref
        :raises: AssertionError
        """
        raise exception.NotImplemented()  # pragma: no cover

    # user crud

    @abc.abstractmethod
    def create_user(self, user_id, user):
        """Creates a new user.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_users(self, hints):
        """List users in the system.

        :param hints: filter hints which the driver should
                      implement if at all possible.

        :returns: a list of user_refs or an empty list.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_user(self, user_id):
        """Get a user by ID.

        :returns: user_ref
        :raises: keystone.exception.UserNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_user(self, user_id, user):
        """Updates an existing user.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.Conflict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_user(self, user_id):
        """Deletes an existing user.

        :raises: keystone.exception.UserNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_user_by_name(self, user_name, domain_id):
        """Get a user by name.

        :returns: user_ref
        :raises: keystone.exception.UserNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover
    
    @abc.abstractmethod
    def list_users_in_group(self, group_id, hints):
        """List users in a group.
        :param group_id: the group in question
        :param hints: filter hints which the driver should
                      implement if at all possible.
        :returns: a list of user_refs or an empty list.
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def add_user_to_group(self, user_id, group_id):
        """Adds a user to a group.
        :raises: keystone.exception.UserNotFound,
                 keystone.exception.GroupNotFound
        """
        raise exception.NotImplemented()  # pragma: no cover


    @abc.abstractmethod
    def check_user_in_group(self, user_id, group_id):
        """Checks if a user is a member of a group.
        :raises: keystone.exception.UserNotFound,
                 keystone.exception.GroupNotFound
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def remove_user_from_group(self, user_id, group_id):
        """Removes a user from a group.
        :raises: keystone.exception.NotFound
        """
        raise exception.NotImplemented()  # pragma: no cover

    # group crud

    @abc.abstractmethod
    def create_group(self, group_id, group):
        """Creates a new group.
        :raises: keystone.exception.Conflict
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_groups(self, hints):
        """List groups in the system.
        :param hints: filter hints which the driver should
                      implement if at all possible.
        :returns: a list of group_refs or an empty list.
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_groups_for_user(self, user_id, hints):
        """List groups a user is in
        :param user_id: the user in question
        :param hints: filter hints which the driver should
                      implement if at all possible.
        :returns: a list of group_refs or an empty list.
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_group(self, group_id):
        """Get a group by ID.
        :returns: group_ref
        :raises: keystone.exception.GroupNotFound
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_group_by_name(self, group_name, domain_id):
        """Get a group by name.
        :returns: group_ref
        :raises: keystone.exception.GroupNotFound
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_group(self, group_id, group):
        """Updates an existing group.
        :raises: keystone.exceptionGroupNotFound,
                 keystone.exception.Conflict
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_group(self, group_id):
        """Deletes an existing group.
        :raises: keystone.exception.GroupNotFound
        """
        raise exception.NotImplemented()  # pragma: no cover

    # end of identity