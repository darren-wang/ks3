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
        user_ref.pop('tenants', None)
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
@dependency.requires('assignment_api', 'id_mapping_api', 'resource_api',
                     'revoke_api')
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

    def __init__(self):
        super(Manager, self).__init__(CONF.identity.driver)
        self.domain_configs = DomainConfigs()

        self.event_callbacks = {
            notifications.ACTIONS.deleted: {
                'domain': [self._domain_deleted],
            },
        }

    def _domain_deleted(self, service, resource_type, operation,
                        payload):
        domain_id = payload['resource_info']

        user_refs = self.list_users(domain_scope=domain_id)

        # And finally, delete the users themselves
        for user in user_refs:
            try:
                self.delete_user(user['id'])
            except exception.UserNotFound:
                LOG.debug(('User %(userid)s not found when deleting domain '
                           'contents for %(domainid)s, continuing with '
                           'cleanup.'),
                          {'userid': user['id'], 'domainid': domain_id})

    # Domain ID normalization methods

    def _set_domain_id_and_mapping(self, ref, domain_id, driver,
                                   entity_type):
        """Patch the domain_id/public_id into the resulting entity(ies).

        :param ref: the entity or list of entities to post process
        :param domain_id: the domain scope used for the call
        :param driver: the driver used to execute the call
        :param entity_type: whether this is a user or group

        :returns: post processed entity or list or entities

        Called to post-process the entity being returned, using a mapping
        to substitute a public facing ID as necessary. This method must
        take into account:

        - If the driver is not domain aware, then we must set the domain
          attribute of all entities irrespective of mapping.
        - If the driver does not support UUIDs, then we always want to provide
          a mapping, except for the special case of this being the default
          driver and backward_compatible_ids is set to True. This is to ensure
          that entity IDs do not change for an existing LDAP installation (only
          single domain/driver LDAP configurations were previously supported).
        - If the driver does support UUIDs, then we always create a mapping
          entry, but use the local UUID as the public ID.  The exception to
        - this is that if we just have single driver (i.e. not using specific
          multi-domain configs), then we don't both with the mapping at all.

        """
        conf = CONF.identity

        if not self._needs_post_processing(driver):
            # a classic case would be when running with a single SQL driver
            return ref

        LOG.debug('ID Mapping - Domain ID: %(domain)s, '
                  'Default Driver: %(driver)s, '
                  'Domains: %(aware)s, UUIDs: %(generate)s, '
                  'Compatible IDs: %(compat)s',
                  {'domain': domain_id,
                   'driver': (driver == self.driver),
                   'aware': driver.is_domain_aware(),
                   'generate': driver.generates_uuids(),
                   'compat': CONF.identity_mapping.backward_compatible_ids})

        if isinstance(ref, dict):
            return self._set_domain_id_and_mapping_for_single_ref(
                ref, domain_id, driver, entity_type, conf)
        elif isinstance(ref, list):
            return [self._set_domain_id_and_mapping(
                    x, domain_id, driver, entity_type) for x in ref]
        else:
            raise ValueError(_('Expected dict or list: %s') % type(ref))

    def _needs_post_processing(self, driver):
        """Returns whether entity from driver needs domain added or mapping."""
        return (driver is not self.driver or not driver.generates_uuids() or
                not driver.is_domain_aware())

    def _set_domain_id_and_mapping_for_single_ref(self, ref, domain_id,
                                                  driver, entity_type, conf):
        LOG.debug('Local ID: %s', ref['id'])
        ref = ref.copy()

        self._insert_domain_id_if_needed(ref, driver, domain_id, conf)

        if self._is_mapping_needed(driver):
            local_entity = {'domain_id': ref['domain_id'],
                            'local_id': ref['id'],
                            'entity_type': entity_type}
            public_id = self.id_mapping_api.get_public_id(local_entity)
            if public_id:
                ref['id'] = public_id
                LOG.debug('Found existing mapping to public ID: %s',
                          ref['id'])
            else:
                # Need to create a mapping. If the driver generates UUIDs
                # then pass the local UUID in as the public ID to use.
                if driver.generates_uuids():
                    public_id = ref['id']
                ref['id'] = self.id_mapping_api.create_id_mapping(
                    local_entity, public_id)
                LOG.debug('Created new mapping to public ID: %s',
                          ref['id'])
        return ref

    def _insert_domain_id_if_needed(self, ref, driver, domain_id, conf):
        """Inserts the domain ID into the ref, if required.

        If the driver can't handle domains, then we need to insert the
        domain_id into the entity being returned.  If the domain_id is
        None that means we are running in a single backend mode, so to
        remain backwardly compatible, we put in the default domain ID.
        """
        if not driver.is_domain_aware():
            if domain_id is None:
                domain_id = conf.admin_domain_id
            ref['domain_id'] = domain_id

    def _is_mapping_needed(self, driver):
        """Returns whether mapping is needed.

        There are two situations where we must use the mapping:
        - this isn't the default driver (i.e. multiple backends), or
        - we have a single backend that doesn't use UUIDs
        The exception to the above is that we must honor backward
        compatibility if this is the default driver (e.g. to support
        current LDAP)
        """
        is_not_default_driver = driver is not self.driver
        return (is_not_default_driver or (
            not driver.generates_uuids() and
            not CONF.identity_mapping.backward_compatible_ids))

    def _clear_domain_id_if_domain_unaware(self, driver, ref):
        """Clear domain_id details if driver is not domain aware."""
        if not driver.is_domain_aware() and 'domain_id' in ref:
            ref = ref.copy()
            ref.pop('domain_id')
        return ref

    def _select_identity_driver(self, domain_id):
        """Choose a backend driver for the given domain_id.

        :param domain_id: The domain_id for which we want to find a driver.  If
                          the domain_id is specified as None, then this means
                          we need a driver that handles multiple domains.

        :returns: chosen backend driver

        If there is a specific driver defined for this domain then choose it.
        If the domain is None, or there no specific backend for the given
        domain is found, then we chose the default driver.

        """
        if domain_id is None:
            driver = self.driver
        else:
            driver = (self.domain_configs.get_domain_driver(domain_id) or
                      self.driver)

        # If the driver is not domain aware (e.g. LDAP) then check to
        # ensure we are not mapping multiple domains onto it - the only way
        # that would happen is that the default driver is LDAP and the
        # domain is anything other than None or the default domain.
        if (not driver.is_domain_aware() and driver == self.driver and
            domain_id != CONF.identity.admin_domain_id and
                domain_id is not None):
                    LOG.warning('Found multiple domains being mapped to a '
                                'driver that does not support that (e.g. '
                                'LDAP) - Domain ID: %(domain)s, '
                                'Default Driver: %(driver)s',
                                {'domain': domain_id,
                                 'driver': (driver == self.driver)})
                    raise exception.DomainNotFound(domain_id=domain_id)
        return driver

    def _get_domain_driver_and_entity_id(self, public_id):
        """Look up details using the public ID.

        :param public_id: the ID provided in the call

        :returns: domain_id, which can be None to indicate that the driver
                  in question supports multiple domains
                  driver selected based on this domain
                  entity_id which will is understood by the driver.

        Use the mapping table to look up the domain, driver and local entity
        that is represented by the provided public ID.  Handle the situations
        were we do not use the mapping (e.g. single driver that understands
        UUIDs etc.)

        """
        conf = CONF.identity
        # First, since we don't know anything about the entity yet, we must
        # assume it needs mapping, so long as we are using domain specific
        # drivers.
        if conf.domain_specific_drivers_enabled:
            local_id_ref = self.id_mapping_api.get_id_mapping(public_id)
            if local_id_ref:
                return (
                    local_id_ref['domain_id'],
                    self._select_identity_driver(local_id_ref['domain_id']),
                    local_id_ref['local_id'])

        # So either we are using multiple drivers but the public ID is invalid
        # (and hence was not found in the mapping table), or the public ID is
        # being handled by the default driver.  Either way, the only place left
        # to look is in that standard driver. However, we don't yet know if
        # this driver also needs mapping (e.g. LDAP in non backward
        # compatibility mode).
        driver = self.driver
        if driver.generates_uuids():
            if driver.is_domain_aware:
                # No mapping required, and the driver can handle the domain
                # information itself.  The classic case of this is the
                # current SQL driver.
                return (None, driver, public_id)
            else:
                # Although we don't have any drivers of this type, i.e. that
                # understand UUIDs but not domains, conceptually you could.
                return (conf.admin_domain_id, driver, public_id)

        # So the only place left to find the ID is in the default driver which
        # we now know doesn't generate UUIDs
        if not CONF.identity_mapping.backward_compatible_ids:
            # We are not running in backward compatibility mode, so we
            # must use a mapping.
            local_id_ref = self.id_mapping_api.get_id_mapping(public_id)
            if local_id_ref:
                return (
                    local_id_ref['domain_id'],
                    driver,
                    local_id_ref['local_id'])
            else:
                raise exception.PublicIDNotFound(id=public_id)

        # If we reach here, this means that the default driver
        # requires no mapping - but also doesn't understand domains
        # (e.g. the classic single LDAP driver situation). Hence we pass
        # back the public_ID unmodified and use the default domain (to
        # keep backwards compatibility with existing installations).
        #
        # It is still possible that the public ID is just invalid in
        # which case we leave this to the caller to check.
        return (conf.admin_domain_id, driver, public_id)

    def _mark_domain_id_filter_satisfied(self, hints):
        if hints:
            for filter in hints.filters:
                if (filter['name'] == 'domain_id' and
                        filter['comparator'] == 'equals'):
                    hints.filters.remove(filter)

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
        domain_id, driver, entity_id = (
            self._get_domain_driver_and_entity_id(user_id))
        ref = driver.authenticate(entity_id, password)
        return self._set_domain_id_and_mapping(
            ref, domain_id, driver, mapping.EntityType.USER)

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
        driver = self._select_identity_driver(domain_id)
        user = self._clear_domain_id_if_domain_unaware(driver, user)
        # Generate a local ID - in the future this might become a function of
        # the underlying driver so that it could conform to rules set down by
        # that particular driver type.
        user['id'] = uuid.uuid4().hex
        ref = driver.create_user(user['id'], user)
        notifications.Audit.created(self._USER, user['id'], initiator)
        return self._set_domain_id_and_mapping(
            ref, domain_id, driver, mapping.EntityType.USER)

    @exception_translated('user')
    @MEMOIZE
    def get_user(self, user_id):
        domain_id, driver, entity_id = (
            self._get_domain_driver_and_entity_id(user_id))
        ref = driver.get_user(entity_id)
        return self._set_domain_id_and_mapping(
            ref, domain_id, driver, mapping.EntityType.USER)

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
        driver = self._select_identity_driver(domain_id)
        ref = driver.get_user_by_name(user_name, domain_id)
        return self._set_domain_id_and_mapping(
            ref, domain_id, driver, mapping.EntityType.USER)

    @manager.response_truncated
    @exception_translated('user')
    def list_users(self, domain_scope=None, hints=None):
        driver = self._select_identity_driver(domain_scope)
        hints = hints or driver_hints.Hints()
        if driver.is_domain_aware():
            # Force the domain_scope into the hint to ensure that we only get
            # back domains for that scope.
            self._ensure_domain_id_in_hints(hints, domain_scope)
        else:
            # We are effectively satisfying any domain_id filter by the above
            # driver selection, so remove any such filter.
            self._mark_domain_id_filter_satisfied(hints)
        ref_list = driver.list_users(hints)
        return self._set_domain_id_and_mapping(
            ref_list, domain_scope, driver, mapping.EntityType.USER)

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

        domain_id, driver, entity_id = (
            self._get_domain_driver_and_entity_id(user_id))
        user = self._clear_domain_id_if_domain_unaware(driver, user)
        self.get_user.invalidate(self, old_user_ref['id'])
        self.get_user_by_name.invalidate(self, old_user_ref['name'],
                                         old_user_ref['domain_id'])

        ref = driver.update_user(entity_id, user)

        notifications.Audit.updated(self._USER, user_id, initiator)

        enabled_change = ((user.get('enabled') is False) and
                          user['enabled'] != old_user_ref.get('enabled'))
        if enabled_change or user.get('password') is not None:
            self.emit_invalidate_user_token_persistence(user_id)

        return self._set_domain_id_and_mapping(
            ref, domain_id, driver, mapping.EntityType.USER)

    @exception_translated('user')
    def delete_user(self, user_id, initiator=None):
        domain_id, driver, entity_id = (
            self._get_domain_driver_and_entity_id(user_id))
        # Get user details to invalidate the cache.
        user_old = self.get_user(user_id)
        driver.delete_user(entity_id)
        self.assignment_api.delete_user(user_id)
        self.get_user.invalidate(self, user_id)
        self.get_user_by_name.invalidate(self, user_old['name'],
                                         user_old['domain_id'])
        self.id_mapping_api.delete_id_mapping(user_id)
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

    def change_password(self, context, user_id, original_password,
                        new_password):

        # authenticate() will raise an AssertionError if authentication fails
        self.authenticate(context, user_id, original_password)

        update_dict = {'password': new_password}
        self.update_user(user_id, update_dict)


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

    # end of identity
