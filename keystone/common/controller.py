# Copyright 2013 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import functools
import uuid

from oslo_config import cfg
from oslo_log import log
from oslo_policy import policy
from oslo_serialization import jsonutils
import six

from keystone.common import authorization
from keystone.common import dependency
from keystone.common import driver_hints
from keystone.common import utils
from keystone.common import wsgi
from keystone import exception
from keystone.i18n import _, _LW
from keystone.models import token_model


LOG = log.getLogger(__name__)
CONF = cfg.CONF


def _build_policy_check_credentials(self, action, context, kwargs):
    LOG.debug('RBAC: Authorizing %(serv)s:%(perm)s(%(kwargs)s)', {
        'serv': action[0],
        'perm': action[1],
        'kwargs': ', '.join(['%s=%s' % (k, kwargs[k]) for k in kwargs])})

    # see if auth context has already been created. If so use it.
    if ('environment' in context and
            authorization.AUTH_CONTEXT_ENV in context['environment']):
        LOG.debug('RBAC: using auth context from the request environment')
        return context['environment'].get(authorization.AUTH_CONTEXT_ENV)

    # There is no current auth context, build it from the incoming token.
    # TODO(morganfainberg): Collapse this logic with AuthContextMiddleware
    # in a sane manner as this just mirrors the logic in AuthContextMiddleware
    try:
        LOG.debug('RBAC: building auth context from the incoming auth token')
        token_ref = token_model.KeystoneToken(
            token_id=context['token_id'],
            token_data=self.token_provider_api.validate_token(
                context['token_id']))
        # NOTE(jamielennox): whilst this maybe shouldn't be within this
        # function it would otherwise need to reload the token_ref from
        # backing store.
        wsgi.validate_token_bind(context, token_ref)
    except exception.TokenNotFound:
        LOG.warning(_LW('RBAC: Invalid token'))
        raise exception.Unauthorized()

    auth_context = authorization.token_to_auth_context(token_ref)

    return auth_context


def protected(callback=None):
    """Wraps API calls with role based access controls (RBAC).

    This handles both the protection of the API parameters as well as any
    target entities for single-entity API calls.

    More complex API calls (for example that deal with several different
    entities) should pass in a callback function, that will be subsequently
    called to check protection for these multiple entities. This callback
    function should gather the appropriate entities needed and then call
    check_protection() in the Controller class.

    """
    def wrapper(f):
        @functools.wraps(f)
        def inner(self, context, *args, **kwargs):
            if 'is_admin' in context and context['is_admin']:
                LOG.warning(_LW('RBAC: Bypassing authorization'))
            elif callback is not None:
                prep_info = {'f_name': f.__name__,
                             'input_attr': kwargs}
                callback(self, context, prep_info, *args, **kwargs)
            else:
                action = ('keystone', f.__name__)
                creds = _build_policy_check_credentials(self, action,
                                                        context, kwargs)
                
                target = {}

                # Check to see if we need to include the target entity in our
                # policy checks.  We deduce this by seeing if the class has
                # specified a get_member() method and that kwargs contains the
                # appropriate entity id.
                if (hasattr(self, 'get_member_from_driver') and
                        self.get_member_from_driver is not None):
                    key = '%s_id' % self.member_name
                    if key in kwargs:
                        ref = self.get_member_from_driver(kwargs[key])
                        target['obj'] = {self.member_name: ref}

                # TODO(henry-nash): Move this entire code to a member
                # method inside v3 Auth
                if context.get('subject_token_id') is not None:
                    ks_token = token_model.KeystoneToken(
                        token_id=context['subject_token_id'],
                        token_data=self.token_provider_api.validate_token(
                            context['subject_token_id']))
                    target.setdefault('obj', {})
                    target['obj'].setdefault(self.member_name, {})
                    target['obj'][self.member_name]['user_id'] = (
                        ks_token.user_id)
                    try:
                        user_domain_id = ks_token.user_domain_id
                    except exception.UnexpectedError:
                        user_domain_id = None
                    if user_domain_id:
                        target['obj'][self.member_name].setdefault(
                            'user', {})
                        target['obj'][self.member_name][
                            'user'].setdefault('domain', {})
                        target['obj'][self.member_name]['user'][
                            'domain']['id'] = (user_domain_id)

                # Add in the kwargs, which means reqBody in create and 
                # update operations.

                subParams = {}
                for k in kwargs.iterkeys():
                    if isinstance(kwargs[k], dict):
                        subParams['reqBody.'+k] = kwargs[k]
                    else:
                        subParams['url.'+k] = kwargs[k]
                target.update(subParams)
                target = utils.flatten_dict(target)

                LOG.debug('Evaluating against System Authz Policies')
                self.policy_api.enforce(action, target, creds, 'system')

                LOG.debug('Evaluating against Domain Authz Policies')
                self.policy_api.enforce(action, target, creds, 'domain')
                LOG.debug('\n#### CREDS HERE ####\n')
                LOG.debug(creds)
                LOG.debug('\n#### TARGET HERE ####\n')
                LOG.debug(target)
            return f(self, context, *args, **kwargs)
        return inner
    return wrapper


def filterprotected(*filters):
    """Wraps filtered API calls with role based access controls (RBAC)."""
    def _filterprotected(f):
        @functools.wraps(f)
        def wrapper(self, context, **kwargs):
            if 'is_admin' in context and context['is_admin']:
                LOG.warning(_LW('RBAC: Bypassing authorization'))
            else:
                action = ('keystone', f.__name__)
                creds = _build_policy_check_credentials(self,
                                                        action,
                                                        context, kwargs)
                
                # Now, build the target dict for policy check.  We include:
                #
                # - Any query filter parameters
                # - Data from the main url (which will be in the kwargs
                #   parameter) and would typically include the prime key
                #   of a get/update/delete call
                #
                # First  any query filter parameters
                target = dict()
                if filters:
                    for item in filters:
                        if item in context['query_string']:
                            target['qStr.'+item] = context['query_string'][item]

                    LOG.debug('RBAC: Adding query filter params (%s)', (
                        ', '.join(['%s=%s' % (item, target[item])
                                  for item in target])))

                # Now any formal url parameters
                for key in kwargs:
                    target['url.'+key] = kwargs[key]
                target = utils.flatten_dict(target)

                LOG.debug('Evaluating against System Authz Policies')
                self.policy_api.enforce(action, target, creds)

                LOG.debug('Evaluating against Domain Authz Policies')
                self.policy_api.enforce(action, target, creds,
                                        check_type='domain')

                LOG.debug('\n#### CREDS HERE ####\n')
                LOG.debug(creds)
                LOG.debug('\n#### TARGET HERE ####\n')
                LOG.debug(target)
            return f(self, context, filters, **kwargs)
        return wrapper
    return _filterprotected


@dependency.requires('policy_api', 'token_provider_api')
class Controller(wsgi.Application):
    """Base controller class for Identity API v3.

    Child classes should set the ``collection_name`` and ``member_name`` class
    attributes, representing the collection of entities they are exposing to
    the API. This is required for supporting self-referential links,
    pagination, etc.

    Class parameters:

    * `_mutable_parameters` - set of parameters that can be changed by users.
                              Usually used by cls.check_immutable_params()
    * `_public_parameters` - set of parameters that are exposed to the user.
                             Usually used by cls.filter_params()

    """

    collection_name = 'entities'
    member_name = 'entity'
    get_member_from_driver = None

    @classmethod
    def base_url(cls, context, path=None):
        endpoint = super(Controller, cls).base_url(context, 'public')
        if not path:
            path = cls.collection_name

        return '%s/%s/%s' % (endpoint, 'v3', path.lstrip('/'))

    def get_auth_context(self, context):
        # TODO(dolphm): this method of accessing the auth context is terrible,
        # but context needs to be refactored to always have reasonable values.
        env_context = context.get('environment', {})
        return env_context.get(authorization.AUTH_CONTEXT_ENV, {})

    @classmethod
    def full_url(cls, context, path=None):
        url = cls.base_url(context, path)
        if context['environment'].get('QUERY_STRING'):
            url = '%s?%s' % (url, context['environment']['QUERY_STRING'])

        return url

    @classmethod
    def query_filter_is_true(cls, filter_value):
        """Determine if bool query param is 'True'.

        We treat this the same way as we do for policy
        enforcement:

        {bool_param}=0 is treated as False

        Any other value is considered to be equivalent to
        True, including the absence of a value

        """

        if (isinstance(filter_value, six.string_types) and
                filter_value == '0'):
            val = False
        else:
            val = True
        return val

    @classmethod
    def _add_self_referential_link(cls, context, ref):
        ref.setdefault('links', {})
        ref['links']['self'] = cls.base_url(context) + '/' + ref['id']

    @classmethod
    def wrap_member(cls, context, ref):
        cls._add_self_referential_link(context, ref)
        return {cls.member_name: ref}

    @classmethod
    def wrap_collection(cls, context, refs, hints=None):
        """Wrap a collection, checking for filtering and pagination.

        Returns the wrapped collection, which includes:
        - Executing any filtering not already carried out
        - Truncate to a set limit if necessary
        - Adds 'self' links in every member
        - Adds 'next', 'self' and 'prev' links for the whole collection.

        :param context: the current context, containing the original url path
                        and query string
        :param refs: the list of members of the collection
        :param hints: list hints, containing any relevant filters and limit.
                      Any filters already satisfied by managers will have been
                      removed
        """
        # Check if there are any filters in hints that were not
        # handled by the drivers. The driver will not have paginated or
        # limited the output if it found there were filters it was unable to
        # handle.

        if hints is not None:
            refs = cls.filter_by_attributes(refs, hints)

        list_limited, refs = cls.limit(refs, hints)

        for ref in refs:
            cls.wrap_member(context, ref)

        container = {cls.collection_name: refs}
        container['links'] = {
            'next': None,
            'self': cls.full_url(context, path=context['path']),
            'previous': None}

        if list_limited:
            container['truncated'] = True

        return container

    @classmethod
    def limit(cls, refs, hints):
        """Limits a list of entities.

        The underlying driver layer may have already truncated the collection
        for us, but in case it was unable to handle truncation we check here.

        :param refs: the list of members of the collection
        :param hints: hints, containing, among other things, the limit
                      requested

        :returns: boolean indicating whether the list was truncated, as well
                  as the list of (truncated if necessary) entities.

        """
        NOT_LIMITED = False
        LIMITED = True

        if hints is None or hints.limit is None:
            # No truncation was requested
            return NOT_LIMITED, refs

        if hints.limit.get('truncated', False):
            # The driver did truncate the list
            return LIMITED, refs

        if len(refs) > hints.limit['limit']:
            # The driver layer wasn't able to truncate it for us, so we must
            # do it here
            return LIMITED, refs[:hints.limit['limit']]

        return NOT_LIMITED, refs

    @classmethod
    def filter_by_attributes(cls, refs, hints):
        """Filters a list of references by filter values."""

        def _attr_match(ref_attr, val_attr):
            """Matches attributes allowing for booleans as strings.

            We test explicitly for a value that defines it as 'False',
            which also means that the existence of the attribute with
            no value implies 'True'

            """
            if type(ref_attr) is bool:
                return ref_attr == utils.attr_as_boolean(val_attr)
            else:
                return ref_attr == val_attr

        def _inexact_attr_match(filter, ref):
            """Applies an inexact filter to a result dict.

            :param filter: the filter in question
            :param ref: the dict to check

            :returns True if there is a match

            """
            comparator = filter['comparator']
            key = filter['name']

            if key in ref:
                filter_value = filter['value']
                target_value = ref[key]
                if not filter['case_sensitive']:
                    # We only support inexact filters on strings so
                    # it's OK to use lower()
                    filter_value = filter_value.lower()
                    target_value = target_value.lower()

                if comparator == 'contains':
                    return (filter_value in target_value)
                elif comparator == 'startswith':
                    return target_value.startswith(filter_value)
                elif comparator == 'endswith':
                    return target_value.endswith(filter_value)
                else:
                    # We silently ignore unsupported filters
                    return True

            return False

        for filter in hints.filters:
            if filter['comparator'] == 'equals':
                attr = filter['name']
                value = filter['value']
                refs = [r for r in refs if _attr_match(
                    utils.flatten_dict(r).get(attr), value)]
            else:
                # It might be an inexact filter
                refs = [r for r in refs if _inexact_attr_match(
                    filter, r)]

        return refs

    @classmethod
    def build_driver_hints(cls, context, supported_filters):
        """Build list hints based on the context query string.

        :param context: contains the query_string from which any list hints can
                        be extracted
        :param supported_filters: list of filters supported, so ignore any
                                  keys in query_dict that are not in this list.

        """
        query_dict = context['query_string']
        hints = driver_hints.Hints()

        if query_dict is None:
            return hints

        for key in query_dict:
            # Check if this is an exact filter
            if supported_filters is None or key in supported_filters:
                hints.add_filter(key, query_dict[key])
                continue

            # Check if it is an inexact filter
            for valid_key in supported_filters:
                # See if this entry in query_dict matches a known key with an
                # inexact suffix added.  If it doesn't match, then that just
                # means that there is no inexact filter for that key in this
                # query.
                if not key.startswith(valid_key + '__'):
                    continue

                base_key, comparator = key.split('__', 1)

                # We map the query-style inexact of, for example:
                #
                # {'email__contains', 'myISP'}
                #
                # into a list directive add filter call parameters of:
                #
                # name = 'email'
                # value = 'myISP'
                # comparator = 'contains'
                # case_sensitive = True

                case_sensitive = True
                if comparator.startswith('i'):
                    case_sensitive = False
                    comparator = comparator[1:]
                hints.add_filter(base_key, query_dict[key],
                                 comparator=comparator,
                                 case_sensitive=case_sensitive)

        # NOTE(henry-nash): If we were to support pagination, we would pull any
        # pagination directives out of the query_dict here, and add them into
        # the hints list.
        return hints

    def _require_matching_id(self, value, ref):
        """Ensures the value matches the reference's ID, if any."""
        if 'id' in ref and ref['id'] != value:
            raise exception.ValidationError('Cannot change ID')

    def _require_matching_domain_id(self, ref_id, ref, get_member):
        """Ensure the current domain ID matches the reference one, if any.

        Provided we want domain IDs to be immutable, check whether any
        domain_id specified in the ref dictionary matches the existing
        domain_id for this entity.

        :param ref_id: the ID of the entity
        :param ref: the dictionary of new values proposed for this entity
        :param get_member: The member function to call to get the current
                           entity
        :raises: :class:`keystone.exception.ValidationError`

        """
        # TODO(henry-nash): It might be safer and more efficient to do this
        # check in the managers affected, so look to migrate this check to
        # there in the future.
        if 'domain_id' in ref:
            existing_ref = get_member(ref_id)
            if ref['domain_id'] != existing_ref['domain_id']:
                raise exception.ValidationError(_('Cannot change Domain ID'))

    def _assign_unique_id(self, ref):
        """Generates and assigns a unique identifier to a reference."""
        ref = ref.copy()
        ref['id'] = uuid.uuid4().hex
        return ref

    def _get_domain_id_for_list_request(self, context):
        """Get the domain_id for a v3 list call.

        If we running with multiple domain drivers, then the caller must
        specify a domain_id either as a filter or as part of the token scope.

        """
        if not CONF.identity.domain_specific_drivers_enabled:
            # We don't need to specify a domain ID in this case
            return

        if context['query_string'].get('domain_id') is not None:
            return context['query_string'].get('domain_id')

        try:
            token_ref = token_model.KeystoneToken(
                token_id=context['token_id'],
                token_data=self.token_provider_api.validate_token(
                    context['token_id']))
        except KeyError:
            raise exception.ValidationError(
                _('domain_id is required as part of entity'))
        except (exception.TokenNotFound,
                exception.UnsupportedTokenVersionException):
            LOG.warning(_LW('Invalid token found while getting domain ID '
                            'for list request'))
            raise exception.Unauthorized()

        if token_ref.domain_scoped:
            return token_ref.domain_id
        else:
            LOG.warning(
                _LW('No domain information specified as part of list request'))
            raise exception.Unauthorized()

    def _get_domain_id_from_token(self, context):
        """Get the domain_id for a v3 create call.

        In the case of a v3 create entity call that does not specify a domain
        ID, the spec says that we should use the domain scoping from the token
        being used.

        """
        # We could make this more efficient by loading the domain_id
        # into the context in the wrapper function above (since
        # this version of normalize_domain will only be called inside
        # a v3 protected call).  However, this optimization is probably not
        # worth the duplication of state
        try:
            token_ref = token_model.KeystoneToken(
                token_id=context['token_id'],
                token_data=self.token_provider_api.validate_token(
                    context['token_id']))
        except KeyError:
            # This might happen if we use the Admin token, for instance
            raise exception.ValidationError(
                _('A scoped token must be used'))
        except (exception.TokenNotFound,
                exception.UnsupportedTokenVersionException):
            LOG.warning(_LW('Invalid token found while getting domain ID '
                            'for list request'))
            raise exception.Unauthorized()

        if token_ref.domain_scoped:
            return token_ref.domain_id
        elif token_ref.project_scoped:
            return token_ref.project_domain_id
        else:
            raise exception.ValidationError('Wrong token scope: not'
                    ' domain-scoped nor project-scoped.')


    def _normalize_domain_id(self, context, ref):
        """Fill in domain_id if not specified in a v3 call."""
        if 'domain_id' not in ref:
            ref['domain_id'] = self._get_domain_id_from_token(context)
        return ref

    @staticmethod
    def filter_domain_id(ref):
        """Override v2 filter to let domain_id out for v3 calls."""
        return ref

    def check_protection(self, context, prep_info, target_attr=None):
        """Provide call protection for complex target attributes.

        As well as including the standard parameters from the original API
        call (which is passed in prep_info), this call will add in any
        additional entities or attributes (passed in target_attr), so that
        they can be referenced by policy rules.

        """
        if 'is_admin' in context and context['is_admin']:
            LOG.warning(_LW('RBAC: Bypassing authorization'))
        else:
            action = ('keystone', prep_info['f_name'])
            # TODO(henry-nash) need to log the target attributes as well
            creds = _build_policy_check_credentials(self, action,
                                                    context,
                                                    prep_info['input_attr'])
            # Build the dict the policy engine will check against from both the
            # parameters passed into the call we are protecting (which was
            # stored in the prep_info by protected()), plus the target
            # attributes provided.
            policy_dict = {}
            if target_attr:
                policy_dict = {'obj': target_attr}
            policy_dict.update(prep_info['input_attr'])
            target = utils.flatten_dict(policy_dict)

            LOG.debug('Evaluating against System Authz Policies')
            self.policy_api.enforce(action, target, creds, 'system')

            LOG.debug('Evaluating against Domain Authz Policies')
            self.policy_api.enforce(action, target, creds, 'domain')
            LOG.debug('RBAC: Authorization granted')

    @classmethod
    def check_immutable_params(cls, ref):
        """Raise exception when disallowed parameter is in ref.

        Check whether the ref dictionary representing a request has only
        mutable parameters included. If not, raise an exception. This method
        checks only root-level keys from a ref dictionary.

        :param ref: a dictionary representing deserialized request to be
                    stored
        :raises: :class:`keystone.exception.ImmutableAttributeError`

        """
        ref_keys = set(ref.keys())
        blocked_keys = ref_keys.difference(cls._mutable_parameters)

        if not blocked_keys:
            # No immutable parameters changed
            return

        exception_args = {'target': cls.__name__,
                          'attributes': ', '.join(blocked_keys)}
        raise exception.ImmutableAttributeError(**exception_args)

    @classmethod
    def filter_params(cls, ref):
        """Remove unspecified parameters from the dictionary.

        This function removes unspecified parameters from the dictionary. See
        check_immutable_parameters for corresponding function that raises
        exceptions. This method checks only root-level keys from a ref
        dictionary.

        :param ref: a dictionary representing deserialized response to be
                    serialized
        """
        ref_keys = set(ref.keys())
        blocked_keys = ref_keys - cls._public_parameters
        for blocked_param in blocked_keys:
            del ref[blocked_param]
        return ref
