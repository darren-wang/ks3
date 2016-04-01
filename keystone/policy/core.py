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
"""Main entry point into the Policy service."""

import abc

from oslo_config import cfg
from oslo_log import log
import six

from keystone.common import dependency
from keystone.common import driver_hints
from keystone.common import manager
from keystone import exception
from keystone import notifications


LOG = log.getLogger(__name__)
CONF = cfg.CONF


@dependency.provider('policy_api')
@dependency.requires('resource_api', 'rule_api')
class PolicyManager(manager.Manager):
    """Default pivot point for the Policy backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """
    _POLICY = 'policy'

    def __init__(self):
        super(PolicyManager, self).__init__(CONF.policy.driver)

        self.event_callbacks = {
            notifications.ACTIONS.deleted: {
                'domain': [self._domain_deleted],
            },
        }

    def _domain_deleted(self, service, resource_type, operation,
                        payload):
        domain_id = payload['resource_info']

        policy_refs = self.list_policies_in_domain(domain_id)

        for policy in policy_refs:
            try:
                self.delete_policy(policy['id'])
            except exception.PolicyNotFound:
                LOG.debug(('Policy %(p_id)s not found when deleting domain '
                           'contents for %(domain_id)s, continuing with '
                           'cleanup.'),
                          {'p_id': policy['id'], 'domain_id': domain_id})

    def create_policy(self, policy_id, policy, initiator=None):
        ref = self.driver.create_policy(policy_id, policy)
        notifications.Audit.created(self._POLICY, policy_id, initiator)
        return ref

    def get_policy(self, policy_id):
        try:
            return self.driver.get_policy(policy_id)
        except exception.NotFound:
            raise exception.PolicyNotFound(policy_id=policy_id)

    def update_policy(self, policy_id, policy, initiator=None):
        try:
            ref = self.driver.update_policy(policy_id, policy)
        except exception.NotFound:
            raise exception.PolicyNotFound(policy_id=policy_id)
        notifications.Audit.updated(self._POLICY, policy_id, initiator)
        return ref

    @manager.response_truncated
    def list_policies(self, hints=None):
        return self.driver.list_policies(hints or driver_hints.Hints())

    def delete_policy(self, policy_id, initiator=None):
        try:
            ret = self.driver.delete_policy(policy_id)
        except exception.NotFound:
            raise exception.PolicyNotFound(policy_id=policy_id)
        notifications.Audit.deleted(self._POLICY, policy_id, initiator)
        return ret
    
    def get_enabled_policy_in_domain(self, domain_id):
        policies_ref = self.list_policies_in_domain(domain_id)
        if policies_ref:
            for policy_ref in policies_ref:
                if policy_ref['enabled']:
                    return policy_ref

    def list_policies_in_domain(self, domain_id):
        return self.driver.list_policies_in_domain(domain_id)
         
    def check_policy_in_domain(self, policy_id, domain_id):
        policies_ref = self.list_policies_in_domain(domain_id)
        if policies_ref:
            policies_id = [ p['id'] for p in policies_ref ]
            return policy_id in policies_id
        return False


@dependency.provider('rule_api')
@dependency.requires('resource_api', 'policy_api')
class RuleManager(manager.Manager):
    _RULE = 'rule'
    
    def __init__(self):
        super(RuleManager, self).__init__(CONF.rule.driver)

        self.event_callbacks = {
            notifications.ACTIONS.deleted: {
                'policy': [self._policy_deleted],
            },
        }

    def _policy_deleted(self, service, resource_type, operation,
                        payload):
        policy_id = payload['resource_info']

        rule_refs = self.list_rules_in_policy(policy_id)

        for rule in rule_refs:
            try:
                self.delete_rule(rule['id'])
            except exception.RuleNotFound:
                LOG.debug(('Rule %(rule_id)s not found when deleting policy '
                           'contents for %(policy_id)s, continuing with '
                           'cleanup.'),
                          {'rule_id': rule['id'], 'policy_id': policy_id})

    def create_rule(self, rule_id, rule, initiator=None):
        ref = self.driver.create_rule(rule_id, rule)
        notifications.Audit.created(self._RULE, rule_id, initiator)
        return ref
    
    def update_rule(self, rule_id, rule, initiator=None):
        try:
            ref = self.driver.update_rule(rule_id, rule)
        except exception.NotFound:
            raise exception.RuleNotFound(rule_id=rule_id)
        notifications.Audit.updated(self._RULE, rule_id, initiator)
        return ref
    
    def get_rule(self, rule_id):
        try:
            return self.driver.get_rule(rule_id)
        except exception.NotFound:
            raise exception.RuleNotFound(rule_id=rule_id)

    def list_rules(self, hints=None):
        rules = self.driver.list_rules(hints or driver_hints.Hints())
        return rules

    def list_rules_in_policy(self, policy_id):
        return self.driver.list_rules_in_policy(policy_id)

    def delete_rule(self, rule_id, initiator=None):
        try:
            ret = self.driver.delete_rule(rule_id)
        except exception.NotFound:
            raise exception.RuleNotFound(rule_id=rule_id)
        notifications.Audit.deleted(self._RULE, rule_id, initiator)
        return ret
    
    def delelte_rules(self, policy_id):
        ret = self.driver.delete_rules(policy_id)
        return ret

@six.add_metaclass(abc.ABCMeta)
class PolicyDriver(object):

    def _get_list_limit(self):
        return CONF.policy.list_limit or CONF.list_limit

    @abc.abstractmethod
    def enforce(self, context, credentials, action, target):
        """Verify that a user is authorized to perform action.

        For more information on a full implementation of this see:
        `keystone.policy.backends.rules.Policy.enforce`
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def create_policy(self, policy_id, policy):
        """Store a policy blob.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_policies(self):
        """List all policies."""
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_policy(self, policy_id):
        """Retrieve a specific policy blob.

        :raises: keystone.exception.PolicyNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_policy(self, policy_id, policy):
        """Update a policy blob.

        :raises: keystone.exception.PolicyNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_policy(self, policy_id):
        """Remove a policy blob.

        :raises: keystone.exception.PolicyNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover


@six.add_metaclass(abc.ABCMeta)
class RuleDriver(object):

    @abc.abstractmethod
    def create_rule(self, rule_id, rule):
        """Store a rule.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_rule(self, rule_id):
        """Retrieve a specific rule's condition.

        :raises: keystone.exception.RuleNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_rules(self):
        """Retrieve a specific rule's condition.

        :raises: keystone.exception.RuleNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def update_rule(self, rule_id, rule):
        """Update a rule.

        :raises: keystone.exception.RuleNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_rule(self, rule_id):
        """Remove a rule.

        :raises: keystone.exception.RuleNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover
