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

from keystone.common import controller
from keystone.common import dependency
from keystone.common import validation
from keystone import exception
from keystone import notifications
from keystone.policy import schema
from oslo_log import log


LOG = log.getLogger(__name__)


@dependency.requires('policy_api', 'rule_api')
class Policy(controller.Controller):
    collection_name = 'policies'
    member_name = 'policy'

    def __init__(self):
        super(Policy, self).__init__()
        self.get_member_from_driver = self.policy_api.get_policy

    @controller.protected()
    @validation.validated(schema.policy_create, 'policy')
    def create_policy(self, context, policy):
        if self.policy_api.domain_has_policy(policy['domain_id']):
            raise exception.ForbiddenAction("Policy Creation Forbidden: " 
                                            "Policy has been created.")

        rule_set = policy.pop('rule_set') # rule_set is a list
        
        ref = self._assign_unique_id(self._normalize_dict(policy))
        initiator = notifications._get_request_audit_info(context)
        ref = self.policy_api.create_policy(ref['id'], ref, initiator)

        # create each rule in this policy
        policy_id = ref['id']
        for p in rule_set: # for each service
            d = {'policy_id':policy_id, 'service': p['service']}
            for rule in p['rules'].iteritems():
                d['operation'] = rule[0]
                d['condition'] = rule[1]
                rule_ref = self._assign_unique_id(self._normalize_dict(d))
                self.rule_api.create_rule(rule_ref['id'], rule_ref,
                                          initiator)

        return Policy.wrap_member(context, ref)

    @controller.filterprotected('domain_id', 'name', 'enabled')
    def list_policies(self, context, filters):
        hints = Policy.build_driver_hints(context, filters)
        refs = self.policy_api.list_policies(hints=hints)
        return Policy.wrap_collection(context, refs, hints=hints)

    @controller.protected()
    def get_policy(self, context, policy_id): # No query string
        ref = self.policy_api.get_policy(policy_id)
        if not context['query_string']:
            context['query_string'] = {}
        context['query_string'].update({'policy_id':policy_id})
        hints = Rule.build_driver_hints(context, ['policy_id'])
        refs = self.rule_api.list_rules(hints=hints)
        ref.update({'rule_set':{}})
        ref['rule_set'].update(refs)
        return Policy.wrap_member(context, ref)

    @controller.protected()
    @validation.validated(schema.policy_update, 'policy')
    def update_policy(self, context, policy_id, policy):
        self._require_matching_id(policy_id, policy)
        self._require_matching_domain_id(
            policy_id, policy, self.policy_api.get_policy)
        
        rule_set = policy.pop('rule_set')
        
        initiator = notifications._get_request_audit_info(context)
        ref = self.policy_api.update_policy(policy_id, policy, initiator)
        
        for p in rule_set: # for each service
            d = {'policy_id':policy_id, 'service': p['service']}
            for rule in p['rules'].iteritems():
                d['operation'] = rule[0]
                d['condition'] = rule[1]
                self.rule_api.update_rule(d, initiator)
        return Policy.wrap_member(context, ref)

    @controller.protected()
    def delete_policy(self, context, policy_id):
        initiator = notifications._get_request_audit_info(context)
        self.rule_api.delelte_rules(policy_id)
        return self.policy_api.delete_policy(policy_id, initiator)

@dependency.requires('rule_api', 'policy_api')
class Rule(controller.Controller):
    collection_name = 'rules'
    member_name = 'rule'

    def __init__(self):
        super(Rule, self).__init__()
        self.get_member_from_driver = self.rule_api.get_rule

    @controller.protected()
    @validation.validated(schema.rule_create, 'rule')
    def create_rule(self, context, rule):
        if not context['query_string']:
            context['query_string'] = {}
        context['query_string'].update({'domain_id':domain_id,
                                        'service':service,
                                        'operation':operation})
        filters = ['domain_id']
        hints = Policy.build_driver_hints(context, filters)
        refs = self.policy_api.list_policies(hints=hints)
        # assert policy created
        if not refs:
            raise exception.ForbiddenAction("Rule creation forbidden:" 
                        " no policy has been created for this domain.")

        filters.extend(['service', 'operation'])
        hints = Rule.build_driver_hints(context, filters)
        refs = self.rule_api.list_rules(hints=hints)
        # assert same rule not created 
        if refs:
            raise exception.ForbiddenAction("Rule creation forbidden:"
                                " rule on the same service and operation"
                                   " in this domain has been created.")
        # create the rule
        ref = self._assign_unique_id(self._normalize_dict(rule))
        initiator = notifications._get_request_audit_info(context)
        ref = self.rule_api.create_rule(ref['id'], ref, initiator)
        return Rule.wrap_member(context, ref)

    @controller.protected()
    @validation.validated(schema.rule_update, 'rule')
    def update_rule(self, context, rule_id, rule):
        self._require_matching_id(rule_id, rule)
        initiator = notifications._get_request_audit_info(context)
        ref = self.rule_api.update_rule(rule_id, rule, initiator)
        return Rule.wrap_member(context, ref)

    @controller.protected()
    def get_rule(self, context, rule_id):
        # where do we get this rule_id? url?
        ref = self.rule_api.get_rule(rule_id)
        return Rule.wrap_member(context, ref)

    @controller.filterprotected('domain_id', 'policy_id','service',
                                'operation')
    def list_rules(self, context, filters):
        hints = Rule.build_driver_hints(context, filters)
        refs = self.rule_api.list_rules(hints=hints)
        return Rule.wrap_collection(context, refs, hints=hints)

    @controller.protected()
    def delete_rule(self, context, rule_id):
        initiator = notifications._get_request_audit_info(context)
        return self.rule_api.delete_rule(rule_id, initiator)