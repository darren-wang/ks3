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

from oslo_config import cfg
from oslo_log import log

from keystone.common import controller
from keystone.common import dependency
from keystone.common import validation
from keystone import exception
from keystone import notifications
from keystone.policy import schema


CONF = cfg.CONF
LOG = log.getLogger(__name__)

_RULE_FILTERS = ['policy_id', 'service', 'permission']

def _build_rule_filter_dict(policy_id, service, permission):
    filter_dict = {}
    filter_dict.update({'policy_id': policy_id,
                        'service': service,
                        'permission': permission})
    return filter_dict


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
        domain_id = policy['domain_id']
        count = len(self.policy_api.list_policies_in_domain(domain_id))
        if count >= CONF.policy.policy_limit:
            raise exception.ForbiddenAction('Policy Creation Forbidden: '
                                'number of created policy exceeds limit.')

        if policy.has_key('enabled') and policy['enabled']:
            policy_ref = self.policy_api.get_enabled_policy_in_domain(
                                                                    domain_id)
            if policy_ref:
                raise exception.ForbiddenAction('Policy Creation Forbidden: '
                                    'number of enabled policy exceeds limit.')
        
        rules = policy.pop('rules') # rules is a dict
        
        ref = self._assign_unique_id(self._normalize_dict(policy))
        initiator = notifications._get_request_audit_info(context)
        ref = self.policy_api.create_policy(ref['id'], ref, initiator)

        # create each rule in this policy
        policy_id = ref['id']
        for serv in rules.iterkeys(): # for each service
            for item in rules[serv].iteritems():
                rule = {'policy_id': policy_id,
                        'service': serv,
                        'permission': item[0],
                        'condition': item[1]}
                rule_ref = self._assign_unique_id(self._normalize_dict(rule))
                self.rule_api.create_rule(rule_ref['id'], rule_ref,
                                          initiator)

        return Policy.wrap_member(context, ref)

    @controller.filterprotected(None, 'domain_id', 'name', 'enabled')
    def list_policies(self, context, filters):
        hints = Policy.build_driver_hints(context, filters)
        refs = self.policy_api.list_policies(hints=hints)
        return Policy.wrap_collection(context, refs, hints=hints)

    @controller.protected()
    def get_policy(self, context, policy_id): 
        policy_ref = self.policy_api.get_policy(policy_id)
        rules_ref = self.rule_api.list_rules_in_policy(policy_id)
        policy_ref['rules']=rules_ref
        return Policy.wrap_member(context, policy_ref)

    @controller.protected()
    @validation.validated(schema.policy_update, 'policy')
    def update_policy(self, context, policy_id, policy):
        self._require_matching_id(policy_id, policy)
        self._require_matching_domain_id(
            policy_id, policy, self.policy_api.get_policy)
        initiator = notifications._get_request_audit_info(context)
 
        if policy.has_key('enabled') and policy['enabled']:
            domain_id = self._get_domain_id_from_token(context)
            policy_ref = self.policy_api.get_enabled_policy_in_domain(
                                                                    domain_id)
            if policy_ref and (policy_ref['id'] != policy_id):
                raise exception.ForbiddenAction('Policy Update Forbidden: '
                                    'number of enabled policy exceeds limit.')

        if policy.has_key('rules'):
            rules = policy.pop('rules')
        else:
            rules = {}

        policy_ref = self.policy_api.update_policy(policy_id, policy,
                                                initiator)
        if rules:
            context['query_string'] = {}
            policy_ref['rules_updated'] = []

            for serv in rules.iterkeys(): 
                for item in rules[serv].iteritems():
                    rule = _build_rule_filter_dict(policy_id, serv, item[0])
                    context['query_string'].update(rule)
                    hints = Rule.build_driver_hints(context, _RULE_FILTERS)
                    rule.update({'condition':item[1]})
                    ref = self.rule_api.list_rules(hints=hints)
                    if ref: # Rule exists already, ref is a list type value
                        rule_ref = self.rule_api.update_rule(ref[0]['id'],
                                                            rule, initiator)
                    else:
                        r = (self._assign_unique_id(
                                            self._normalize_dict(rule)))
                        rule_ref = self.rule_api.create_rule(r['id'], r,
                                                        initiator)
                    policy_ref['rules_updated'].append(rule_ref)
        return Policy.wrap_member(context, policy_ref)

    @controller.protected()
    def delete_policy(self, context, policy_id):
        initiator = notifications._get_request_audit_info(context)
 
        rules_ref = self.rule_api.list_rules_in_policy(policy_id)
        if rules_ref:
            for rule_ref in rules_ref:
                self.rule_api.delete_rule(rule_ref['id'], initiator)
        return self.policy_api.delete_policy(policy_id, initiator)

@dependency.requires('rule_api', 'policy_api')
class Rule(controller.Controller):
    collection_name = 'rules'
    member_name = 'rule'

    def __init__(self):
        super(Rule, self).__init__()
        self.get_member_from_driver = self.rule_api.get_rule

    def _check_rule_protection(self, context, prep_info, rule_id=None):
        """Check protection for rule APIs.

        The policy rule might want to inspect attributes of both the rule
        and policy involved.  So we get these and pass them to the
        check_protection() handler in the controller.

        """
        ref = {}
        if rule_id:
            ref['rule'] = self.rule_api.get_rule(rule_id)
            if ref['rule']:
                policy_id = ref['rule']['policy_id']
                ref['policy'] = self.policy_api.get_policy(policy_id)
        self.check_protection(context, prep_info, ref)

    @controller.protected()
    @validation.validated(schema.rule_create, 'rule')
    def create_rule(self, context, rule):
        policy_id = rule['policy_id']
        # (DWang) For those who are not Cloud Root User, we check if the given
        # policy_id in request belongs to user's scoping domain.
        # (TODO DWang) Move this logic out to an independent function.
        if not context.has_key('is_admin'):
            try:
                policy_ref = self.policy_api.get_policy(policy_id)
                policy_domain_id = policy_ref['domain_id']
                subject_domain_id = self._get_domain_id_from_token(context)
                if policy_domain_id != subject_domain_id:
                    raise exception.ForbiddenAction('Rule Creation Forbidden:'
                                        ' no such policy in scoping domain.')
            except exception.PolicyNotFound:
                raise
 
        #(DWang) Proceed with rule creation
        ref = self._assign_unique_id(self._normalize_dict(rule))
        initiator = notifications._get_request_audit_info(context)
        ref = self.rule_api.create_rule(ref['id'], ref, initiator)
        return Rule.wrap_member(context, ref)

    @controller.protected()
    @validation.validated(schema.rule_update, 'rule')
    def update_rule(self, context, rule_id, rule):
        self._require_matching_id(rule_id, rule)
        initiator = notifications._get_request_audit_info(context)
        # (DWang) Forbid changing the policy that a rule belongs to through
        # this method.
        if rule.has_key('policy_id'):
            rule.pop('policy_id')
        ref = self.rule_api.update_rule(rule_id, rule, initiator)
        return Rule.wrap_member(context, ref)

    @controller.protected(callback=_check_rule_protection)
    def get_rule(self, context, rule_id):
        ref = self.rule_api.get_rule(rule_id)
        return Rule.wrap_member(context, ref)

    @controller.filterprotected(None, 'policy_id', 'service',
                                'permission')
    def list_rules(self, context, filters):
        hints = Rule.build_driver_hints(context, filters)
        refs = self.rule_api.list_rules(hints=hints)
        return Rule.wrap_collection(context, refs, hints=hints)

    @controller.protected()
    def delete_rule(self, context, rule_id):
        initiator = notifications._get_request_audit_info(context)
        return self.rule_api.delete_rule(rule_id, initiator)

