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


MaxPolicyNum = 3
MaxEnabledPolicyNum = 1


@dependency.requires('policy_api')
class PolicyV3(controller.V3Controller):
    collection_name = 'policies'
    member_name = 'policy'

    def __init__(self):
        super(PolicyV3, self).__init__()
        self.get_member_from_driver = self.policy_api.get_policy

    def _assert_domain_policy_num(self, domain_id, num):
        policy_refs = self.policy_api.list_policies_in_domain(
                                                            domain_id)
        policy_amount = len(policy_refs)
        if policy_amount < num:
            return
        else:
            raise exception.ForbiddenAction("Policy amount exceeded.")

    def _assert_domain_enabled_policy_num(self, domain_id, num):
        policy_refs = self.policy_api.list_enabled_policies_in_domain(
                                                            domain_id)
        policy_amount = len(policy_refs)
        if policy_amount < num:
            return
        else:
            raise exception.ForbiddenAction("Enabled "
                                            "Policy amount exceeded.")

    @controller.protected()
    @validation.validated(schema.policy_create, 'policy')
    def create_policy(self, context, policy):
        self._assert_domain_policy_num(policy['domain_id'],
                                       MaxPolicyNum)
        try:
            enabled = policy['enabled']
            if enabled:
                self._assert_domain_enabled_policy_num(
                                                policy['domain_id'],
                                                MaxEnabledPolicyNum)
        except KeyError:
            pass
        ref = self._assign_unique_id(self._normalize_dict(policy))
        initiator = notifications._get_request_audit_info(context)
        ref = self.policy_api.create_policy(ref['id'], ref, initiator)
        return PolicyV3.wrap_member(context, ref)

    @controller.filterprotected('type', 'domain_id', 'name', 'enabled')
    def list_policies(self, context, filters):
        hints = PolicyV3.build_driver_hints(context, filters)
        refs = self.policy_api.list_policies(hints=hints)
        return PolicyV3.wrap_collection(context, refs, hints=hints)

    @controller.protected()
    def get_policy(self, context, policy_id):
        ref = self.policy_api.get_policy(policy_id)
        return PolicyV3.wrap_member(context, ref)

    @controller.protected()
    @validation.validated(schema.policy_update, 'policy')
    def update_policy(self, context, policy_id, policy):
        initiator = notifications._get_request_audit_info(context)
        ref = self.policy_api.update_policy(policy_id, policy, initiator)
        return PolicyV3.wrap_member(context, ref)

    @controller.protected()
    def delete_policy(self, context, policy_id):
        initiator = notifications._get_request_audit_info(context)
        return self.policy_api.delete_policy(policy_id, initiator)
