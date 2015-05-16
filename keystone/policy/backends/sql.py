# Copyright 2012 OpenStack LLC
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

from keystone.common import sql
from keystone import exception
from keystone.policy.backends import rules


class PolicyModel(sql.ModelBase, sql.DictBase):
    __tablename__ = 'policy'
    attributes = ['id', 'blob', 'type', 'name', 'enabled'
                  'description', 'domain_id']
    id = sql.Column(sql.String(64), primary_key=True)
    blob = sql.Column(sql.JsonBlob(), nullable=False)
    type = sql.Column(sql.String(255), nullable=False)
    name = sql.Column(sql.String(64), nullable=False)
    domain_id = sql.Column(sql.String(64), sql.ForeignKey('domain.id'),
                           nullable=False)
    enabled = sql.Column(sql.Boolean, default=False, nullable=False)
    description = sql.Column(sql.Text())
    extra = sql.Column(sql.JsonBlob())


class Policy(rules.Policy):

    @sql.handle_conflicts(conflict_type='policy')
    def create_policy(self, policy_id, policy):
        with sql.transaction() as session:
            policy_ref = PolicyModel.from_dict(policy)
            session.add(policy_ref)
        return policy_ref.to_dict()

    @sql.truncated
    def list_policies(self, hints):
        with sql.transaction() as session:
            query = session.query(PolicyModel)
            policy_refs = sql.filter_limit_query(PolicyModel, query, hints)
            return [policy_ref.to_dict() for policy_ref in policy_refs]

    def list_policies_from_ids(self, policy_ids):
        if not policy_ids:
            return []
        else:
            with sql.transaction() as session:
                query = session.query(PolicyModel)
                query = query.filter(PolicyModel.id.in_(ids))
                return [policy_ref.to_dict() for policy_ref in query.all()]

    def list_policies_ids_from_domain_ids(self, domain_ids):
        # (darren) The existence of all the domains in domain_ids needs to be
        # validated before calling this method 
        if not domain_ids:
            return []
        else:
            with sql.transaction() as session:
                query = session.query(PolicyModel.id)
                query = (
                    query.filter(PolicyModel.domain_id.in_(domain_ids)))
                return [x.id for x in query.all()]

    def list_policies_in_domain(self, domain_id):
        with sql.transaction() as session:
            # (Darren) Managers must make sure the domain_id passed in 
            # does exist. And we shouldn't rely on other backends here. 
            query = session.query(PolicyModel)
            policy_refs = query.filter_by(domain_id=domain_id)
            return [policy_ref.to_dict() for policy_ref in policy_refs]

    def _get_policy(self, session, policy_id):
        """Private method to get a policy model object (NOT a dictionary)."""
        ref = session.query(PolicyModel).get(policy_id)
        if not ref:
            raise exception.PolicyNotFound(policy_id=policy_id)
        return ref

    def get_policy(self, policy_id):
        session = sql.get_session()
        return self._get_policy(session, policy_id).to_dict()

    @sql.handle_conflicts(conflict_type='policy')
    def update_policy(self, policy_id, policy):
        with sql.transaction() as session:
            policy_ref = self._get_policy(session, policy_id)
            old_policy_dict = policy_ref.to_dict()
            for k in policy:
                old_policy_dict[k] = policy[k]
            new_policy = PolicyModel.from_dict(old_policy_dict)
            for attr in PolicyModel.attributes:
                if attr != 'id':
                    setattr(policy_ref, attr, getattr(new_policy, attr))
            policy_ref.extra = new_policy.extra
        return policy_ref.to_dict(include_extra_dict = True)

    def delete_policy(self, policy_id):
        with sql.transaction() as session:
            policy_ref = self._get_policy(session, policy_id)
            session.delete(policy_ref)
