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
from keystone import policy

class PolicyModel(sql.ModelBase, sql.DictBase):
    __tablename__ = 'policy'
    attributes = ['description', 'domain_id', 'enabled', 'id', 'name']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(64), nullable=False)
    domain_id = sql.Column(sql.String(64), sql.ForeignKey('domain.id'),
                           nullable=False)
    enabled = sql.Column(sql.Boolean, default=False, nullable=False)
    description = sql.Column(sql.Text(), nullable=True)
    __table_args__ = (sql.UniqueConstraint('domain_id', 'name'), {})


class RuleModel(sql.ModelBase, sql.DictBase):
    __tablename__ = 'rule'
    attributes = ['id', 'policy_id', 'service', 'permission', 'condition']
    id = sql.Column(sql.String(64), primary_key=True)
    policy_id = sql.Column(sql.String(64), sql.ForeignKey('policy.id'),
                            nullable=False)
    service = sql.Column(sql.String(64), nullable=False)
    permission = sql.Column(sql.String(64), nullable=False)
    condition = sql.Column(sql.JsonBlob(), nullable=True)
    __table_args__ = (sql.UniqueConstraint('policy_id', 'service',
                                           'permission'), {})


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


class Rule(policy.RuleDriver):

    @sql.handle_conflicts(conflict_type='rule')
    def create_rule(self, rule_id, rule):
        with sql.transaction() as session:
            rule_ref = RuleModel.from_dict(rule)
            session.add(rule_ref)
            return rule_ref.to_dict()
    
    def _get_rule(self, session, rule_id):
        """Private method to get a rule model object (NOT a dictionary)."""
        ref = session.query(RuleModel).get(rule_id)
        if not ref:
            raise exception.RuleNotFound(rule_id=rule_id)
        return ref
    
    def get_rule(self, rule_id):
        with sql.transaction() as session:
            return self._get_rule(session, rule_id).to_dict()

    @sql.truncated
    def list_rules(self, hints):
        with sql.transaction() as session:
            query = session.query(RuleModel)
            rule_refs = sql.filter_limit_query(RuleModel, query, hints)
            return [rule_ref.to_dict() for rule_ref in rule_refs]

    @sql.handle_conflicts(conflict_type='rule')
    def update_rule(self, rule_id, rule):
        with sql.transaction() as session:
            rule_ref = self._get_rule(session, rule_id)
            old_rule_dict = rule_ref.to_dict()
            for k in rule:
                old_rule_dict[k] = rule[k]
            new_rule = RuleModel.from_dict(old_rule_dict)
            for attr in RuleModel.attributes:
                if attr != 'id':
                    setattr(rule_ref, attr, getattr(new_rule, attr))
            rule_ref.extra = new_rule.extra
            return rule_ref.to_dict(include_extra_dict = True)

    def delete_rule(self, rule_id):
        with sql.transaction() as session:
            rule_ref = self._get_rule(session, rule_id)
            session.delete(rule_ref)
    
    def delelte_rules(self, policy_id):
        with sql.transaction() as session:
            refs = session.query(RuleModel).filter_by(policy_id=policy_id)
            for ref in refs:
                session.delete(ref)