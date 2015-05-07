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

from keystone import assignment
from keystone.common import sql
from keystone import exception
from keystone.resource.backends.sql import Domain


class Role(assignment.RoleDriver):

    @sql.handle_conflicts(conflict_type='role')
    def create_role(self, role_id, role):
        with sql.transaction() as session:
            ref = RoleTable.from_dict(role)
            session.add(ref)
            return ref.to_dict()

    @sql.truncated
    def list_roles(self, hints):
        with sql.transaction() as session:
            query = session.query(RoleTable)
            refs = sql.filter_limit_query(RoleTable, query, hints)
            return [ref.to_dict() for ref in refs]

    def list_roles_from_ids(self, ids):
        if not ids:
            return []
        else:
            with sql.transaction() as session:
                query = session.query(RoleTable)
                query = query.filter(RoleTable.id.in_(ids))
                return [role_ref.to_dict() for role_ref in query.all()]
    
    def list_roles_in_domain(self, domain_id):
        with sql.transaction() as session:
            self._get_domain(session, domain_id)
            query = session.query(RoleTable)
            role_refs = query.filter_by(domain_id=domain_id)
            return [role_ref.to_dict() for role_ref in role_refs]

    def _get_domain(self, session, domain_id):
        ref = session.query(Domain).get(domain_id)
        if ref is None:
            raise exception.DomainNotFound(domain_id=domain_id)
        return ref

    def list_role_ids_from_domain_ids(self, domain_ids):
        if not domain_ids:
            return []
        else:
            with sql.transaction() as session:
                query = session.query(RoleTalbe.id)
                query = (
                    query.filter(RoleTable.domain_id.in_(domain_ids)))

    def get_role(self, role_id):
        with sql.transaction() as session:
            return self._get_role(session, role_id).to_dict()

    def _get_role(self, session, role_id):
        ref = session.query(RoleTable).get(role_id)
        if ref is None:
            raise exception.RoleNotFound(role_id=role_id)
        return ref

    @sql.handle_conflicts(conflict_type='role')
    def update_role(self, role_id, role):
        with sql.transaction() as session:
            ref = self._get_role(session, role_id)
            old_dict = ref.to_dict()
            for k in role:
                old_dict[k] = role[k]
            new_role = RoleTable.from_dict(old_dict)
            for attr in RoleTable.attributes:
                if attr != 'id':
                    setattr(ref, attr, getattr(new_role, attr))
            ref.extra = new_role.extra
            return ref.to_dict()

    def delete_role(self, role_id):
        with sql.transaction() as session:
            ref = self._get_role(session, role_id)
            session.delete(ref)


class RoleTable(sql.ModelBase, sql.DictBase):
    __tablename__ = 'role'
    attributes = ['id', 'name', 'domain_id', 'description']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(255), unique=True, nullable=False)
    description = sql.Column(sql.Text())
    domain_id = sql.Column(sql.String(64), sql.ForeignKey('domain.id'),
                           nullable=False)
    extra = sql.Column(sql.JsonBlob())
    __table_args__ = (sql.UniqueConstraint('domain_id','name'), {})
