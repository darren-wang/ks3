from keystone import role_hierarchy
from keystone.common import sql
from keystone import exception


class RoleHierarchyTable(sql.ModelBase, sql.DictBase):
    __tablename__ = 'role_hierarchy'
    attributes = ['asc_role_id', 'desc_role_id']
    asc_role_id = sql.Column(sql.String(64), nullable=False)
    desc_role_id = sql.Column(sql.String(64), nullable=False)
    __table_args__ = (sql.UniqueConstraint('asc_role_id','desc_role_id'), {})


class RoleHierarchy(role_hierarchy.Driver):

    def add_inheritance(self, asc_id, desc_id, inheritance):
        with sql.transaction() as session:
            ref = RoleHierarchyTable.from_dict(inheritance)
            session.add(ref)
            return ref.to_dict()
    
    def del_inheritance(self, asc_id, desc_id):
        with sql.transaction() as session:
            ref = self._get_inheritance(session, asc_id, desc_id)
            session.delete(ref)

    def get_inheritance(self, asc_id, desc_id):
        with sql.transaction as session:
            return _get_inheritance(session, asc_id, desc_id).to_dict()

    def _get_inheritance(self, session, asc_id, desc_id):
        query = session.query(RoleHierarchyTable)
        query = query.filter_by(asc_role_id=asc_id)
        query = query.filter_by(desc_role_id=desc_id)
        try:
            ref = query.one()
        except sql.NotFound:
            raise exception.InheritanceNotFound(asc_role_id=asc_id,
                                                desc_role_id=desc_id)
        return ref

    def list_inheritances(self, src_id):
        with sql.transaction as session:
            query = session.query(RoleHierarchyTable)
            refs = query.filter_by(asc_role_id=src_id)
            return [ref.to_dict()['desc_role_id'] for ref in refs]
