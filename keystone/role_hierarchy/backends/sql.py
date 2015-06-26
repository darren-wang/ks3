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

    def add_inheritance(self, asc_id, desc_id):
        pass
    
    def del_inheritance(self, asc_id, desc_id):
        pass

    def get_inheritance(self, asc_id, desc_id):
        with sql.transaction as session:
            query = session.query(RoleHierarchyTable)
            query = query.filter_by(asc_role_id=asc_id)
            query = query.filter_by(desc_role_id=desc_id)
            try:
                rh_ref = query.one()
            except sql.NotFound:
                raise exception.InheritanceNotFound(asc_role_id=asc_id,
                                                    desc_role_id=desc_id)
            return rh_ref.to_dict()

    def list_inheritances(self, src_id):
        pass