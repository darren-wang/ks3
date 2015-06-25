
from keystone.common import json_home
from keystone.common import wsgi
from keystone.role_hierarchy import controllers

class HierarchyRouters(wsgi.RoutersBase):

    def append_v3_routers(self, mapper):
        controller = controllers.RoleHierarchy()

        self._add_resource(
            mapper, controller,
            path='/roles/{asc_id}/roles/{desc_id}',
            head_action='check_inheritance',
            get_action='check_reachable',
            put_action='add_inheritance',
            delete_action='del_inheritance',
            path_vars={
                'asc_id': json_home.Parameters.ROLE_ID,
                'desc_id': json_home.Parameters.ROLE_ID
            })
        
        self._add_resource(
            mapper, controller,
            path='/domain/{domain_id}/role_hierarchy',
            get_action='get_role_hierarchy',
            path_vars={
                'domain_id':json_home.Parameters.DOMAIN_ID
            })