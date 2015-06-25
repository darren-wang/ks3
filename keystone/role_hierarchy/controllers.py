from keystone.common import controller
from keystone.common import dependency
from keystone import exception
from openstackclient.tests.identity.v2_0.fakes import role_id

@dependency.requires('role_api', 'identity_api', 'rh_api')
class RoleHierarchy(controller.V3Controller):

    collection_name = 'roles'
    member_name = 'role'

    def __init__(self):
        super(RoleHierarchy, self).__init__()
        self.get_member_from_driver = self.role_api.get_role

    def _check_rh_protection(self, context, protection, asc_id, desc_id):
        """Check protection for role hierarchy APIs.

        The policy rule might want to inspect attributes of any of the entities
        involved in the role hierarchy.  So we get these and pass them to the
        check_protection() handler in the controller.

        """
        ref = {}
        try:
            ref['asc_role'] = self.role_api.get_role(asc_id)
            ref['desc_role'] = self.role_api.get_role(desc_id)
        except exception.RoleNotFound:
            # Simply re-raise it.
            raise

        self.check_protection(context, protection, ref)

    @controller.protected(callback=_check_rh_protection)
    def add_inheritance(self, context, asc_id, desc_id):
        exist = self.rh_api.check_inheritance(asc_id, desc_id)
        if not exist:
            cycle = self.rh_api.check_reachable(desc_id, asc_id)
            if not cycle:
                self.rh_api.add_inheritance(asc_id, desc_id)
            else:
                # (TODO wangzhiyu) What exception should we raise?
                raise 
        else:
            raise exception.Conflict

    @controller.protected(callback=_check_rh_protection)
    def del_inheritance(self, context, asc_id, desc_id):
        exist = self.rh_api.check_inheritance(asc, desc)
        if exist:
            self.rh_api.del_inheritance(asc_id, desc_id)

    @controller.protected(callback=_check_rh_protection)
    def check_inheritance(self, asc, desc):
        return self.rh_api.check_inheritance(asc, desc)

    @controller.protected(callback=_check_rh_protection)
    def check_reachable(self, src, dest):
        return self.rh_api.check_reachable(src, dest)

    @controller.protected(callback=_check_rh_protection)
    def list_lower_roles(self, src_role_id):
        lower_roles = {}
        name = self.role_api.get_role(src_role_id)['name']
        reachable = self.rh_api.list_reachable_roles(src_role_id)
        for role in reachable:
            role_name =role['name']
            lower_roles[role_name] = role_id
        result = {'role_name':name, 'role_id':src_role_id,
                  'lower_roles':lower_roles}
        return result

    def get_role_hierarchy(self, domain_id):
        pass
            
