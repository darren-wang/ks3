from keystone.common import controller
from keystone.common import dependency

@dependency.requires('role_api', 'identity_api')
class RoleHierarchy(controller.V3Controller):

    collection_name = 'roles'
    member_name = 'role'

    def __init__(self):
        pass

    @controller.protected()
    def add_inheritance(self):
        pass

    @controller.protected()
    def delete_inheritance(self):
        pass