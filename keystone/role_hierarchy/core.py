import abc

from keystone.common import dependency
from keystone.common import manager
from keystone import exception

import six


@dependency.provider('rh_api')
@dependency.requires('role_api')
class Manager(manager.Manager):

    def add_inheritance(self, asc_role_id, desc_role_id):
        return self.driver.add_inheritance(asc_role_id, desc_role_id)

    def del_inheritance(self, asc_role_id, desc_role_id):
        pass

    def check_inheritance(self, asc, desc):
        try:
            edge = self.driver.get_inheritance(asc, desc)
            if edge:
                return True
        except exception.InheritanceNotFound:
            return False

    def list_reachable_roles(self, src_role_id):
        pass

    def _reachable_role_ids(self, src_role_id):
        reachable_ids = []
        reachable = self._list_reachable_roles(src_role_id)
        for role in reachable:
            reachable_ids.append(role['id'])
        return reachable_ids

    def check_reachable(self, src_role_id, dest_role_id):
        reachable_ids = self._reachable_role_ids(src_role_id)
        if dest_role_id in reachable_ids:
            return True
        return False

@six.add_metaclass(abc.ABCMeta)
class Driver(object):

    def add_inheritance(self, asc, desc):
        raise exception.NotImplemented()

    def del_inheritance(self, asc, desc):
        raise exception.NotImplemented()

    def get_inheritance(self, asc, desc):
        raise exception.NotImplemented()

    