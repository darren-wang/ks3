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

    def list_immediate_ids(self, src_role_id):
        idesc = self.driver.list_immediate_desc(src_role_id)
        iid = [role['id'] for role in idesc]
        return iid

    def list_reachable_roles(self, src_role_id):
        # ir, immediate reachable
        # rr, reachable roles
        rr = set()
        ir = set(self.list_immediate_ids(src_role_id))
        while ir:
            for role_id in ir:
                delta_ir = set(self.list_immediate_ids(role_id))
                new_ir = ir.union(delta_ir)
                new_ir.difference_update(rr)
                new_ir.remove(role_id)
                rr.add(role_id)
                ir = new_ir
        return rr

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

    