import abc

from keystone.common import dependency
from keystone.common import manager
from keystone import exception

import six


@dependency.provider('rh_api')
@dependency.requires('role_api')
class Manager(manager.Manager):

    def add_inheritance(self, asc_id, desc_id):
        d = {'asc_role_id':asc_id, 'desc_role_id':desc_id}
        return self.driver.add_inheritance(asc_id, desc_id, d)

    def del_inheritance(self, asc_id, desc_id):
        return self.driver.del_inheritance(asc_id, desc_id)

    def check_inheritance(self, asc_id, desc_id):
        try:
            edge = self.driver.get_inheritance(asc_id, desc_id)
            if edge:
                return True
        except exception.InheritanceNotFound:
            return False

    def list_reachable_ids(self, src_id):
        # ir, immediate reachable
        # rr, reachable roles
        rr = set()
        ir = set(self.driver.list_inheritances(src_id))
        while ir:
            for role_id in ir:
                delta_ir = set(self.driver.list_inheritances(role_id))
                new_ir = ir.union(delta_ir)
                new_ir.difference_update(rr)
                new_ir.remove(role_id)
                rr.add(role_id)
                ir = new_ir
        return rr

    def check_reachable(self, src, dest):
        reachable_ids = self.list_reachable_ids(src)
        if dest_role_id in reachable_ids:
            return True
        return False

@six.add_metaclass(abc.ABCMeta)
class Driver(object):

    @abc.abstractmethod
    def add_inheritance(self, asc, desc):
        raise exception.NotImplemented()

    @abc.abstractmethod
    def del_inheritance(self, asc, desc):
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_inheritance(self, asc, desc):
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_inheritances(self, src):
        raise exception.NotImplemented()
