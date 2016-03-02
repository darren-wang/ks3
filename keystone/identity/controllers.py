# Copyright 2012 OpenStack Foundation
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

"""Workflow Logic the Identity service."""

from oslo_config import cfg
from oslo_log import log

from keystone.common import controller
from keystone.common import dependency
from keystone.common import validation
from keystone import exception
from keystone.i18n import _, _LW
from keystone import notifications
from keystone.identity import schema


CONF = cfg.CONF
LOG = log.getLogger(__name__)


@dependency.requires('identity_api')
class User(controller.Controller):
    collection_name = 'users'
    member_name = 'user'

    def __init__(self):
        super(User, self).__init__()
        self.get_member_from_driver = self.identity_api.get_user

    @controller.protected()
    @validation.validated(schema.user_create, 'user')
    def create_user(self, context, user):
        self._require_attribute(user, 'name')

        # The manager layer will generate the unique ID for users
        ref = self._normalize_dict(user)
        ref = self._normalize_domain_id(context, ref)
        initiator = notifications._get_request_audit_info(context)
        ref = self.identity_api.create_user(ref, initiator)
        return User.wrap_member(context, ref)

    @controller.filterprotected('domain_id', 'enabled', 'name')
    def list_users(self, context, filters):
        hints = User.build_driver_hints(context, filters)
        refs = self.identity_api.list_users(
            domain_scope=self._get_domain_id_for_list_request(context),
            hints=hints)
        return User.wrap_collection(context, refs, hints=hints)

    @controller.protected()
    def get_user(self, context, user_id):
        ref = self.identity_api.get_user(user_id)
        return User.wrap_member(context, ref)

    def _update_user(self, context, user_id, user):
        self._require_matching_id(user_id, user)
        self._require_matching_domain_id(
            user_id, user, self.identity_api.get_user)
        initiator = notifications._get_request_audit_info(context)
        ref = self.identity_api.update_user(user_id, user, initiator)
        return User.wrap_member(context, ref)

    @controller.protected()
    @validation.validated(schema.user_update, 'user')
    def update_user(self, context, user_id, user):
        return self._update_user(context, user_id, user)

    @controller.protected()
    def delete_user(self, context, user_id):
        initiator = notifications._get_request_audit_info(context)
        return self.identity_api.delete_user(user_id, initiator)

    @controller.protected()
    def change_password(self, context, user_id, user):
        original_password = user.get('original_password')
        if original_password is None:
            raise exception.ValidationError(target='user',
                                            attribute='original_password')

        password = user.get('password')
        if password is None:
            raise exception.ValidationError(target='user',
                                            attribute='password')
        try:
            self.identity_api.change_password(
                context, user_id, original_password, password)
        except AssertionError:
            raise exception.Unauthorized()

    def _check_user_and_group_protection(self, context, prep_info,
                                         user_id, group_id):
        ref = {}
        ref['user'] = self.identity_api.get_user(user_id)
        ref['group'] = self.identity_api.get_group(group_id)
        self.check_protection(context, prep_info, ref)

    @controller.filterprotected('domain_id', 'enabled', 'name')
    def list_users_in_group(self, context, filters, group_id):
        hints = User.build_driver_hints(context, filters)
        refs = self.identity_api.list_users_in_group(group_id, hints=hints)
        return User.wrap_collection(context, refs, hints=hints)

    @controller.protected(callback=_check_user_and_group_protection)
    def add_user_to_group(self, context, user_id, group_id):
        self.identity_api.add_user_to_group(user_id, group_id)

    @controller.protected(callback=_check_user_and_group_protection)
    def check_user_in_group(self, context, user_id, group_id):
        return self.identity_api.check_user_in_group(user_id, group_id)

    @controller.protected(callback=_check_user_and_group_protection)
    def remove_user_from_group(self, context, user_id, group_id):
        self.identity_api.remove_user_from_group(user_id, group_id)

@dependency.requires('identity_api')
class Group(controller.Controller):
    collection_name = 'groups'
    member_name = 'group'

    def __init__(self):
        super(Group, self).__init__()
        self.get_member_from_driver = self.identity_api.get_group

    @controller.protected()
    def create_group(self, context, group):
        self._require_attribute(group, 'name')

        # The manager layer will generate the unique ID for groups
        ref = self._normalize_dict(group)
        ref = self._normalize_domain_id(context, ref)
        initiator = notifications._get_request_audit_info(context)
        ref = self.identity_api.create_group(ref, initiator)
        return Group.wrap_member(context, ref)

    @controller.filterprotected('domain_id', 'name')
    def list_groups(self, context, filters):
        hints = Group.build_driver_hints(context, filters)
        refs = self.identity_api.list_groups(
            domain_scope=self._get_domain_id_for_list_request(context),
            hints=hints)
        return Group.wrap_collection(context, refs, hints=hints)

    @controller.filterprotected('name')
    def list_groups_for_user(self, context, filters, user_id):
        hints = Group.build_driver_hints(context, filters)
        refs = self.identity_api.list_groups_for_user(user_id, hints=hints)
        return Group.wrap_collection(context, refs, hints=hints)

    @controller.protected()
    def get_group(self, context, group_id):
        ref = self.identity_api.get_group(group_id)
        return Group.wrap_member(context, ref)

    @controller.protected()
    def update_group(self, context, group_id, group):
        self._require_matching_id(group_id, group)
        self._require_matching_domain_id(
            group_id, group, self.identity_api.get_group)
        initiator = notifications._get_request_audit_info(context)
        ref = self.identity_api.update_group(group_id, group, initiator)
        return Group.wrap_member(context, ref)

    @controller.protected()
    def delete_group(self, context, group_id):
        initiator = notifications._get_request_audit_info(context)
        self.identity_api.delete_group(group_id, initiator)
