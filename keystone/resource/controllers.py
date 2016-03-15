# Copyright 2013 Metacloud, Inc.
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

"""Workflow Logic the Resource service."""

import uuid
import base64

from oslo_config import cfg
from oslo_log import log

from keystone.common import controller
from keystone.common import dependency
from keystone.common import validation
from keystone.common import wsgi
from keystone import exception
from keystone.i18n import _
from keystone import notifications
from keystone.resource import schema


CONF = cfg.CONF
LOG = log.getLogger(__name__)


@dependency.requires('resource_api', 'identity_api', 'role_api',
                     'assignment_api')
class Domain(controller.Controller):
    collection_name = 'domains'
    member_name = 'domain'

    def __init__(self):
        super(Domain, self).__init__()
        self.get_member_from_driver = self.resource_api.get_domain

    def _create_init_user(self, user_name, domain_id, initiator):
        init_pass = base64.urlsafe_b64encode(uuid.uuid4().hex[:18])
        domain_name = self.resource_api.get_domain(domain_id)['name']
        init_user = {
         'domain_id': domain_id,
         'password': init_pass,
         'description': 'Initial user of domain: %s.' %domain_name,
         'enabled':True
        }
        if user_name:
            init_user.update({'name': user_name})
        else:
            init_user.update({'name': 'domain_root'})
        ref = self.identity_api.create_user(init_user, initiator)
        ref.update({'password':init_pass})
        return {'user':ref}
    
    def _create_init_role(self, domain_id, initiator):
        init_role_id = uuid.uuid4().hex
        domain_name = self.resource_api.get_domain(domain_id)['name']
        init_role = {
         'name':'domain_admin',
         'id': init_role_id,
         'domain_id':domain_id,
         'description': 'Initial role of domain: %s' %domain_name
         }
        ref = self.role_api.create_role(init_role_id, init_role,
                                        initiator)
        return {'role':ref}
        
    @controller.protected()
    @validation.validated(schema.domain_create, 'domain')
    def create_domain(self, context, domain):
        ref = self._assign_unique_id(self._normalize_dict(domain))
        initiator = notifications._get_request_audit_info(context)
        if ref.has_key('domain_root_user'):
            init_user = ref.pop('domain_root_user')
        else:
            init_user = ''
        ref = self.resource_api.create_domain(ref['id'], ref, initiator)
        domain_ref = Domain.wrap_member(context, ref)
        user_ref = self._create_init_user(init_user, ref['id'], initiator)
        role_ref = self._create_init_role(ref['id'], initiator)
        self.assignment_api.create_grant(role_ref['role']['id'],
                                    user_id=user_ref['user']['id'],
                                    domain_id=domain_ref['domain']['id'])
        domain_ref.update(user_ref)
        domain_ref.update(role_ref)
        return domain_ref

    @controller.filterprotected('enabled', 'name')
    def list_domains(self, context, filters):
        hints = Domain.build_driver_hints(context, filters)
        refs = self.resource_api.list_domains(hints=hints)
        return Domain.wrap_collection(context, refs, hints=hints)

    @controller.protected()
    def get_domain(self, context, domain_id):
        ref = self.resource_api.get_domain(domain_id)
        return Domain.wrap_member(context, ref)

    @controller.protected()
    @validation.validated(schema.domain_update, 'domain')
    def update_domain(self, context, domain_id, domain):
        self._require_matching_id(domain_id, domain)
        initiator = notifications._get_request_audit_info(context)
        ref = self.resource_api.update_domain(domain_id, domain, initiator)
        return Domain.wrap_member(context, ref)

    @controller.protected()
    def delete_domain(self, context, domain_id):
        initiator = notifications._get_request_audit_info(context)
        return self.resource_api.delete_domain(domain_id, initiator)


@dependency.requires('resource_api')
class Project(controller.Controller):
    collection_name = 'projects'
    member_name = 'project'

    def __init__(self):
        super(Project, self).__init__()
        self.get_member_from_driver = self.resource_api.get_project

    @controller.protected()
    @validation.validated(schema.project_create, 'project')
    def create_project(self, context, project):
        ref = self._assign_unique_id(self._normalize_dict(project))
        ref = self._normalize_domain_id(context, ref)
        initiator = notifications._get_request_audit_info(context)
        ref = self.resource_api.create_project(ref['id'], ref,
                                               initiator=initiator)
        return Project.wrap_member(context, ref)

    @controller.filterprotected('domain_id', 'enabled', 'name',
                                'parent_id')
    def list_projects(self, context, filters):
        hints = Project.build_driver_hints(context, filters)
        refs = self.resource_api.list_projects(hints=hints)
        return Project.wrap_collection(context, refs, hints=hints)

    def _expand_project_ref(self, context, ref):
        params = context['query_string']

        parents_as_list = 'parents_as_list' in params and (
            self.query_filter_is_true(params['parents_as_list']))
        parents_as_ids = 'parents_as_ids' in params and (
            self.query_filter_is_true(params['parents_as_ids']))

        subtree_as_list = 'subtree_as_list' in params and (
            self.query_filter_is_true(params['subtree_as_list']))
        subtree_as_ids = 'subtree_as_ids' in params and (
            self.query_filter_is_true(params['subtree_as_ids']))

        # parents_as_list and parents_as_ids are mutually exclusive
        if parents_as_list and parents_as_ids:
            msg = _('Cannot use parents_as_list and parents_as_ids query '
                    'params at the same time.')
            raise exception.ValidationError(msg)

        # subtree_as_list and subtree_as_ids are mutually exclusive
        if subtree_as_list and subtree_as_ids:
            msg = _('Cannot use subtree_as_list and subtree_as_ids query '
                    'params at the same time.')
            raise exception.ValidationError(msg)

        user_id = self.get_auth_context(context).get('user_id')

        if parents_as_list:
            parents = self.resource_api.list_project_parents(
                ref['id'], user_id)
            ref['parents'] = [Project.wrap_member(context, p)
                              for p in parents]
        elif parents_as_ids:
            ref['parents'] = self.resource_api.get_project_parents_as_ids(ref)

        if subtree_as_list:
            subtree = self.resource_api.list_projects_in_subtree(
                ref['id'], user_id)
            ref['subtree'] = [Project.wrap_member(context, p)
                              for p in subtree]
        elif subtree_as_ids:
            ref['subtree'] = self.resource_api.get_projects_in_subtree_as_ids(
                ref['id'])

    @controller.protected()
    def get_project(self, context, project_id):
        ref = self.resource_api.get_project(project_id)
        self._expand_project_ref(context, ref)
        return Project.wrap_member(context, ref)

    @controller.protected()
    @validation.validated(schema.project_update, 'project')
    def update_project(self, context, project_id, project):
        self._require_matching_id(project_id, project)
        self._require_matching_domain_id(
            project_id, project, self.resource_api.get_project)
        initiator = notifications._get_request_audit_info(context)
        ref = self.resource_api.update_project(project_id, project,
                                               initiator=initiator)
        return Project.wrap_member(context, ref)

    @controller.protected()
    def delete_project(self, context, project_id):
        initiator = notifications._get_request_audit_info(context)
        return self.resource_api.delete_project(project_id,
                                                initiator=initiator)
