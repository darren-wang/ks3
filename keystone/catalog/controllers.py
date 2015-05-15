# Copyright 2012 OpenStack Foundation
# Copyright 2012 Canonical Ltd.
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

import six

from keystone.catalog import schema
from keystone.common import controller
from keystone.common import dependency
from keystone.common import validation
from keystone.common import wsgi
from keystone import exception
from keystone.i18n import _
from keystone import notifications


INTERFACES = ['public', 'internal', 'admin']


@dependency.requires('catalog_api')
class RegionV3(controller.V3Controller):
    collection_name = 'regions'
    member_name = 'region'

    def create_region_with_id(self, context, region_id, region):
        """Create a region with a user-specified ID.

        This method is unprotected because it depends on ``self.create_region``
        to enforce policy.
        """
        if 'id' in region and region_id != region['id']:
            raise exception.ValidationError(
                _('Conflicting region IDs specified: '
                  '"%(url_id)s" != "%(ref_id)s"') % {
                      'url_id': region_id,
                      'ref_id': region['id']})
        region['id'] = region_id
        return self.create_region(context, region)

    @controller.protected()
    @validation.validated(schema.region_create, 'region')
    def create_region(self, context, region):
        ref = self._normalize_dict(region)

        if not ref.get('id'):
            ref = self._assign_unique_id(ref)

        initiator = notifications._get_request_audit_info(context)
        ref = self.catalog_api.create_region(ref, initiator)
        return wsgi.render_response(
            RegionV3.wrap_member(context, ref),
            status=(201, 'Created'))

    @controller.filterprotected('parent_region_id')
    def list_regions(self, context, filters):
        hints = RegionV3.build_driver_hints(context, filters)
        refs = self.catalog_api.list_regions(hints)
        return RegionV3.wrap_collection(context, refs, hints=hints)

    @controller.protected()
    def get_region(self, context, region_id):
        ref = self.catalog_api.get_region(region_id)
        return RegionV3.wrap_member(context, ref)

    @controller.protected()
    @validation.validated(schema.region_update, 'region')
    def update_region(self, context, region_id, region):
        self._require_matching_id(region_id, region)
        initiator = notifications._get_request_audit_info(context)
        ref = self.catalog_api.update_region(region_id, region, initiator)
        return RegionV3.wrap_member(context, ref)

    @controller.protected()
    def delete_region(self, context, region_id):
        initiator = notifications._get_request_audit_info(context)
        return self.catalog_api.delete_region(region_id, initiator)


@dependency.requires('catalog_api')
class ServiceV3(controller.V3Controller):
    collection_name = 'services'
    member_name = 'service'

    def __init__(self):
        super(ServiceV3, self).__init__()
        self.get_member_from_driver = self.catalog_api.get_service

    @controller.protected()
    @validation.validated(schema.service_create, 'service')
    def create_service(self, context, service):
        ref = self._assign_unique_id(self._normalize_dict(service))
        initiator = notifications._get_request_audit_info(context)
        ref = self.catalog_api.create_service(ref['id'], ref, initiator)
        return ServiceV3.wrap_member(context, ref)

    @controller.filterprotected('type', 'name')
    def list_services(self, context, filters):
        hints = ServiceV3.build_driver_hints(context, filters)
        refs = self.catalog_api.list_services(hints=hints)
        return ServiceV3.wrap_collection(context, refs, hints=hints)

    @controller.protected()
    def get_service(self, context, service_id):
        ref = self.catalog_api.get_service(service_id)
        return ServiceV3.wrap_member(context, ref)

    @controller.protected()
    @validation.validated(schema.service_update, 'service')
    def update_service(self, context, service_id, service):
        self._require_matching_id(service_id, service)
        initiator = notifications._get_request_audit_info(context)
        ref = self.catalog_api.update_service(service_id, service, initiator)
        return ServiceV3.wrap_member(context, ref)

    @controller.protected()
    def delete_service(self, context, service_id):
        initiator = notifications._get_request_audit_info(context)
        return self.catalog_api.delete_service(service_id, initiator)


@dependency.requires('catalog_api')
class EndpointV3(controller.V3Controller):
    collection_name = 'endpoints'
    member_name = 'endpoint'

    def __init__(self):
        super(EndpointV3, self).__init__()
        self.get_member_from_driver = self.catalog_api.get_endpoint

    @classmethod
    def wrap_member(cls, context, ref):
        return super(EndpointV3, cls).wrap_member(context, ref)

    @controller.protected()
    @validation.validated(schema.endpoint_create, 'endpoint')
    def create_endpoint(self, context, endpoint):
        ref = self._assign_unique_id(self._normalize_dict(endpoint))
        initiator = notifications._get_request_audit_info(context)
        ref = self.catalog_api.create_endpoint(ref['id'], ref, initiator)
        return EndpointV3.wrap_member(context, ref)

    @controller.filterprotected('interface', 'service_id', 'region_id')
    def list_endpoints(self, context, filters):
        hints = EndpointV3.build_driver_hints(context, filters)
        refs = self.catalog_api.list_endpoints(hints=hints)
        return EndpointV3.wrap_collection(context, refs, hints=hints)

    @controller.protected()
    def get_endpoint(self, context, endpoint_id):
        ref = self.catalog_api.get_endpoint(endpoint_id)
        return EndpointV3.wrap_member(context, ref)

    @controller.protected()
    @validation.validated(schema.endpoint_update, 'endpoint')
    def update_endpoint(self, context, endpoint_id, endpoint):
        self._require_matching_id(endpoint_id, endpoint)
        initiator = notifications._get_request_audit_info(context)
        ref = self.catalog_api.update_endpoint(endpoint_id, endpoint,
                                               initiator)
        return EndpointV3.wrap_member(context, ref)

    @controller.protected()
    def delete_endpoint(self, context, endpoint_id):
        initiator = notifications._get_request_audit_info(context)
        return self.catalog_api.delete_endpoint(endpoint_id, initiator)
