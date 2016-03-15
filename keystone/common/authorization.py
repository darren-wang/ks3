# Copyright 2012 OpenStack Foundation
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2011 - 2012 Justin Santa Barbara
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_log import log

from keystone import exception
from keystone.i18n import _, _LW
from keystone.models import token_model


AUTH_CONTEXT_ENV = 'KEYSTONE_AUTH_CONTEXT'
"""Environment variable used to convey the Keystone auth context.

Auth context is essentially the user credential used for policy enforcement.
It is a dictionary with the following attributes:

* ``user_id``: user ID of the principal
* ``project_id`` (optional): project ID of the scoped project if auth is
                             project-scoped
* ``domain_id`` (optional): domain ID of the scoped domain if auth is
                            domain-scoped
* ``roles`` (optional): list of role names for the given scope
* ``group_ids``: list of group IDs for which the API user has membership

"""

LOG = log.getLogger(__name__)


def token_to_auth_context(token):
    if not isinstance(token, token_model.KeystoneToken):
        raise exception.UnexpectedError(_('token reference must be a '
                                          'KeystoneToken type, got: %s') %
                                        type(token))
    auth_context = {'token': token}
    try:
        auth_context['sub.user_id'] = token.user_id
    except KeyError:
        LOG.warning(_LW('RBAC: Invalid user data in token'))
        raise exception.Unauthorized()

    if token.project_scoped:
        auth_context['sub.scope'] = 'project'
        auth_context['scope.project_id'] = token.project_id
        auth_context['scope.domain_id'] = token.project_domain_id
    elif token.domain_scoped:
        auth_context['scope'] = 'domain'
        auth_context['scope.domain_id'] = token.domain_id
    else:
        LOG.debug('RBAC: Proceeding without project or domain scope')

    roles = token.role_names
    if roles:
        auth_context['sub.roles'] = roles
        
    auth_context['sub.domain_id'] = token.user_domain_id

    return auth_context
