# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from keystone.common import validation
from keystone.common.validation import parameter_types


_policy_create_properties = {
    'domain_id': parameter_types.id_string,
    'name': parameter_types.name,
    'description': validation.nullable(parameter_types.description),
    'enabled': parameter_types.boolean,
    'rules': {
        'type': 'object'
    }
}

_policy_update_properties = {
    'name': parameter_types.name,
    'description': validation.nullable(parameter_types.description),
    'enabled': parameter_types.boolean,
    'rules': {
        'type': 'object'
    }
}

policy_create = {
    'type': 'object',
    'properties': _policy_create_properties,
    'required': ['domain_id', 'name', 'rules'],
    'additionalProperties': True
}

policy_update = {  
    'type': 'object',
    'properties': _policy_update_properties,
    'minProperties': 1,
    'additionalProperties': True
}

_rule_create_properties = {
    'domain_id': parameter_types.id_string,
    'policy_id': parameter_types.id_string,
    'service': {
        'type': 'string'
    },
    'permission': {
        'type': 'string'
    },
    'condition': {
        'type': 'string'
    },
}

_rule_update_properties = {
    'service': {
        'type': 'string'
    },
    'permission': {
        'type': 'string'
    },
    'condition': {
        'type': 'string'
    },
}

rule_create = {
    'type': 'object',
    'properties': _rule_create_properties,
    'required': ['domain_id', 'policy_id', 'service',
                 'permission', 'condition'],
    'additionalProperties': False
}

rule_update = {  
    'type': 'object',
    'properties': _rule_update_properties,
    'minProperties': 1,
    'additionalProperties': False
}
