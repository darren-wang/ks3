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


_policy_properties = {
    'domain_id': parameter_types.id_string,
    'name': parameter_types.name,
    'description': validation.nullable(parameter_types.description),
    'enabled': parameter_types.boolean,
    'policy': {
        'type': 'string'
    }
}

policy_create = {
    'type': 'object',
    'properties': _policy_properties,
    'required': ['domain_id', 'policy'],
    'additionalProperties': True
}

policy_update = {  
    'type': 'object',
    'properties': _policy_properties,
    'minProperties': 1,
    'additionalProperties': True
}

_rule_properties = {
    'domain_id': parameter_types.id_string,
    'service': {
        'type': 'string'
    },
    'action': {
        'type': 'string'
    },
    'content': {
        'type': 'string'
    },
}

rule_create = {
    'type': 'object',
    'properties': _rule_properties,
    'required': ['domain_id', 'service', 'action', 'content'],
    'additionalProperties': False
}

rule_update = {  
    'type': 'object',
    'properties': _rule_properties,
    'minProperties': 1,
    'additionalProperties': False
}