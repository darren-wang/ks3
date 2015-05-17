from keystone.common import validation
from keystone.common.validation import parameter_types

_user_properties = {
    'description': validation.nullable(parameter_types.description),
    'domain_id': parameter_types.id_string,
    'enabled': parameter_types.boolean,
    'name': {
        'type': 'string',
        'minLength': 1,
        'maxLength': 64
    },
    'email': validation.nullable(parameter_types.email)
}

user_create = {
    'type': 'object',
    'properties': _user_properties,
    'required': ['name', 'domain_id'],
    'additionalProperties': True
}

user_update = {
    'type': 'object',
    'properties': _user_properties,
    'minProperties': 1,
    'additionalProperties': True
}

_group_properties = {
    'description': validation.nullable(parameter_types.description),
    'domain_id': parameter_types.id_string,
    'name': {
        'type': 'string',
        'minLength': 1,
        'maxLength': 64
    }
}

group_create = {
    'type': 'object',
    'properties': _user_properties,
    'required': ['name', 'domain_id'],
    'additionalProperties': True
}

group_update = {
    'type': 'object',
    'properties': _user_properties,
    'minProperties': 1,
    'additionalProperties': True
}