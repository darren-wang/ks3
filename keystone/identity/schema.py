from keystone.common import validation
from keystone.common.validation import parameter_types

# NOTE(lhcheng): the max length is not applicable since it is specific
# to the SQL backend, LDAP does not have length limitation.
_identity_name = {
    'type': 'string',
    'minLength': 1
}

_user_properties = {
    'description': validation.nullable(parameter_types.description),
    'domain_id': parameter_types.id_string,
    'enabled': parameter_types.boolean,
    'name': _identity_name,
    'password': {
        'type': ['string', 'null']
    }
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
    'name': _identity_name
}

group_create = {
    'type': 'object',
    'properties': _group_properties,
    'required': ['name', 'domain_id'],
    'additionalProperties': True
}

group_update = {
    'type': 'object',
    'properties': _group_properties,
    'minProperties': 1,
    'additionalProperties': True
}