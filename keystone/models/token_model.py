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

"""Unified in-memory token model."""

from keystone.common import cms
from oslo_config import cfg
from oslo_utils import timeutils
import six

from keystone import exception
from keystone.i18n import _


CONF = cfg.CONF
# supported token versions
V3 = 'v3.0'
VERSIONS = frozenset([V3])


def _parse_and_normalize_time(time_data):
    if isinstance(time_data, six.string_types):
        time_data = timeutils.parse_isotime(time_data)
    return timeutils.normalize_time(time_data)


class KeystoneToken(dict):
    """An in-memory representation that unifies v2 and v3 tokens."""
    # TODO(morganfainberg): Align this in-memory representation with the
    # objects in keystoneclient. This object should be eventually updated
    # to be the source of token data with the ability to emit any version
    # of the token instead of only consuming the token dict and providing
    # property accessors for the underlying data.

    def __init__(self, token_id, token_data):
        self.token_data = token_data
        if 'token' in token_data and 'methods' in token_data['token']:
            super(KeystoneToken, self).__init__(**token_data['token'])
            self.version = V3
        else:
            raise exception.UnsupportedTokenVersionException()
        self.token_id = token_id
        self.short_id = cms.cms_hash_token(token_id,
                                           mode=CONF.token.hash_algorithm)

        if self.project_scoped and self.domain_scoped:
            raise exception.UnexpectedError(_('Found invalid token: scoped to '
                                              'both project and domain.'))

    def __repr__(self):
        desc = ('<%(type)s (audit_id=%(audit_id)s, '
                'audit_chain_id=%(audit_chain_id)s) at %(loc)s>')
        return desc % {'type': self.__class__.__name__,
                       'audit_id': self.audit_id,
                       'audit_chain_id': self.audit_chain_id,
                       'loc': hex(id(self))}

    @property
    def expires(self):
        expires_at = self['expires_at']
        return _parse_and_normalize_time(expires_at)

    @property
    def issued(self):
        issued_at = self['issued_at']
        return _parse_and_normalize_time(issued_at)

    @property
    def audit_id(self):
        return self.get('audit_ids', [None])[0]

    @property
    def audit_chain_id(self):
        return self.get('audit_ids', [None])[-1]

    @property
    def auth_token(self):
        return self.token_id

    @property
    def user_id(self):
        return self['user']['id']

    @property
    def user_name(self):
        return self['user']['name']

    @property
    def user_domain_name(self):
        try:
            return self['user']['domain']['name']
        except KeyError:
            # Do not raise KeyError, raise UnexpectedError
            pass
        raise exception.UnexpectedError()

    @property
    def user_domain_id(self):
        try:
            return self['user']['domain']['id']
        except KeyError:
            # Do not raise KeyError, raise UnexpectedError
            pass
        raise exception.UnexpectedError()

    @property
    def domain_id(self):
        try:
            return self['domain']['id']
        except KeyError:
            # Do not raise KeyError, raise UnexpectedError
            raise exception.UnexpectedError()

    @property
    def domain_name(self):
        try:
            return self['domain']['name']
        except KeyError:
            # Do not raise KeyError, raise UnexpectedError
            raise exception.UnexpectedError()

    @property
    def project_id(self):
        try:
            return self['project']['id']
        except KeyError:
            # Do not raise KeyError, raise UnexpectedError
            raise exception.UnexpectedError()

    @property
    def project_name(self):
        try:
            return self['project']['name']
        except KeyError:
            # Do not raise KeyError, raise UnexpectedError
            raise exception.UnexpectedError()

    @property
    def project_domain_id(self):
        try:
            return self['project']['domain']['id']
        except KeyError:
            # Do not raise KeyError, raise UnexpectedError
            pass
        raise exception.UnexpectedError()

    @property
    def project_domain_name(self):
        try:
            return self['project']['domain']['name']
        except KeyError:
            # Do not raise KeyError, raise UnexpectedError
            pass
        raise exception.UnexpectedError()

    @property
    def project_scoped(self):
            return 'project' in self

    @property
    def domain_scoped(self):
            return 'domain' in self

    @property
    def scoped(self):
        return self.project_scoped or self.domain_scoped

    @property
    def role_ids(self):
            return [r['id'] for r in self.get('roles', [])]

    @property
    def role_names(self):
            return [r['name'] for r in self.get('roles', [])]

    @property
    def bind(self):
            return self.get('bind')

    @property
    def metadata(self):
        return self.get('metadata', {})

    @property
    def methods(self):
        return self.get('methods', [])
