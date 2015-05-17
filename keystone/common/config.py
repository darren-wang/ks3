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

from oslo_config import cfg
import oslo_messaging


_DEFAULT_AUTH_METHODS = ['external', 'password', 'token', 'oauth1']
_CERTFILE = '/etc/keystone/ssl/certs/signing_cert.pem'
_KEYFILE = '/etc/keystone/ssl/private/signing_key.pem'
_SSO_CALLBACK = '/etc/keystone/sso_callback_template.html'


FILE_OPTIONS = {
    None: [
        cfg.StrOpt('admin_token', secret=True, default='ADMIN',
                   help='A "shared secret" that can be used to bootstrap '
                        'Keystone. This "token" does not represent a user, '
                        'and carries no explicit authorization. To disable '
                        'in production (highly recommended), remove '
                        'AdminTokenAuthMiddleware from your paste '
                        'application pipelines (for example, in '
                        'keystone-paste.ini).'),
        cfg.IntOpt('compute_port', default=8774,
                   help='(Deprecated) The port which the OpenStack Compute '
                        'service listens on. This option was only used for '
                        'string replacement in the templated catalog backend. '
                        'Templated catalogs should replace the '
                        '"$(compute_port)s" substitution with the static port '
                        'of the compute service. As of Juno, this option is '
                        'deprecated and will be removed in the L release.'),
        cfg.StrOpt('public_endpoint',
                   help='The base public endpoint URL for Keystone that is '
                        'advertised to clients (NOTE: this does NOT affect '
                        'how Keystone listens for connections). '
                        'Defaults to the base host URL of the request. E.g. a '
                        'request to http://server:5000/v3/users will '
                        'default to http://server:5000. You should only need '
                        'to set this value if the base URL contains a path '
                        '(e.g. /prefix/v3) or the endpoint should be found '
                        'on a different server.'),
        cfg.StrOpt('admin_endpoint',
                   help='The base admin endpoint URL for Keystone that is '
                        'advertised to clients (NOTE: this does NOT affect '
                        'how Keystone listens for connections). '
                        'Defaults to the base host URL of the request. E.g. a '
                        'request to http://server:35357/v3/users will '
                        'default to http://server:35357. You should only need '
                        'to set this value if the base URL contains a path '
                        '(e.g. /prefix/v3) or the endpoint should be found '
                        'on a different server.'),
        cfg.IntOpt('max_project_tree_depth', default=5,
                   help='Maximum depth of the project hierarchy. WARNING: '
                        'setting it to a large value may adversely impact '
                        'performance.'),
        cfg.IntOpt('max_param_size', default=64,
                   help='Limit the sizes of user & project ID/names.'),
        # we allow tokens to be a bit larger to accommodate PKI
        cfg.IntOpt('max_token_size', default=8192,
                   help='Similar to max_param_size, but provides an '
                        'exception for token values.'),
        cfg.StrOpt('member_role_id',
                   default='9fe2ff9ee4384b1894a90878d3e92bab',
                   help='Similar to the member_role_name option, this '
                        'represents the default role ID used to associate '
                        'users with their default projects in the v2 API. '
                        'This will be used as the explicit role where one is '
                        'not specified by the v2 API.'),
        cfg.StrOpt('member_role_name', default='_member_',
                   help='This is the role name used in combination with the '
                        'member_role_id option; see that option for more '
                        'detail.'),
        cfg.IntOpt('crypt_strength', default=40000,
                   help='The value passed as the keyword "rounds" to '
                        'passlib\'s encrypt method.'),
        cfg.IntOpt('list_limit',
                   help='The maximum number of entities that will be '
                        'returned in a collection, with no limit set by '
                        'default. This global limit may be then overridden '
                        'for a specific driver, by specifying a list_limit '
                        'in the appropriate section (e.g. [assignment]).'),
        cfg.BoolOpt('strict_password_check', default=False,
                    help='If set to true, strict password length checking is '
                         'performed for password manipulation. If a password '
                         'exceeds the maximum length, the operation will fail '
                         'with an HTTP 403 Forbidden error. If set to false, '
                         'passwords are automatically truncated to the '
                         'maximum length.'),
        cfg.StrOpt('secure_proxy_ssl_header',
                   help='The HTTP header used to determine the scheme for the '
                        'original request, even if it was removed by an SSL '
                        'terminating proxy. Typical value is '
                        '"HTTP_X_FORWARDED_PROTO".'),
    ],
    'identity': [
        cfg.StrOpt('admin_domain_id', default='default',
                   help='This references the domain to use for all '
                        'Identity API v2 requests (which are not aware of '
                        'domains). A domain with this ID will be created '
                        'for you by keystone-manage db_sync in migration '
                        '008. The domain referenced by this ID cannot be '
                        'deleted on the v3 API, to prevent accidentally '
                        'breaking the v2 API. There is nothing special about '
                        'this domain, other than the fact that it must '
                        'exist to order to maintain support for your v2 '
                        'clients.'),
        cfg.BoolOpt('domain_specific_drivers_enabled',
                    default=False,
                    help='A subset (or all) of domains can have their own '
                         'identity driver, each with their own partial '
                         'configuration options, stored in either the '
                         'resource backend or in a file in a domain '
                         'configuration directory (depending on the setting '
                         'of domain_configurations_from_database). Only '
                         'values specific to the domain need to be specified '
                         'in this manner. This feature is disabled by '
                         'default; set to true to enable.'),
        cfg.BoolOpt('domain_configurations_from_database',
                    default=False,
                    help='Extract the domain specific configuration options '
                         'from the resource backend where they have been '
                         'stored with the domain data. This feature is '
                         'disabled by default (in which case the domain '
                         'specific options will be loaded from files in the '
                         'domain configuration directory); set to true to '
                         'enable.'),
        cfg.StrOpt('domain_config_dir',
                   default='/etc/keystone/domains',
                   help='Path for Keystone to locate the domain specific '
                        'identity configuration files if '
                        'domain_specific_drivers_enabled is set to true.'),
        cfg.StrOpt('driver',
                   default=('keystone.identity.backends'
                            '.sql.Identity'),
                   help='Identity backend driver.'),
        cfg.BoolOpt('caching', default=True,
                    help='Toggle for identity caching. This has no '
                         'effect unless global caching is enabled.'),
        cfg.IntOpt('cache_time', default=600,
                   help='Time to cache identity data (in seconds). This has '
                        'no effect unless global and identity caching are '
                        'enabled.'),
        cfg.IntOpt('max_password_length', default=4096,
                   help='Maximum supported length for user passwords; '
                        'decrease to improve performance.'),
        cfg.IntOpt('list_limit',
                   help='Maximum number of entities that will be returned in '
                        'an identity collection.'),
    ],
    'identity_mapping': [
        cfg.StrOpt('driver',
                   default=('keystone.identity.mapping_backends'
                            '.sql.Mapping'),
                   help='Keystone Identity Mapping backend driver.'),
        cfg.StrOpt('generator',
                   default=('keystone.identity.id_generators'
                            '.sha256.Generator'),
                   help='Public ID generator for user and group entities. '
                        'The Keystone identity mapper only supports '
                        'generators that produce no more than 64 characters.'),
        cfg.BoolOpt('backward_compatible_ids',
                    default=True,
                    help='The format of user and group IDs changed '
                         'in Juno for backends that do not generate UUIDs '
                         '(e.g. LDAP), with keystone providing a hash mapping '
                         'to the underlying attribute in LDAP. By default '
                         'this mapping is disabled, which ensures that '
                         'existing IDs will not change. Even when the '
                         'mapping is enabled by using domain specific '
                         'drivers, any users and groups from the default '
                         'domain being handled by LDAP will still not be '
                         'mapped to ensure their IDs remain backward '
                         'compatible. Setting this value to False will '
                         'enable the mapping for even the default LDAP '
                         'driver. It is only safe to do this if you do not '
                         'already have assignments for users and '
                         'groups from the default LDAP domain, and it is '
                         'acceptable for Keystone to provide the different '
                         'IDs to clients than it did previously.  Typically '
                         'this means that the only time you can set this '
                         'value to False is when configuring a fresh '
                         'installation.'),
    ],
    'trust': [
        cfg.BoolOpt('enabled', default=True,
                    help='Delegation and impersonation features can be '
                         'optionally disabled.'),
        cfg.BoolOpt('allow_redelegation', default=False,
                    help='Enable redelegation feature.'),
        cfg.IntOpt('max_redelegation_count', default=3,
                   help='Maximum depth of trust redelegation.'),
        cfg.StrOpt('driver',
                   default='keystone.trust.backends.sql.Trust',
                   help='Trust backend driver.')],
    'os_inherit': [
        cfg.BoolOpt('enabled', default=False,
                    help='role-assignment inheritance to projects from '
                         'owning domain or from projects higher in the '
                         'hierarchy can be optionally enabled.'),
    ],
    'fernet_tokens': [
        cfg.StrOpt('key_repository',
                   default='/etc/keystone/fernet-keys/',
                   help='Directory containing Fernet token keys.'),
        cfg.IntOpt('max_active_keys',
                   default=3,
                   help='This controls how many keys are held in rotation by '
                        'keystone-manage fernet_rotate before they are '
                        'discarded. The default value of 3 means that '
                        'keystone will maintain one staged key, one primary '
                        'key, and one secondary key. Increasing this value '
                        'means that additional secondary keys will be kept in '
                        'the rotation.'),
    ],
    'token': [
        cfg.ListOpt('bind', default=[],
                    help='External auth mechanisms that should add bind '
                         'information to token, e.g., kerberos,x509.'),
        cfg.StrOpt('enforce_token_bind', default='permissive',
                   help='Enforcement policy on tokens presented to Keystone '
                        'with bind information. One of disabled, permissive, '
                        'strict, required or a specifically required bind '
                        'mode, e.g., kerberos or x509 to require binding to '
                        'that authentication.'),
        cfg.IntOpt('expiration', default=3600,
                   help='Amount of time a token should remain valid '
                        '(in seconds).'),
        cfg.StrOpt('provider',
                   default='keystone.token.providers.uuid.Provider',
                   help='Controls the token construction, validation, and '
                        'revocation operations. Core providers are '
                        '"keystone.token.providers.[fernet|pkiz|pki|uuid].'
                        'Provider".'),
        cfg.StrOpt('driver',
                   default='keystone.token.persistence.backends.sql.Token',
                   help='Token persistence backend driver.'),
        cfg.BoolOpt('caching', default=True,
                    help='Toggle for token system caching. This has no '
                         'effect unless global caching is enabled.'),
        cfg.IntOpt('cache_time',
                   help='Time to cache tokens (in seconds). This has no '
                        'effect unless global and token caching are '
                        'enabled.'),
        cfg.BoolOpt('revoke_by_id', default=True,
                    help='Revoke token by token identifier. Setting '
                    'revoke_by_id to true enables various forms of '
                    'enumerating tokens, e.g. `list tokens for user`. '
                    'These enumerations are processed to determine the '
                    'list of tokens to revoke. Only disable if you are '
                    'switching to using the Revoke extension with a '
                    'backend other than KVS, which stores events in memory.'),
        cfg.BoolOpt('allow_rescope_scoped_token', default=True,
                    help='Allow rescoping of scoped token. Setting '
                    'allow_rescoped_scoped_token to false prevents a user '
                    'from exchanging a scoped token for any other token.'),
        cfg.StrOpt('hash_algorithm', default='md5',
                   help="The hash algorithm to use for PKI tokens. This can "
                        "be set to any algorithm that hashlib supports. "
                        "WARNING: Before changing this value, the auth_token "
                        "middleware must be configured with the "
                        "hash_algorithms, otherwise token revocation will "
                        "not be processed correctly."),
    ],
    'revoke': [
        cfg.StrOpt('driver',
                   default='keystone.contrib.revoke.backends.sql.Revoke',
                   help='An implementation of the backend for persisting '
                        'revocation events.'),
        cfg.IntOpt('expiration_buffer', default=1800,
                   help='This value (calculated in seconds) is added to token '
                        'expiration before a revocation event may be removed '
                        'from the backend.'),
        cfg.BoolOpt('caching', default=True,
                    help='Toggle for revocation event caching. This has no '
                         'effect unless global caching is enabled.'),
        cfg.IntOpt('cache_time', default=3600,
                   help='Time to cache the revocation list and the revocation '
                        'events (in seconds). This has no effect unless '
                        'global and token caching are enabled.',
                   deprecated_opts=[cfg.DeprecatedOpt(
                       'revocation_cache_time', group='token')]),
    ],
    'cache': [
        cfg.StrOpt('config_prefix', default='cache.keystone',
                   help='Prefix for building the configuration dictionary '
                        'for the cache region. This should not need to be '
                        'changed unless there is another dogpile.cache '
                        'region with the same configuration name.'),
        cfg.IntOpt('expiration_time', default=600,
                   help='Default TTL, in seconds, for any cached item in '
                        'the dogpile.cache region. This applies to any '
                        'cached method that doesn\'t have an explicit '
                        'cache expiration time defined for it.'),
        # NOTE(morganfainberg): the dogpile.cache.memory acceptable in devstack
        # and other such single-process/thread deployments. Running
        # dogpile.cache.memory in any other configuration has the same pitfalls
        # as the KVS token backend. It is recommended that either Redis or
        # Memcached are used as the dogpile backend for real workloads. To
        # prevent issues with the memory cache ending up in "production"
        # unintentionally, we register a no-op as the keystone default caching
        # backend.
        cfg.StrOpt('backend', default='keystone.common.cache.noop',
                   help='Dogpile.cache backend module. It is recommended '
                        'that Memcache with pooling '
                        '(keystone.cache.memcache_pool) or Redis '
                        '(dogpile.cache.redis) be used in production '
                        'deployments.  Small workloads (single process) '
                        'like devstack can use the dogpile.cache.memory '
                        'backend.'),
        cfg.MultiStrOpt('backend_argument', default=[], secret=True,
                        help='Arguments supplied to the backend module. '
                             'Specify this option once per argument to be '
                             'passed to the dogpile.cache backend. Example '
                             'format: "<argname>:<value>".'),
        cfg.ListOpt('proxies', default=[],
                    help='Proxy classes to import that will affect the way '
                         'the dogpile.cache backend functions. See the '
                         'dogpile.cache documentation on '
                         'changing-backend-behavior.'),
        cfg.BoolOpt('enabled', default=False,
                    help='Global toggle for all caching using the '
                         'should_cache_fn mechanism.'),
        cfg.BoolOpt('debug_cache_backend', default=False,
                    help='Extra debugging from the cache backend (cache '
                         'keys, get/set/delete/etc calls). This is only '
                         'really useful if you need to see the specific '
                         'cache-backend get/set/delete calls with the '
                         'keys/values.  Typically this should be left set '
                         'to false.'),
        cfg.ListOpt('memcache_servers', default=['localhost:11211'],
                    help='Memcache servers in the format of "host:port".'
                    ' (dogpile.cache.memcache and keystone.cache.memcache_pool'
                    ' backends only).'),
        cfg.IntOpt('memcache_dead_retry',
                   default=5 * 60,
                   help='Number of seconds memcached server is considered dead'
                   ' before it is tried again. (dogpile.cache.memcache and'
                   ' keystone.cache.memcache_pool backends only).'),
        cfg.IntOpt('memcache_socket_timeout',
                   default=3,
                   help='Timeout in seconds for every call to a server.'
                   ' (dogpile.cache.memcache and keystone.cache.memcache_pool'
                   ' backends only).'),
        cfg.IntOpt('memcache_pool_maxsize',
                   default=10,
                   help='Max total number of open connections to every'
                   ' memcached server. (keystone.cache.memcache_pool backend'
                   ' only).'),
        cfg.IntOpt('memcache_pool_unused_timeout',
                   default=60,
                   help='Number of seconds a connection to memcached is held'
                   ' unused in the pool before it is closed.'
                   ' (keystone.cache.memcache_pool backend only).'),
        cfg.IntOpt('memcache_pool_connection_get_timeout',
                   default=10,
                   help='Number of seconds that an operation will wait to get '
                        'a memcache client connection.'),
    ],
    'ssl': [
        cfg.StrOpt('ca_key',
                   default='/etc/keystone/ssl/private/cakey.pem',
                   help='Path of the CA key file for SSL.'),
        cfg.IntOpt('key_size', default=1024,
                   help='SSL key length (in bits) (auto generated '
                        'certificate).'),
        cfg.IntOpt('valid_days', default=3650,
                   help='Days the certificate is valid for once signed '
                        '(auto generated certificate).'),
        cfg.StrOpt('cert_subject',
                   default='/C=US/ST=Unset/L=Unset/O=Unset/CN=localhost',
                   help='SSL certificate subject (auto generated '
                        'certificate).'),
    ],
    'signing': [
        cfg.StrOpt('certfile',
                   default=_CERTFILE,
                   help='Path of the certfile for token signing. For '
                        'non-production environments, you may be interested '
                        'in using `keystone-manage pki_setup` to generate '
                        'self-signed certificates.'),
        cfg.StrOpt('keyfile',
                   default=_KEYFILE,
                   help='Path of the keyfile for token signing.'),
        cfg.StrOpt('ca_certs',
                   default='/etc/keystone/ssl/certs/ca.pem',
                   help='Path of the CA for token signing.'),
        cfg.StrOpt('ca_key',
                   default='/etc/keystone/ssl/private/cakey.pem',
                   help='Path of the CA key for token signing.'),
        cfg.IntOpt('key_size', default=2048,
                   help='Key size (in bits) for token signing cert '
                        '(auto generated certificate).'),
        cfg.IntOpt('valid_days', default=3650,
                   help='Days the token signing cert is valid for '
                        '(auto generated certificate).'),
        cfg.StrOpt('cert_subject',
                   default=('/C=US/ST=Unset/L=Unset/O=Unset/'
                            'CN=www.example.com'),
                   help='Certificate subject (auto generated certificate) for '
                        'token signing.'),
    ],
    'assignment': [
        # assignment has no default for backward compatibility reasons.
        # If assignment driver is not specified, the identity driver chooses
        # the backend
        cfg.StrOpt('driver',
                   help='Assignment backend driver.'),
    ],
    'resource': [
        cfg.StrOpt('driver',
                   help='Resource backend driver. If a resource driver is '
                        'not specified, the assignment driver will choose '
                        'the resource driver.'),
        cfg.BoolOpt('caching', default=True,
                    deprecated_opts=[cfg.DeprecatedOpt('caching',
                                                       group='assignment')],
                    help='Toggle for resource caching. This has no effect '
                         'unless global caching is enabled.'),
        cfg.IntOpt('cache_time',
                   deprecated_opts=[cfg.DeprecatedOpt('cache_time',
                                                      group='assignment')],
                   help='TTL (in seconds) to cache resource data. This has '
                        'no effect unless global caching is enabled.'),
        cfg.IntOpt('list_limit',
                   deprecated_opts=[cfg.DeprecatedOpt('list_limit',
                                                      group='assignment')],
                   help='Maximum number of entities that will be returned '
                        'in a resource collection.'),
    ],
    'domain_config': [
        cfg.StrOpt('driver',
                   default='keystone.resource.config_backends.sql.'
                           'DomainConfig',
                   help='Domain config backend driver.'),
        cfg.BoolOpt('caching', default=True,
                    help='Toggle for domain config caching. This has no '
                         'effect unless global caching is enabled.'),
        cfg.IntOpt('cache_time', default=300,
                   help='TTL (in seconds) to cache domain config data. This '
                        'has no effect unless domain config caching is '
                        'enabled.'),
    ],
    'role': [
        # The role driver has no default for backward compatibility reasons.
        # If role driver is not specified, the assignment driver chooses
        # the backend
        cfg.StrOpt('driver',
                   help='Role backend driver.'),
        cfg.BoolOpt('caching', default=True,
                    help='Toggle for role caching. This has no effect '
                         'unless global caching is enabled.'),
        cfg.IntOpt('cache_time',
                   help='TTL (in seconds) to cache role data. This has '
                        'no effect unless global caching is enabled.'),
        cfg.IntOpt('list_limit',
                   help='Maximum number of entities that will be returned '
                        'in a role collection.'),
    ],
    'policy': [
        cfg.StrOpt('driver',
                   default='keystone.policy.backends.sql.Policy',
                   help='Policy backend driver.'),
        cfg.IntOpt('list_limit',
                   help='Maximum number of entities that will be returned '
                        'in a policy collection.'),
    ],
    'endpoint_filter': [
        cfg.StrOpt('driver',
                   default='keystone.contrib.endpoint_filter.backends'
                           '.sql.EndpointFilter',
                   help='Endpoint Filter backend driver'),
        cfg.BoolOpt('return_all_endpoints_if_no_filter', default=True,
                    help='Toggle to return all active endpoints if no filter '
                         'exists.'),
    ],
    'endpoint_policy': [
        cfg.StrOpt('driver',
                   default='keystone.contrib.endpoint_policy.backends'
                           '.sql.EndpointPolicy',
                   help='Endpoint policy backend driver'),
    ],
    
    'auth': [
        cfg.ListOpt('methods', default=_DEFAULT_AUTH_METHODS,
                    help='Default auth methods.'),
        cfg.StrOpt('password',
                   default='keystone.auth.plugins.password.Password',
                   help='The password auth plugin module.'),
        cfg.StrOpt('token',
                   default='keystone.auth.plugins.token.Token',
                   help='The token auth plugin module.'),
        # deals with REMOTE_USER authentication
        cfg.StrOpt('external',
                   default='keystone.auth.plugins.external.DefaultDomain',
                   help='The external (REMOTE_USER) auth plugin module.'),
        cfg.StrOpt('oauth1',
                   default='keystone.auth.plugins.oauth1.OAuth',
                   help='The oAuth1.0 auth plugin module.'),
    ],
    'paste_deploy': [
        cfg.StrOpt('config_file', default='keystone-paste.ini',
                   help='Name of the paste configuration file that defines '
                        'the available pipelines.'),
    ],
    'memcache': [
        cfg.ListOpt('servers', default=['localhost:11211'],
                    help='Memcache servers in the format of "host:port".'),
        cfg.IntOpt('dead_retry',
                   default=5 * 60,
                   help='Number of seconds memcached server is considered dead'
                        ' before it is tried again. This is used by the key '
                        'value store system (e.g. token '
                        'pooled memcached persistence backend).'),
        cfg.IntOpt('socket_timeout',
                   default=3,
                   help='Timeout in seconds for every call to a server. This '
                        'is used by the key value store system (e.g. token '
                        'pooled memcached persistence backend).'),
        cfg.IntOpt('pool_maxsize',
                   default=10,
                   help='Max total number of open connections to every'
                        ' memcached server. This is used by the key value '
                        'store system (e.g. token pooled memcached '
                        'persistence backend).'),
        cfg.IntOpt('pool_unused_timeout',
                   default=60,
                   help='Number of seconds a connection to memcached is held'
                        ' unused in the pool before it is closed. This is used'
                        ' by the key value store system (e.g. token pooled '
                        'memcached persistence backend).'),
        cfg.IntOpt('pool_connection_get_timeout',
                   default=10,
                   help='Number of seconds that an operation will wait to get '
                        'a memcache client connection. This is used by the '
                        'key value store system (e.g. token pooled memcached '
                        'persistence backend).'),
    ],
    'catalog': [
        cfg.StrOpt('template_file',
                   default='default_catalog.templates',
                   help='Catalog template file name for use with the '
                        'template catalog backend.'),
        cfg.StrOpt('driver',
                   default='keystone.catalog.backends.sql.Catalog',
                   help='Catalog backend driver.'),
        cfg.BoolOpt('caching', default=True,
                    help='Toggle for catalog caching. This has no '
                         'effect unless global caching is enabled.'),
        cfg.IntOpt('cache_time',
                   help='Time to cache catalog data (in seconds). This has no '
                        'effect unless global and catalog caching are '
                        'enabled.'),
        cfg.IntOpt('list_limit',
                   help='Maximum number of entities that will be returned '
                        'in a catalog collection.'),
    ],
    'kvs': [
        cfg.ListOpt('backends', default=[],
                    help='Extra dogpile.cache backend modules to register '
                         'with the dogpile.cache library.'),
        cfg.StrOpt('config_prefix', default='keystone.kvs',
                   help='Prefix for building the configuration dictionary '
                        'for the KVS region. This should not need to be '
                        'changed unless there is another dogpile.cache '
                        'region with the same configuration name.'),
        cfg.BoolOpt('enable_key_mangler', default=True,
                    help='Toggle to disable using a key-mangling function '
                         'to ensure fixed length keys. This is toggle-able '
                         'for debugging purposes, it is highly recommended '
                         'to always leave this set to true.'),
        cfg.IntOpt('default_lock_timeout', default=5,
                   help='Default lock timeout (in seconds) for distributed '
                        'locking.'),
    ],
    'eventlet_server': [
        cfg.IntOpt('public_workers',
                   deprecated_name='public_workers',
                   deprecated_group='DEFAULT',
                   deprecated_for_removal=True,
                   help='The number of worker processes to serve the public '
                        'eventlet application. Defaults to number of CPUs '
                        '(minimum of 2).'),
        cfg.IntOpt('admin_workers',
                   deprecated_name='admin_workers',
                   deprecated_group='DEFAULT',
                   deprecated_for_removal=True,
                   help='The number of worker processes to serve the admin '
                        'eventlet application. Defaults to number of CPUs '
                        '(minimum of 2).'),
        cfg.StrOpt('public_bind_host',
                   default='0.0.0.0',
                   deprecated_opts=[cfg.DeprecatedOpt('bind_host',
                                                      group='DEFAULT'),
                                    cfg.DeprecatedOpt('public_bind_host',
                                                      group='DEFAULT'), ],
                   deprecated_for_removal=True,
                   help='The IP address of the network interface for the '
                        'public service to listen on.'),
        cfg.IntOpt('public_port', default=5000, deprecated_name='public_port',
                   deprecated_group='DEFAULT',
                   deprecated_for_removal=True,
                   help='The port number which the public service listens '
                        'on.'),
        cfg.StrOpt('admin_bind_host',
                   default='0.0.0.0',
                   deprecated_opts=[cfg.DeprecatedOpt('bind_host',
                                                      group='DEFAULT'),
                                    cfg.DeprecatedOpt('admin_bind_host',
                                                      group='DEFAULT')],
                   deprecated_for_removal=True,
                   help='The IP address of the network interface for the '
                        'admin service to listen on.'),
        cfg.IntOpt('admin_port', default=35357, deprecated_name='admin_port',
                   deprecated_group='DEFAULT',
                   deprecated_for_removal=True,
                   help='The port number which the admin service listens '
                        'on.'),
        cfg.BoolOpt('tcp_keepalive', default=False,
                    deprecated_name='tcp_keepalive',
                    deprecated_group='DEFAULT',
                    deprecated_for_removal=True,
                    help='Set this to true if you want to enable '
                         'TCP_KEEPALIVE on server sockets, i.e. sockets used '
                         'by the Keystone wsgi server for client '
                         'connections.'),
        cfg.IntOpt('tcp_keepidle',
                   default=600,
                   deprecated_name='tcp_keepidle',
                   deprecated_group='DEFAULT',
                   deprecated_for_removal=True,
                   help='Sets the value of TCP_KEEPIDLE in seconds for each '
                        'server socket. Only applies if tcp_keepalive is '
                        'true.'),
    ],
    'eventlet_server_ssl': [
        cfg.BoolOpt('enable', default=False, deprecated_name='enable',
                    deprecated_group='ssl',
                    deprecated_for_removal=True,
                    help='Toggle for SSL support on the Keystone '
                         'eventlet servers.'),
        cfg.StrOpt('certfile',
                   default="/etc/keystone/ssl/certs/keystone.pem",
                   deprecated_name='certfile', deprecated_group='ssl',
                   deprecated_for_removal=True,
                   help='Path of the certfile for SSL. For non-production '
                        'environments, you may be interested in using '
                        '`keystone-manage ssl_setup` to generate self-signed '
                        'certificates.'),
        cfg.StrOpt('keyfile',
                   default='/etc/keystone/ssl/private/keystonekey.pem',
                   deprecated_name='keyfile', deprecated_group='ssl',
                   deprecated_for_removal=True,
                   help='Path of the keyfile for SSL.'),
        cfg.StrOpt('ca_certs',
                   default='/etc/keystone/ssl/certs/ca.pem',
                   deprecated_name='ca_certs', deprecated_group='ssl',
                   deprecated_for_removal=True,
                   help='Path of the CA cert file for SSL.'),
        cfg.BoolOpt('cert_required', default=False,
                    deprecated_name='cert_required', deprecated_group='ssl',
                    deprecated_for_removal=True,
                    help='Require client certificate.'),
    ],
}


CONF = cfg.CONF
oslo_messaging.set_transport_defaults(control_exchange='keystone')


def _register_auth_plugin_opt(conf, option):
    conf.register_opt(option, group='auth')


def setup_authentication(conf=None):
    # register any non-default auth methods here (used by extensions, etc)
    if conf is None:
        conf = CONF
    for method_name in conf.auth.methods:
        if method_name not in _DEFAULT_AUTH_METHODS:
            option = cfg.StrOpt(method_name)
            _register_auth_plugin_opt(conf, option)


def configure(conf=None):
    if conf is None:
        conf = CONF

    conf.register_cli_opt(
        cfg.BoolOpt('standard-threads', default=False,
                    help='Do not monkey-patch threading system modules.'))
    conf.register_cli_opt(
        cfg.StrOpt('pydev-debug-host',
                   help='Host to connect to for remote debugger.'))
    conf.register_cli_opt(
        cfg.IntOpt('pydev-debug-port',
                   help='Port to connect to for remote debugger.'))

    for section in FILE_OPTIONS:
        for option in FILE_OPTIONS[section]:
            if section:
                conf.register_opt(option, group=section)
            else:
                conf.register_opt(option)

    # register any non-default auth methods here (used by extensions, etc)
    setup_authentication(conf)


def list_opts():
    """Return a list of oslo_config options available in Keystone.

    The returned list includes all oslo_config options which are registered as
    the "FILE_OPTIONS" in keystone.common.config. This list will not include
    the options from the oslo-incubator library or any options registered
    dynamically at run time.

    Each object in the list is a two element tuple. The first element of
    each tuple is the name of the group under which the list of options in the
    second element will be registered. A group name of None corresponds to the
    [DEFAULT] group in config files.

    This function is also discoverable via the 'oslo_config.opts' entry point
    under the 'keystone.config.opts' namespace.

    The purpose of this is to allow tools like the Oslo sample config file
    generator to discover the options exposed to users by this library.

    :returns: a list of (group_name, opts) tuples
    """
    return FILE_OPTIONS.items()
