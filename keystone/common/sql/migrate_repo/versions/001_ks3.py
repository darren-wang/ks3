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


import migrate
from oslo_config import cfg
from oslo_log import log
import sqlalchemy as sql
from sqlalchemy import orm

from keystone.assignment.backends import sql as assignment_sql
from keystone.common import sql as ks_sql
from keystone.common.sql import migration_helpers


LOG = log.getLogger(__name__)
CONF = cfg.CONF


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    if migrate_engine.name == 'mysql':
        # In Folsom we explicitly converted migrate_version to UTF8.
        migrate_engine.execute(
            'ALTER TABLE migrate_version CONVERT TO CHARACTER SET utf8')
        # Set default DB charset to UTF8.
        migrate_engine.execute(
            'ALTER DATABASE %s DEFAULT CHARACTER SET utf8' %
            migrate_engine.url.database)

    assignment = sql.Table(
        'assignment',
        meta,
        sql.Column('type', sql.Enum(
            assignment_sql.AssignmentType.USER_PROJECT,
            assignment_sql.AssignmentType.GROUP_PROJECT,
            assignment_sql.AssignmentType.USER_DOMAIN,
            assignment_sql.AssignmentType.GROUP_DOMAIN,
            name='type'),
            nullable=False),
        sql.Column('actor_id', sql.String(64), nullable=False),
        sql.Column('target_id', sql.String(64), nullable=False),
        sql.Column('role_id', sql.String(64), nullable=False),
        sql.Column('inherited', sql.Boolean, default=False, nullable=False),
        sql.PrimaryKeyConstraint('type', 'actor_id', 'target_id', 'role_id'),
        mysql_engine='InnoDB',
        mysql_charset='utf8')

    domain = sql.Table(
        'domain', meta,
        sql.Column('id', sql.String(length=64), primary_key=True),
        sql.Column('name', sql.String(length=64), nullable=False),
        sql.Column('enabled', sql.Boolean, default=True, nullable=False),
        sql.Column('description', sql.Text(), nullable=True),
        sql.Column('extra', ks_sql.JsonBlob.impl),
        mysql_engine='InnoDB',
        mysql_charset='utf8')

    endpoint = sql.Table(
        'endpoint', meta,
        sql.Column('id', sql.String(length=64), primary_key=True),
        sql.Column('interface', sql.String(length=8), nullable=False),
        sql.Column('region', sql.String(length=255)),
        sql.Column('service_id', sql.String(length=64), nullable=False),
        sql.Column('url', sql.Text, nullable=False),
        sql.Column('extra', ks_sql.JsonBlob.impl),
        sql.Column('enabled', sql.Boolean, nullable=False, default=True,
                   server_default='1'),
        sql.Column('description', sql.String(255), nullable=True),
        mysql_engine='InnoDB',
        mysql_charset='utf8')

    policy = sql.Table(
        'policy', meta,
        sql.Column('id', sql.String(length=64), primary_key=True),
        sql.Column('name', sql.String(length=64), nullable=False),
        sql.Column('domain_id', sql.String(length=64), nullable=False),
        sql.Column('description', sql.Text, nullable=True),
        sql.Column('enabled', sql.Boolean, nullable=False, default=True),
        mysql_engine='InnoDB',
        mysql_charset='utf8')
 
    project = sql.Table(
        'project', meta,
        sql.Column('id', sql.String(length=64), primary_key=True),
        sql.Column('name', sql.String(length=64), nullable=False),
        sql.Column('domain_id', sql.String(length=64), nullable=False),
        sql.Column('description', sql.Text),
        sql.Column('enabled', sql.Boolean),
        mysql_engine='InnoDB',
        mysql_charset='utf8')

    region = sql.Table(
        'region', meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('description', sql.String(255), nullable=False),
        sql.Column('parent_region_id', sql.String(64), nullable=True),
        sql.Column('extra', sql.Text()),
        mysql_engine='InnoDB',
        mysql_charset='utf8')

    role = sql.Table(
        'role', meta,
        sql.Column('id', sql.String(length=64), primary_key=True),
        sql.Column('name', sql.String(length=255), nullable=False),
        sql.Column('extra', ks_sql.JsonBlob.impl),
        sql.Column('description', sql.Text),
        sql.Column('domain_id', sql.String(length=64), nullable=False),
        mysql_engine='InnoDB',
        mysql_charset='utf8')

    rule = sql.Table(
        'rule', meta,
        sql.Column('id', sql.String(length=64), primary_key=True),
        sql.Column('policy_id', sql.String(length=64), nullable=False),
        sql.Column('service', sql.String(length=64), nullable=False),
        sql.Column('action', sql.String(length=64), nullable=False),
        sql.Column('content', ks_sql.JsonBlob.impl, nullable=True),
        mysql_engine='InnoDB',
        mysql_charset='utf8')

    service = sql.Table(
        'service', meta,
        sql.Column('id', sql.String(length=64), primary_key=True),
        sql.Column('type', sql.String(length=255)),
        sql.Column('enabled', sql.Boolean, nullable=False, default=True,
                   server_default='1'),
        sql.Column('description', sql.String(255), nullable=True),
        sql.Column('extra', ks_sql.JsonBlob.impl),
        mysql_engine='InnoDB',
        mysql_charset='utf8')

    token = sql.Table(
        'token', meta,
        sql.Column('id', sql.String(length=64), primary_key=True),
        sql.Column('expires', sql.DateTime, default=None),
        sql.Column('extra', ks_sql.JsonBlob.impl),
        sql.Column('valid', sql.Boolean, default=True, nullable=False),
        sql.Column('trust_id', sql.String(length=64)),
        sql.Column('user_id', sql.String(length=64)),
        mysql_engine='InnoDB',
        mysql_charset='utf8')

    user = sql.Table(
        'user', meta,
        sql.Column('id', sql.String(length=64), primary_key=True),
        sql.Column('name', sql.String(length=255), nullable=False),
        sql.Column('password', sql.String(length=128)),
        sql.Column('domain_id', sql.String(length=64), nullable=False),
        sql.Column('description', sql.Text(), nullable=True),
        sql.Column('enabled', sql.Boolean),
        sql.Column('extra', ks_sql.JsonBlob.impl),
        mysql_engine='InnoDB',
        mysql_charset='utf8')

    # create all tables
    tables = [region, service, endpoint, rule,
              domain, project, role, assignment,
              user, policy, token ]

    for table in tables:
        try:
            table.create()
        except Exception:
            LOG.exception('Exception while creating table: %r', table)
            raise

    # Unique Constraints
    migrate.UniqueConstraint(user.c.domain_id,
                             user.c.name,
                             name='ixu_user_name_domain_id').create()
    migrate.UniqueConstraint(role.c.name,
                             role.c.domain_id,
                             name='ixu_role_name_domain_id').create()
    migrate.UniqueConstraint(project.c.domain_id,
                             project.c.name,
                             name='ixu_project_name_domain_id').create()
    migrate.UniqueConstraint(policy.c.domain_id,
                             policy.c.name,
                             name='ixu_policy_name_domain_id').create()
    migrate.UniqueConstraint(policy.c.domain_id,
                             policy.c.enabled,
                             name='ixu_policy_enabled_domain_id').create()
    migrate.UniqueConstraint(rule.c.service, rule.c.policy_id,
                             rule.c.action,
                             name='ixu_rule_policy_service_action').create()
    migrate.UniqueConstraint(domain.c.name,
                             name='ixu_domain_name').create()

    # Indexes
    sql.Index('ix_token_expires', token.c.expires).create()
    sql.Index('ix_token_expires_valid', token.c.expires,
              token.c.valid).create()
    
    sql.Index('ix_actor_id', assignment.c.actor_id).create()
    
    sql.Index('ix_token_user_id', token.c.user_id).create()
    sql.Index('ix_token_trust_id', token.c.trust_id).create()

    # Foreign keys
    fkeys = [
        {'columns': [user.c.domain_id],
         'references': [domain.c.id],
         'name': 'fk_user_domain_id'},

        {'columns': [project.c.domain_id],
         'references': [domain.c.id],
         'name': 'fk_project_domain_id'},

        {'columns': [role.c.domain_id],
         'references': [domain.c.id],
         'name': 'fk_role_domain_id'},
   
        {'columns': [policy.c.domain_id],
         'references': [domain.c.id],
         'name':'fk_policy_domain_id'},

        {'columns': [endpoint.c.service_id],
         'references': [service.c.id],
         'name': 'fk_endpoint_service_id'},
             
        {'columns': [rule.c.policy_id],
         'references': [policy.c.id],
         'name': 'fk_rule_policy_id'}
    ]

    for fkey in fkeys:
        migrate.ForeignKeyConstraint(columns=fkey['columns'],
                                     refcolumns=fkey['references'],
                                     name=fkey.get('name')).create()

    # Create the default domain.
    session = orm.sessionmaker(bind=migrate_engine)()
    domain.insert(migration_helpers.get_default_domain()).execute()
    session.commit()


def downgrade(migrate_engine):
    raise NotImplementedError('Downgrade to pre-Icehouse release db schema is '
                              'unsupported.')
