import sqlalchemy as sql
from keystone.common import sql as ks_sql

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
    
    trust = sql.Table(
        'trust', meta,
        sql.Column('id', sql.String(length=64), primary_key=True),
        sql.Column('trustor_user_id', sql.String(length=64), nullable=False),
        sql.Column('trustee_user_id', sql.String(length=64), nullable=False),
        sql.Column('project_id', sql.String(length=64)),
        sql.Column('impersonation', sql.Boolean, nullable=False),
        sql.Column('deleted_at', sql.DateTime),
        sql.Column('expires_at', sql.DateTime),
        sql.Column('remaining_uses', sql.Integer, nullable=True),
        sql.Column('extra', ks_sql.JsonBlob.impl),
        mysql_engine='InnoDB',
        mysql_charset='utf8')

    trust_role = sql.Table(
        'trust_role', meta,
        sql.Column('trust_id', sql.String(length=64), primary_key=True,
                   nullable=False),
        sql.Column('role_id', sql.String(length=64), primary_key=True,
                   nullable=False),
        mysql_engine='InnoDB',
        mysql_charset='utf8')
    
    trust.create()
    trust_role.create()