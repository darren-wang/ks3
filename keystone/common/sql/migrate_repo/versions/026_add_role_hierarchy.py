import sqlalchemy as sql

from keystone.identity.mapping_backends import mapping


HIERARCHY_TABLE = 'role_hierarchy'


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    mapping_table = sql.Table(
        HIERARCHY_TABLE,
        meta,
        sql.Column('public_id', sql.String(64), primary_key=True),
        sql.Column('domain_id', sql.String(64), nullable=False),
        sql.Column('local_id', sql.String(64), nullable=False),
        sql.Column('entity_type', sql.Enum(
            mapping.EntityType.USER,
            mapping.EntityType.GROUP,
            name='entity_type'),
            nullable=False),
        sql.UniqueConstraint('domain_id', 'local_id', 'entity_type'),
        mysql_engine='InnoDB',
        mysql_charset='utf8')
    mapping_table.create(migrate_engine, checkfirst=True)