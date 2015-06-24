import sqlalchemy as sql

from keystone.identity.mapping_backends import mapping


HIERARCHY_TABLE = 'role_hierarchy'


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    rh_table = sql.Table(
        HIERARCHY_TABLE,
        meta,
        sql.Column('asc_id', sql.String(64), nullable=False),
        sql.Column('desc_id', sql.String(64), nullable=True),
        mysql_engine='InnoDB',
        mysql_charset='utf8')

    rh_table.create(migrate_engine, checkfirst=True)