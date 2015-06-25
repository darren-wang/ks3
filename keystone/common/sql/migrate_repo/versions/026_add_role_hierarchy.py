import migrate
import sqlalchemy as sql

HIERARCHY_TABLE = 'role_hierarchy'

def _add_constraints(role_table, rh_table):
    migrate.ForeignKeyConstraint(
        columns=[rh_table.asc_role_id, rh_table.desc_role_id],
        refcolumns=[role_table.id],
        name='fk_role_hierarchy_id').create()

    migrate.UniqueConstraint(rh_table.c.asc_role_id,
                             rh_table.c.desc_role_id,
                             name='ixu_asc_id_desc_id').create()

def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    role_table = sql.Table('role', meta, autoload=True)
    rh_table = sql.Table(
        HIERARCHY_TABLE, meta,
        sql.Column('asc_role_id', sql.String(64), nullable=False),
        sql.Column('desc_role_id', sql.String(64), nullable=False),
        mysql_engine='InnoDB', mysql_charset='utf8')

    rh_table.create(migrate_engine, checkfirst=True)

    _add_constraints(role_table, rh_table)