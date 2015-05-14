import sqlalchemy as sql

_USER_TABLE_NAME = 'user'


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    region_table = sql.Table(_USER_TABLE_NAME, meta, autoload=True)
    region_table.drop_column('default_project_id')