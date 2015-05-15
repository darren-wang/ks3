import sqlalchemy as sql

_USER_TABLE_NAME = 'user'


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    user_table = sql.Table(_USER_TABLE_NAME, meta, autoload=True)
    user_table.drop_column('default_project_id')