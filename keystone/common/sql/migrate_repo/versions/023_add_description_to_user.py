import sqlalchemy as sql

_USER_TABLE_NAME = 'user'

def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    user_table = sql.Table(_USER_TABLE_NAME, meta, autoload=True)

    user_desc = sql.Column('description', sql.Text(), nullable=True)
    user_table.create_column(user_desc)