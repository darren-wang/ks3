import sqlalchemy as sql

_ENDPOINT_TABLE_NAME = 'service'

def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    endpoint_table = sql.Table(_ENDPOINT_TABLE_NAME, meta, autoload=True)

    endpoint_desc = sql.Column('description', sql.String(255), nullable=False)
    endpoint_table.create_column(endpoint_desc)