import sqlalchemy as sql

_SERVICE_TABLE_NAME = 'service'

def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    service_table = sql.Table(_SERVICE_TABLE_NAME, meta, autoload=True)

    # adding new columns
    service_desc = sql.Column('description', sql.String(255), nullable=True)
    service_table.create_column(service_desc)