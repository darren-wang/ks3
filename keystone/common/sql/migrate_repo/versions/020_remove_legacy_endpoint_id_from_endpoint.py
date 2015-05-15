import sqlalchemy as sql

_ENDPOINT_TABLE_NAME = 'endpoint'


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    endpoint_table = sql.Table(_ENDPOINT_TABLE_NAME, meta, autoload=True)
    endpoint_table.drop_column('legacy_endpoint_id')