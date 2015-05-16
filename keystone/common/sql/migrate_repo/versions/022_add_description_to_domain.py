import sqlalchemy as sql

_DOMAIN_TABLE_NAME = 'domain'

def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    domain_table = sql.Table(_DOMAIN_TABLE_NAME, meta, autoload=True)

    domain_desc = sql.Column('description', sql.Text(), nullable=True)
    domain_table.create_column(domain_desc)