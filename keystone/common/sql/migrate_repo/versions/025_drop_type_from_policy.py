import sqlalchemy as sql

_POLICY_TABLE_NAME = 'policy'


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    policy_table = sql.Table(_POLICY_TABLE_NAME, meta, autoload=True)
    policy_table.drop_column('type')