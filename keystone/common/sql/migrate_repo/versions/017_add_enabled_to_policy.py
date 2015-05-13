import sqlalchemy as sql

_POLICY_TABLE_NAME = 'policy'

def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    policy_table = sql.Table(_POLICY_TABLE_NAME, meta, autoload=True)

    # adding new columns
    policy_enabled = sql.Column('enabled', sql.Boolean, nullable=False, default=False)
    policy_table.create_column(policy_enabled)
