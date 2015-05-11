import sqlalchemy as sql
import migrate

_POLICY_TABLE_NAME = 'policy'

def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    policy_table = sql.Table(_POLICY_TABLE_NAME, meta, autoload=True)

    # adding new columns
    policy_name = sql.Column('name', sql.String(length=64), nullable=False)
    policy_table.create_column(policy_name)
    
    policy_desc = sql.Column('description', sql.Text)
    policy_table.create_column(policy_desc)
    
    policy_domain_id = sql.Column('domain_id', sql.String(length=64), nullable=False)
    policy_table.create_column(policy_domain_id)

    # adding unique constraints
    migrate.UniqueConstraint(policy_table.c.domain_id,
                             policy_table.c.name,
                             name='ixu_policy_name_domain_id').create()
