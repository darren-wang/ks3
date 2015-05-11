import sqlalchemy as sql

from keystone.common.sql import migration_helpers

# adding foreign key constraints
def list_constraints(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    domain_table = sql.Table('domain', meta, autoload=True)
    policy_table = sql.Table('policy', meta, autoload=True)
    constraints = [{'table': policy_table,
                    'fk_column': 'domain_id',
                    'ref_column': domain_table.c.id}]
    return constraints

def upgrade(migrate_engine):
    if migrate_engine.name == 'sqlite':
        return
    migration_helpers.add_constraints(list_constraints(migrate_engine))