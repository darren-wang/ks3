from oslo_config import cfg
from oslo_policy import policy as common_policy


CONF = cfg.CONF

# This dict is unusable due to following reasons:
# 1. It's just my expectation to have isolation in this way, the attributes used
# in this dict are not tested, every operation needs to be tested in the official
# release to verify if the attributes used here are available.
# 2. Even the attributes are available, the rules defined here may not be enough
# to provide desirable domain(tenant) isolation.

isol_rules = {
# generic
    # The Syetem developer must ensure that: All the actions need
    # to be isolated are listed here.
    # so if an action isn't found in this dict, it is in the charge
    # of RBAC enforcer.
    "default": "",  
    "admin_domain": "domain_id:" + CONF.identity.default_domain_id, # what if this value changes?
    "owner": "user_id:%(user_id)s or user_id:%(target.token.user_id)s",
    "matching_domain_id": "domain_id:%(domain_id)s",
# domain
    "matching_target_domain_id": "domain_id:%(target.domain.id)s",
    "identity:get_domain": "domain_id:%(target.domain.id)s",
    "identity:update_domain": "domain_id:%(target.domain.id)s",
# project
    "matching_target_project_domain_id": "domain_id:%(target.project.domain_id)s",
    "matching_project_domain_id": "domain_id:%(project.domain_id)s",
    "identity:get_project": "rule:matching_target_project_domain_id",
    "identity:list_projects": "rule:matching_domain_id",
    "identity:list_user_projects": "rule:owner or rule:matching_domain_id",
    "identity:create_project": "rule:matching_project_domain_id",
    "identity:update_project": "rule:matching_target_project_domain_id",
    "identity:delete_project": "rule:matching_target_project_domain_id",
# user
    "matching_target_user_domain_id": "domain_id:%(target.user.domain_id)s",
    "matching_user_domain_id": "domain_id:%(user.domain_id)s",
    "identity:get_user": "rule:owner or rule:matching_target_user_domain_id",
    "identity:list_users": "rule:matching_domain_id",
    "identity:create_user": "rule:matching_user_domain_id",
    "identity:update_user": "rule:owner or rule:matching_target_user_domain_id",
    "identity:delete_user": "rule:matching_target_user_domain_id",
# group
    "matching_target_group_domain_id": "domain_id:%(target.group.domain_id)s",
    "matching_group_domain_id": "domain_id:%(group.domain_id)s",
    "identity:get_group": "rule:matching_target_group_domain_id",
    "identity:list_groups": "rule:matching_domain_id",
    "identity:list_groups_for_user": "rule:matching_domain_id",
    "identity:create_group": "rule:matching_group_domain_id",
    "identity:update_group": "rule:matching_target_group_domain_id",
    "identity:delete_group": "rule:matching_target_group_domain_id",
    "identity:list_users_in_group": "rule:matching_target_group_domain_id",
    "identity:remove_user_from_group": "rule:matching_target_group_domain_id",
    "identity:check_user_in_group": "rule:matching_target_group_domain_id",
    "identity:add_user_to_group": "rule:matching_target_group_domain_id",
# role
    "matching_target_role_domain_id": "domain_id:%(target.role.domain_id)s",
    "matching_role_domain_id": "domain_id:%(role.domain_id)s",
    "identity:get_role": "rule:matching_target_role_domain_id",
    "identity:list_roles": "rule:matching_domain_id",
    "identity:create_role": "rule:matching_role_domain_id",
    "identity:update_role": "rule:matching_target_role_domain_id",
    "identity:delete_role": "rule:matching_target_role_domain_id",
# grant
    "matching_domain_for_grants": "domain_id:%(domain_id)s or domain_id:%(target.project.domain_id)s",
    "matching_project_for_grants": "project_id:%(project_id)s",
    "identity:check_grant": "rule:matching_domain_for_grants or rule:matching_project_for_grants",
    "identity:list_grants": "rule:matching_domain_for_grants or rule:matching_project_for_grants",
    "identity:create_grant": "rule:matching_domain_for_grants or rule:matching_project_for_grants",
    "identity:revoke_grant": "rule:matching_domain_for_grants or rule:matching_project_for_grants",
# role assignment
    "matching_domain_filter" : "domain_id:%(scope.domain.id)s",
    "matching_project_filter" : "project_id:%(scope.project.id)s",
    "identity:list_role_assignments": "rule:matching_domain_filter or rule:matching_project_filter",
# policy
    "matching_target_policy_domain_id": "domain_id:%(target.policy.domain_id)s",
    "matching_policy_domain_id": "domain_id:%(policy.domain_id)s",
    "identity:get_policy": "rule:matching_target_policy_domain_id",
    "identity:list_policies": "rule:matching_domain_id",
    "identity:create_policy": "rule:matching_policy_domain_id",
    "identity:update_policy": "rule:matching_target_policy_domain_id",
    "identity:delete_policy": "rule:matching_target_policy_domain_id",
# token
    "matching_target_token_domain_id": "domain_id:%(target.token.user.domain.id)s",
    "identity:revoke_token": "rule:matching_target_token_domain_id",
# domain config
    "matching_target_domain_config_domain_id":"domain_id:%(target.domain_config.domain_id)s",
    "matching_domain_config_domain_id": "domain_id:%(domain_config.domain_id)s",
    "identity:create_domain_config": "rule:matching_domain_config_domain_id",
    "identity:get_domain_config": "rule:matching_target_domain_config_domain_id",
    "identity:update_domain_config": "rule:matching_target_domain_config_domain_id",
    "identity:delete_domain_config": "rule:matching_target_domain_config_domain_id",
# un-triaged
    "identity:list_projects_for_groups": "",
    "identity:list_domains_for_groups": "",
}


# Next, we are going to point isol_dict to the result of parsed 
# dict above, the dict above will no longer occupy memory since
# it's no longer referenced.
isol_rules = common_policy.Rules.from_dict(isol_rules, isol_rules['default'])