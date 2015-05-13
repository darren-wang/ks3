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
    "default": "@",  
    "admin_domain": "domain_id:" + CONF.identity.default_domain_id, # what if this value changes?
# domain
    "identity:get_domain": "domain_id:%(target.domain.id)s",
    "identity:update_domain": "domain_id:%(target.domain.id)s",
# project
    "identity:list_projects": "domain_id:%(domain_id)s",
    "identity:list_user_projects": "user_id:%(user_id)s or domain_id:%(domain_id)s",
    "identity:create_project": "domain_id:%(project.domain_id)s",
    "identity:get_project": "domain_id:%(target.project.domain_id)s or project_id:%(target.project.id)s",
    "identity:update_project": "domain_id:%(target.project.domain_id)s or project_id:%(target.project.id)s",
    "identity:delete_project": "domain_id:%(target.project.domain_id)s",
# user    
    "identity:list_users": "domain_id:%(domain_id)s",
    "identity:create_user": "domain_id:%(user.domain_id)s or project_id:%(user.default_project_id)s",
    "identity:get_user": "user_id:%(user_id)s or user_id:%(target.user.id)s or domain_id:%(target.user.domain_id)s",
    "identity:update_user": "user_id:%(user_id)s or user_id:%(target.user.id)s or domain_id:%(target.user.domain_id)s or project_id:%(target.user.default_project_id)s",
    "identity:delete_user": "domain_id:%(target.user.domain_id)s or project_id:%(target.user.default_project_id)s",
# group
    "identity:get_group": "domain_id:%(target.group.domain_id)s",
    "identity:list_groups": "domain_id:%(domain_id)s",
    "identity:list_groups_for_user": "domain_id:%(domain_id)s",
    "identity:create_group": "domain_id:%(group.domain_id)s",
    "identity:update_group": "domain_id:%(target.group.domain_id)s",
    "identity:delete_group": "domain_id:%(target.group.domain_id)s",
    "identity:remove_user_from_group": "domain_id:%(target.group.domain_id)s",
    "identity:check_user_in_group": "domain_id:%(target.group.domain_id)s",
    "identity:add_user_to_group": "domain_id:%(target.group.domain_id)s",
    "identity:list_users_in_group": "domain_id:%(target.group.domain_id)s",
    "identity:list_projects_for_groups": "",
    "identity:list_domains_for_groups": "",
# grant(it's very loose)
    "identity:check_grant": "domain_id:%(domain_id)s or domain_id:%(target.project.domain_id)s or project_id:%(project_id)s",
    "identity:list_grants": "domain_id:%(domain_id)s or domain_id:%(target.project.domain_id)s or project_id:%(project_id)s",
    "identity:create_grant": "domain_id:%(domain_id)s or domain_id:%(target.project.domain_id)s or project_id:%(project_id)s",
    "identity:revoke_grant": "domain_id:%(domain_id)s or domain_id:%(target.project.domain_id)s or project_id:%(project_id)s",
# role assignment
    "identity:list_role_assignments": "user_id:%(user.id)s or domain_id:%(scope.domain.id)s or project_id:%(scope.project.id)s",
# token
    "identity:revoke_token": "user_id:%(target.token.user_id)s or domain_id:%(target.token.user.domain.id)s",
# role
    "identity:get_role": "domain_id:%(target.role.domain_id)s",
    "identity:list_roles": "domain_id:%(domain_id)s",
    "identity:create_role": "domain_id:%(role.domain_id)s",
    "identity:update_role": "domain_id:%(target.role.domain_id)s",
    "identity:delete_role": "domain_id:%(target.role.domain_id)s",
# policy
    "identity:get_policy": "domain_id:%(target.policy.domain_id)s",
    "identity:list_policies": "domain_id:%(domain_id)s",
    "identity:create_policy": "domain_id:%(policy.domain_id)s",
    "identity:update_policy": "domain_id:%(target.policy.domain_id)s",
    "identity:delete_policy": "domain_id:%(target.policy.domain_id)s"
}


# Next, we are going to point isol_dict to the result of parsed 
# dict above, the dict above will no longer occupy memory since
# it's no longer referenced.
isol_rules = common_policy.Rules.from_dict(isol_rules, isol_rules['default'])