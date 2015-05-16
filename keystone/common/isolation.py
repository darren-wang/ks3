from oslo_config import cfg
from oslo_log import log
from oslo_policy import policy as common_policy


CONF = cfg.CONF
LOG = log.getLogger(__name__)

# This dict is unusable due to following reasons:
# 1. It's just my expectation to have isolation in this way, the attributes used
# in this dict are not tested, every operation needs to be tested in the official
# release to verify if the attributes used here are available.
# 2. Even the attributes are available, the rules defined here may not be enough
# to provide desirable domain(tenant) isolation.
class IsolationRules(object):
    def __init__(self):
        self.isol_rules = {
        # generic
            # The Syetem developer must ensure that: All the actions need
            # to be isolated are listed here.
            # so if an action isn't found in this dict, it is in the charge
            # of RBAC enforcer.
            "default": "@",  
            "admin_domain": "domain_id:" + CONF.identity.admin_domain_id,
        # region
            "identity:list_regions": "",
            "identity:get_region": "",
            "identity:create_region": "rule:admin_domain",
            "identity:update_region": "rule:admin_domain",
            "identity:delete_region": "rule:admin_domain",
        # service
            "identity:list_services": "",
            "identity:get_service": "",
            "identity:create_service": "rule:admin_domain",
            "identity:update_service": "rule:admin_domain",
            "identity:delete_service": "rule:admin_domain",
        # endpoint
            "identity:get_endpoint": "",
            "identity:list_endpoints": "",
            "identity:create_endpoint": "rule:admin_domain",
            "identity:update_endpoint": "rule:admin_domain",
            "identity:delete_endpoint": "rule:admin_domain",
        # domain
            "identity:list_domains": "rule:admin_domain",
            "identity:create_domain": "rule:admin_domain",
            "identity:delete_domain": "rule:admin_domain",
            "identity:get_domain": "scope:domain and scope_id:%(target.domain.id)s",
            "identity:update_domain": "scope:domain and scope_id:%(target.domain.id)s",
        # project
            "identity:list_projects": "scope:domain and scope_id:%(domain_id)s",
            "identity:list_user_projects": "user_id:%(user_id)s or (scope:domain and scope_id:%(domain_id)s)",
            "identity:create_project": "scope:domain and scope_id:%(project.domain_id)s",
            "identity:get_project": "(scope:domain and scope_id:%(target.project.domain_id)s) or (scope:project and scope_id:%(target.project.id)s)",
            "identity:update_project": "(scope:domain and scope_id:%(target.project.domain_id)s and scope_id:%(project.domain_id)s) or (scope:project and scope_id:%(target.project.id)s and scope_domain_id:%(project.domain_id)s)",
            "identity:delete_project": "scope:domain and scope_id:%(target.project.domain_id)s",
        # user    
            "identity:list_users": "scope:domain and scope_id:%(domain_id)s",
            "identity:create_user": "scope:domain and scope_id:%(user.domain_id)s",
            "identity:get_user": "user_id:%(user_id)s or user_id:%(target.user.id)s or (scope:domain and scope_id:%(target.user.domain_id)s)",
            "identity:update_user": "user_id:%(user_id)s or user_id:%(target.user.id)s or (scope:domain and scope_id:%(target.user.domain_id)s)",
            "identity:delete_user": "scope:domain and scope_id:%(target.user.domain_id)s",
        # group
            "identity:get_group": "scope:domain and scope_id:%(target.group.domain_id)s",
            "identity:list_groups": "scope:domain and scope_id:%(domain_id)s",
            "identity:list_groups_for_user": "user_id:%(user_id)s or (scope:domain and scope_id:%(domain_id)s)",
            "identity:create_group": "scope:domain and scope_id:%(group.domain_id)s",
            "identity:update_group": "scope:domain and scope_id:%(target.group.domain_id)s",
            "identity:delete_group": "scope:domain and scope_id:%(target.group.domain_id)s",
            "identity:remove_user_from_group": "scope:domain and scope_id:%(target.group.domain_id)s",
            "identity:check_user_in_group": "scope:domain and scope_id:%(target.group.domain_id)s",
            "identity:add_user_to_group": "scope:domain and scope_id:%(target.group.domain_id)s",
            "identity:list_users_in_group": "scope:domain and scope_id:%(target.group.domain_id)s",
            "identity:list_projects_for_groups": "",
            "identity:list_domains_for_groups": "",
        # grant(it's very loose)
            "identity:check_grant": "scope_id:%(domain_id)s or scope_id:%(target.project.domain_id)s or scope_id:%(project_id)s",
            "identity:list_grants": "scope_id:%(domain_id)s or scope_id:%(target.project.domain_id)s or scope_id:%(project_id)s",
            "identity:create_grant": "scope_id:%(domain_id)s or scope_id:%(target.project.domain_id)s or scope_id:%(project_id)s",
            "identity:revoke_grant": "scope_id:%(domain_id)s or scope_id:%(target.project.domain_id)s or scope_id:%(project_id)s",
        # role assignment
            "identity:list_role_assignments": "user_id:%(user.id)s or scope_id:%(scope.domain.id)s or scope_id:%(scope.project.id)s",
        # token
            "identity:change_password": "",
            "identity:check_token": "",
            "identity:validate_token": "",
            "identity:revocation_list": "",
            "identity:revoke_token": "user_id:%(target.token.user_id)s or scope_id:%(target.token.user.domain.id)s",
        # role
            "identity:get_role": "scope_domain_id:%(target.role.domain_id)s",
            "identity:list_roles": "scope_domain_id:%(domain_id)s",
            "identity:create_role": "scope:domain and scope_id:%(role.domain_id)s",
            "identity:update_role": "scope:domain and scope_id:%(target.role.domain_id)s and scope_id:%(role.domain_id)s",
            "identity:delete_role": "scope:domain and scope_id:%(target.role.domain_id)s",
        # policy
#            "identity:get_policy": "scope:domain and scope_id:%(target.policy.domain_id)s",
#            "identity:list_policies": "scope:domain and scope_id:%(domain_id)s",
#            "identity:create_policy": "scope:domain and scope_id:%(policy.domain_id)s",
#            "identity:update_policy": "scope:domain and scope_id:%(target.policy.domain_id)s",
#            "identity:delete_policy": "scope:domain and scope_id:%(target.policy.domain_id)s",
            "identity:get_policy":"",
            "identity:list_policies":"",
            "identity:create_policy":"",
            "identity:update_policy":"",
            "identity:delete_policy":"",
        # other
            "identity:get_auth_catalog": "",
            "identity:get_auth_projects": "",
            "identity:get_auth_domains": "",
            "identity:list_revoke_events": ""
        }

        # Next, we are going to point isol_dict to the result of parsed 
        # dict above, the dict above will no longer occupy memory since
        # it's no longer referenced.
        self.isol_rules = common_policy.Rules.from_dict(self.isol_rules, 'default')
