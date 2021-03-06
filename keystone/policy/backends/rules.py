# Copyright (c) 2011 OpenStack, LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Policy engine for keystone"""

from oslo_config import cfg
from oslo_log import log
from oslo_policy import policy as common_policy

from keystone import exception
from keystone import policy

CONF = cfg.CONF
LOG = log.getLogger(__name__)


_ENFORCER = None


def reset():
    global _ENFORCER
    _ENFORCER = None


def init():
    global _ENFORCER
    if not _ENFORCER:
        _ENFORCER = common_policy.Enforcer(CONF)


def enforce(action, target, creds, do_raise=True):
    """Verifies that the action is valid on the target in this context.

       :param creds: user credentials
       :param action: string representing the action to be checked, which
                      should be colon separated for clarity.
                      Or it can be a Check instance.
       :param target: dictionary representing the object of the action
                      for object creation this should be a dictionary
                      representing the location of the object e.g.
                      {'project_id': object.project_id}
       :param rule_dict: instance of oslo_policy.policy.Rules, it's 
                         actually a dict, with keys are the actions
                         to be protected and values are parsed Check trees.
       :raises: `exception.Forbidden` if verification fails.

       Actions should be colon separated for clarity. For example:

        * identity:list_users

    """
    init()

    # Add the exception arguments if asked to do a raise
    extra = {}
    if do_raise:
        extra.update(exc=exception.ForbiddenAction, service=action[0],
                     permission=action[1], do_raise=do_raise)

    return _ENFORCER.enforce(action, target, creds, **extra)


class Policy(policy.PolicyDriver):

    def enforce(self, action, target, creds, do_raise=True):
        LOG.debug('API protection:\nsubject:%(creds)s\nact\n'
        'service:%(serv)s permission:%(perm)s\non\n'
        'target: %(target)s\n', {
            'serv': action[0], 'perm': action[1], 'creds': creds,
            'target':target})
        return enforce(action, target, creds, do_raise)

    def create_policy(self, policy_id, policy):
        raise exception.NotImplemented()

    def list_policies(self):
        raise exception.NotImplemented()

    def get_policy(self, policy_id):
        raise exception.NotImplemented()

    def update_policy(self, policy_id, policy):
        raise exception.NotImplemented()

    def delete_policy(self, policy_id):
        raise exception.NotImplemented()
