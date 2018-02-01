#
# (c) Copyright 2015, 2016 Hewlett Packard Enterprise Development LP
# (c) Copyright 2017-2018 SUSE LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
import hashlib
import logging
import logging.config

from ardana_configurationprocessor.cp.model.ValidatorPlugin \
    import ValidatorPlugin
from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog


IPTABLES_MAX_CHAIN_NAME_LEN = 28
IPTABLES_ROOT_PREFIX = 'ardana-INPUT-'
IPTABLES_ROOT_PREFIX_LEN = len(IPTABLES_ROOT_PREFIX)
IPTABLES_CHAIN_NAME_HASH_LEN = IPTABLES_MAX_CHAIN_NAME_LEN - IPTABLES_ROOT_PREFIX_LEN


LOG = logging.getLogger(__name__)


class NetworkGroupsValidator(ValidatorPlugin):
    def __init__(self, instructions, config_files):
        super(NetworkGroupsValidator, self).__init__(
            2.0, instructions, config_files,
            'network-groups-2.0')
        self._valid = False
        LOG.info('%s()' % KenLog.fcn())

    def validate(self):
        LOG.info('%s()' % KenLog.fcn())

        version = float(self.version())

        input = self._create_content(version, "network-groups")
        self._valid = self.validate_schema(input, "network_group")
        if self._valid:

            components = self._get_dict_from_config_value(version, 'service-components')
            network_groups = input['network-groups']
            self._validate_names(network_groups)
            self._validate_unique_hash_prefix(network_groups)
            self._validate_components(network_groups, components)
        LOG.info('%s()' % KenLog.fcn())
        return self._valid

    def _validate_unique_hash_prefix(self, network_groups):
        # This validation check is needed because the iptables_update module
        # for creating the Ardana OpenStack firewall uses the md5 hash of the network
        # group name as the iptables chain name.
        hash_prefixes = {}
        for network_group in network_groups:
            group_name_hash = hashlib.md5(network_group['name']).hexdigest()
            hash_prefix = group_name_hash[:IPTABLES_CHAIN_NAME_HASH_LEN]
            if hash_prefix in hash_prefixes:
                msg = ("Network groups: the first %s chars of the md5 "
                       "hexdigest for '%s' clashes with the md5 hexdigest of "
                       "'%s'. Please change one of these names." %
                       (IPTABLES_CHAIN_NAME_HASH_LEN, network_group['name'],
                        hash_prefixes[hash_prefix]))
                self.add_error(msg)
                self._valid = False
            else:
                hash_prefixes[hash_prefix] = network_group['name']

    def _validate_names(self, network_groups):
        names = set()
        for group in network_groups:
            if group['name'] in names:
                msg = ("Network Group %s is defined more than once." %
                       (group['name']))
                self.add_error(msg)
                self._valid = False
            else:
                names.add(group['name'])

    def _validate_components(self, network_groups, components):

        connected_components = {}
        default_components = []

        for net_group in network_groups:
            for comp_name in (net_group.get('component-endpoints', []) +
                              net_group.get('tls-component-endpoints', [])):
                if comp_name == 'default':
                    if default_components:
                        default_components.append(net_group['name'])
                        msg = ("'default' specified for component-endpoints in "
                               "more than one network group: %s" %
                               sorted(default_components))
                        self.add_error(msg)
                    else:
                        default_components.append(net_group['name'])
                else:
                    if comp_name not in components:
                        msg = ("Undefined component '%s' in network group '%s'" %
                               (comp_name, net_group['name']))
                        self.add_error(msg)
                    else:
                        if 'endpoints' in components[comp_name]:
                            if comp_name in connected_components:
                                connected_components[comp_name].append(net_group['name'])
                                msg = ("'%s' is connected to more than one "
                                       "network group: %s." %
                                       (comp_name,
                                        sorted(connected_components[comp_name])))
                                self.add_error(msg)
                            else:
                                if comp_name not in connected_components:
                                    connected_components[comp_name] = []
                                connected_components[comp_name].append(net_group['name'])

    @staticmethod
    def _get_network_groups_with_tags(network_groups):
        return (group for group in network_groups if 'tags' in group)

    @staticmethod
    def _get_dict_tags_from_network_group(network_group):
        return (tag for tag in network_group['tags'] if type(tag) is dict)

    @property
    def instructions(self):
        return self._instructions

    @property
    def valid(self):
        return self._valid

    @valid.setter
    def valid(self, is_valid):
        self._valid = is_valid

    def get_dependencies(self):
        return []
