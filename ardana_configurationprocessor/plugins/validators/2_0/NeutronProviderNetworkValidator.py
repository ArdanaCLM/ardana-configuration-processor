#
# (c) Copyright 2019 SUSE LLC
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

import logging
import logging.config
import re

from ardana_configurationprocessor.cp.model.ValidatorPlugin \
    import ValidatorPlugin
from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog

PROVIDER_KEY = 'neutron_provider_networks'
EXTERNAL_KEY = 'neutron_external_networks'

LOG = logging.getLogger(__name__)


class NeutronProviderNetworkValidator(ValidatorPlugin):
    def __init__(self, instructions, config_files):
        super(NeutronProviderNetworkValidator, self).__init__(
            2.0, instructions, config_files,
            'physnet-check-2.0')
        LOG.info('%s()' % KenLog.fcn())
        self._valid = True
        self.input = {}
        self.ardana_physnet_mappings = {}
        self._read_input()

    def validate(self):
        for physnet in self.ardana_physnet_mappings.keys():
            networks = self.ardana_physnet_mappings[physnet]
            for network in networks:
                msg = ("The network group %s is mapped to neutron physnet %s. "
                       "Please ensure that management network access is not "
                       "provided by physnet %s as this can cause management "
                       "network connectivity to be interruped."
                       % (network, physnet, physnet))
                self.add_warning(msg)

    def _read_input(self):
        self.input['network-groups'] = self._create_content(
            self.version(), "network-groups").get('network-groups')
        self._read_model_physnets()

    def _read_model_physnets(self):
        for group in self.input['network-groups']:
            for tag in group.get('tags', []):
                physnet = self._get_tag_provider_physnet(tag)
                if physnet:
                    mappings = self.ardana_physnet_mappings.get(physnet, [])
                    mappings.append(group['name'])
                    self.ardana_physnet_mappings[physnet] = mappings

    def _get_tag_provider_physnet(self, tag):
        if isinstance(tag, dict):
            for attr in tag.values():
                if isinstance(attr, dict):
                    return attr.get('provider-physical-network')
        return None
