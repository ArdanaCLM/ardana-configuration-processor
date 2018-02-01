# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
# (c) Copyright 2017-2018 SUSE LLC
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
import logging
import logging.config

from ardana_configurationprocessor.cp.model.CPLogging import \
    CPLogging as KenLog
from ardana_configurationprocessor.cp.model.GeneratorPlugin \
    import GeneratorPlugin
from ardana_configurationprocessor.cp.model.v2_0.CloudModel \
    import CloudModel


LOG = logging.getLogger(__name__)
DEFAULT_MTU = 1500


class NetworkGenerator(GeneratorPlugin):
    def __init__(self, instructions, models, controllers):
        super(NetworkGenerator, self).__init__(
            2.0, instructions, models, controllers,
            'network-generator-2.0')
        LOG.info('%s()' % KenLog.fcn())

    def generate(self):
        LOG.info('%s()' % KenLog.fcn())
        self._action = KenLog.fcn()
        cloud_version = CloudModel.version(
            self._models['CloudModel'], self._version)
        cloud_internal = CloudModel.internal(self._models['CloudModel'])

        networks = {}
        network_groups = {}

        for group in CloudModel.get(cloud_version, 'network-groups'):
            network_groups[group['name']] = group
            network_groups[group['name']]['networks'] = []

        for net in CloudModel.get(cloud_version, 'networks'):
            networks[net['name']] = net

        # add networks into their respective network groups
        for net_name, net in networks.iteritems():
            if net.get('network-group', None):
                network_groups[net['network-group']]['networks'].append(net)

        # Inject a network group for each provider network, so we can support
        # routes to them
        for config_data in CloudModel.get(cloud_version, 'configuration-data', []):
            if 'neutron' in config_data.get('services', []):
                for net in config_data.get('data', {}).get('neutron_provider_networks', []):
                    provider_net = {'name': net['name'],
                                    'cidr': net['cidr'],
                                    'network-group': net['name'],
                                    'neutron_network': True}
                    group = {'name': net['name'],
                             'networks': [provider_net]}
                    networks[net['name']] = provider_net
                    network_groups[net['name']] = group

        self._generate_default_network_mtu(network_groups)

        CloudModel.put(cloud_internal, 'networks', networks)
        CloudModel.put(cloud_internal, 'network-groups', network_groups)

    def _generate_default_network_mtu(self, network_groups):
        LOG.info('%s()' % KenLog.fcn())

        for net_group in network_groups.values():
            explicit_mtu = 'mtu' in net_group
            mtu = net_group.get('mtu', DEFAULT_MTU)
            for net in net_group.get('networks', []):
                net['mtu'] = mtu
                net['explicit_mtu'] = explicit_mtu

    def get_dependencies(self):
        return []
