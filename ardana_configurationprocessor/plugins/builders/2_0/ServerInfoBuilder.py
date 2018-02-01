#
# (c) Copyright 2015-2017 Hewlett Packard Enterprise Development LP
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
import os
import logging
import logging.config
import yaml

from ardana_configurationprocessor.cp.model.v2_0.ArdanaPaths \
    import ArdanaPaths
from ardana_configurationprocessor.cp.model.v2_0.CloudModel \
    import CloudModel
from ardana_configurationprocessor.cp.model.v2_0 \
    import ServerState

from ardana_configurationprocessor.cp.model.BuilderPlugin \
    import BuilderPlugin
from ardana_configurationprocessor.cp.model.BuilderPlugin \
    import ArtifactMode
from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog


LOG = logging.getLogger(__name__)


class ServerInfoBuilder(BuilderPlugin):
    def __init__(self, instructions, models, controllers):
        super(ServerInfoBuilder, self).__init__(
            2.0, instructions, models, controllers,
            'server-info-2.0')
        LOG.info('%s()' % KenLog.fcn())

        self.cloud_desc = self._models['CloudDescription']['cloud']
        self._file_path = ArdanaPaths.get_output_path(self._instructions, self.cloud_desc)

        self._cloud_model = self._models['CloudModel']
        self._cloud_version = CloudModel.version(self._cloud_model, self._version)
        self._cloud_internal = CloudModel.internal(self._cloud_model)

        ArdanaPaths.make_path(self._file_path)

    def build(self):
        LOG.info('%s()' % KenLog.fcn())

        servers = CloudModel.get(self._cloud_internal, 'servers')
        server_info = {}

        for server in servers:
            server_info[server['id']] = {}
            data = server_info[server['id']]
            data['state'] = server['state']

            if server['state'] == ServerState.ALLOCATED:

                data['hostname'] = server['hostname']
                data['failure-zone'] = server['failure-zone']
                data['control-plane-name'] = server['control-plane-name']
                data['role'] = server['role']
                data['region'] = server['region']
                data['disk-model'] = server['disk-model']

                net_info = {}
                for if_name, if_data in server['interfaces'].iteritems():
                    net_info[if_name] = {}
                    for net_name, net_data in if_data['networks'].iteritems():
                        net_info[if_name][net_name] = \
                            {'addr': net_data.get('addr'),
                             'vlan-id': net_data.get('vlanid'),
                             'tagged-vlan': net_data.get('tagged-vlan', True),
                             'endpoints': net_data.get('endpoints'),
                             'cidr': net_data.get('cidr'),
                             'addresses': net_data.get('addresses', []),
                             'gateway-ip': net_data.get('gateway-ip'),
                             'network-group': net_data.get('network-group')}
                data['net_data'] = net_info

        filename = "%s/info/server_info.yml" % (
            self._file_path)
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))
        self.add_artifact(filename, ArtifactMode.CREATED)

        with open(filename, 'w') as fp:
            yaml.dump(server_info, fp, default_flow_style=False, indent=4)

    def get_dependencies(self):
        return ['persistent-state-2.0']
