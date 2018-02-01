#
# (c) Copyright 2015-2016 Hewlett Packard Enterprise Development LP
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

from ardana_configurationprocessor.cp.model.BuilderPlugin \
    import BuilderPlugin
from ardana_configurationprocessor.cp.model.BuilderPlugin \
    import ArtifactMode
from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog


LOG = logging.getLogger(__name__)


class TopologyInfoBuilder(BuilderPlugin):
    def __init__(self, instructions, models, controllers):
        super(TopologyInfoBuilder, self).__init__(
            2.0, instructions, models, controllers,
            'topology-info-2.0')
        LOG.info('%s()' % KenLog.fcn())

        self.cloud_desc = self._models['CloudDescription']['cloud']
        self._file_path = ArdanaPaths.get_output_path(self._instructions, self.cloud_desc)

        self._cloud_model = self._models['CloudModel']
        self._cloud_version = CloudModel.version(self._cloud_model, self._version)
        self._cloud_internal = CloudModel.internal(self._cloud_model)

        ArdanaPaths.make_path(self._file_path)

    def build(self):
        LOG.info('%s()' % KenLog.fcn())

        cp_topology = CloudModel.get(self._cloud_internal, 'cp-topology')
        filename = "%s/info/control_plane_topology.yml" % (
            self._file_path)
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))
        self.add_artifact(filename, ArtifactMode.CREATED)
        with open(filename, 'w') as fp:
            yaml.dump(cp_topology, fp, default_flow_style=False, indent=4)

        region_topology = CloudModel.get(self._cloud_internal, 'region-topology')
        filename = "%s/info/region_topology.yml" % (
            self._file_path)
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))
        self.add_artifact(filename, ArtifactMode.CREATED)
        with open(filename, 'w') as fp:
            yaml.dump(region_topology, fp, default_flow_style=False, indent=4)

        service_topology = CloudModel.get(self._cloud_internal, 'service-topology')
        filename = "%s/info/service_topology.yml" % (
            self._file_path)
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))
        self.add_artifact(filename, ArtifactMode.CREATED)
        with open(filename, 'w') as fp:
            yaml.dump(service_topology, fp, default_flow_style=False, indent=4)

        network_topology = CloudModel.get(self._cloud_internal, 'network-topology')
        filename = "%s/info/network_topology.yml" % (
            self._file_path)
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))
        self.add_artifact(filename, ArtifactMode.CREATED)
        with open(filename, 'w') as fp:
            yaml.dump(network_topology, fp, default_flow_style=False, indent=4)

    def get_dependencies(self):
        return ['persistent-state-2.0']
