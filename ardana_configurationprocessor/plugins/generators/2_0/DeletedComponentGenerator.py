# (c) Copyright 2015-2016 Hewlett Packard Enterprise Development LP
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


class DeletedComponentGenerator(GeneratorPlugin):
    def __init__(self, instructions, models, controllers):
        super(DeletedComponentGenerator, self).__init__(
            2.0, instructions, models, controllers,
            'deleted-component-generator-2.0')
        LOG.info('%s()' % KenLog.fcn())

    def generate(self):
        LOG.info('%s()' % KenLog.fcn())

        cloud_internal = CloudModel.internal(self._models['CloudModel'])
        control_planes = CloudModel.get(cloud_internal, 'control-planes', [])

        for cp_name, cp in control_planes.iteritems():
            deleted_components = []
            for cluster in cp['clusters']:
                for server in cluster['servers']:
                    self._add_deleted_components(deleted_components, server)

            for r_name, resources in cp.get('resources', {}).iteritems():
                for server in resources.get('servers', []):
                    self._add_deleted_components(deleted_components, server)

            cp['deleted-components'] = deleted_components

        CloudModel.put(cloud_internal, 'control-planes', control_planes)

    def _add_deleted_components(self, deleted_components, server):

        previous_config = server.get('previous_config', {})
        for previous_component in previous_config.get('components', []):
            if previous_component in server.get('components', []):
                continue

            print "Component %s deleted from server %s" % (previous_component, server['name'])

            if previous_component not in deleted_components:
                deleted_components.append(previous_component)

    def get_dependencies(self):
        return ['encryption-key',
                'internal-model-2.0',
                'cloud-cplite-2.0']
