# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
# (c) Copyright 2017-2018 SUSE LLC
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
import logging
import logging.config
import string

from ardana_configurationprocessor.cp.model.CPLogging import \
    CPLogging as KenLog
from ardana_configurationprocessor.cp.model.GeneratorPlugin \
    import GeneratorPlugin
from ardana_configurationprocessor.cp.model.v2_0.CloudModel \
    import CloudModel


LOG = logging.getLogger(__name__)


class MemoryModelGenerator(GeneratorPlugin):
    def __init__(self, instructions, models, controllers):
        super(MemoryModelGenerator, self).__init__(
            2.0, instructions, models, controllers,
            'memory-model-generator-2.0')
        LOG.info('%s()' % KenLog.fcn())

    def generate(self):
        LOG.info('%s()' % KenLog.fcn())

        self._action = KenLog.fcn()
        cloud_internal = CloudModel.internal(self._models['CloudModel'])
        cloud_version = CloudModel.version(self._models['CloudModel'], self._version)
        servers = CloudModel.get(cloud_internal, 'servers', {})

        server_roles = {}
        for role in CloudModel.get(cloud_version, 'server-roles'):
            server_roles[role['name']] = role

        memory_models = {}
        for memory_model in CloudModel.get(cloud_version, 'memory-models', []):
            memory_models[memory_model['name']] = memory_model

        for server in servers:
            if server['state'] != 'allocated':
                continue

            server['memory-model'] = {}

            server_role = server_roles[server['role']]
            if 'memory-model' not in server_role:
                continue

            memory_model = memory_models[server_role['memory-model']]
            my_memory_model = {'name': memory_model['name']}
            non_numa_pages = []
            numa_pages = []
            for page in memory_model.get('huge-pages', {}):
                page_info = {'size': page['size'],
                             'count': page['count'],
                             'size_in_k': self._page_size(page['size'])}

                if 'numa-node' in page:
                    page_info['numa_node'] = page['numa-node']
                    numa_pages.append(page_info)
                else:
                    non_numa_pages.append(page_info)
            if memory_model.get('vm-size', None):
                my_memory_model['vm_ram_size_in_k'] = self._memory_size(memory_model['vm-size']['ram'])

            my_memory_model['numa_huge_pages'] = numa_pages
            my_memory_model['non_numa_huge_pages'] = non_numa_pages

            if 'default-huge-page-size' in memory_model:
                my_memory_model['default_huge_page_size'] = memory_model['default-huge-page-size']

            server['memory-model'] = my_memory_model

    def _page_size(self, size):
            multiplier = {'K': 0,
                          'M': 1024,
                          'G': 1024 * 1024}

            num = str(size).strip("KMG")
            qual = str(size).lstrip(string.digits)
            return int(num) * multiplier[qual]

    def _memory_size(self, size):
            multiplier = {'K': 1,
                          'M': 1024,
                          'G': 1024 * 1024}

            num = str(size).strip("KMG")
            qual = str(size).lstrip(string.digits)
            return int(num) * multiplier[qual]

    def get_dependencies(self):
        return ['encryption-key',
                'internal-model-2.0',
                'cloud-cplite-2.0']
