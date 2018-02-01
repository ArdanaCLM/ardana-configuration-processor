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

from copy import deepcopy
import logging
import logging.config

from ardana_configurationprocessor.cp.model.CPLogging import \
    CPLogging as KenLog
from ardana_configurationprocessor.cp.model.GeneratorPlugin \
    import GeneratorPlugin
from ardana_configurationprocessor.cp.model.v2_0.CloudModel \
    import CloudModel


LOG = logging.getLogger(__name__)


class CpuAssignmentGenerator(GeneratorPlugin):
    def __init__(self, instructions, models, controllers):
        super(CpuAssignmentGenerator, self).__init__(
            2.0, instructions, models, controllers,
            'cpu-assignment-generator-2.0')
        LOG.info('%s()' % KenLog.fcn())

    def generate(self):

        def _get_bitmask(cpus):
            bitmask = 0
            for x in cpus:
                bitmask += (1 << x)
            return bitmask

        LOG.info('%s()' % KenLog.fcn())

        self._action = KenLog.fcn()
        cloud_internal = CloudModel.internal(self._models['CloudModel'])

        cloud_version = CloudModel.version(self._models['CloudModel'], self._version)

        servers = CloudModel.get(cloud_internal, 'servers', {})
        components = CloudModel.get(cloud_internal, 'components', {})

        cpu_models = {}
        for model in CloudModel.get(cloud_version, 'cpu-models', []):
            cpu_models[model['name']] = model

        server_roles = {}
        for role in CloudModel.get(cloud_version, 'server-roles', []):
            server_roles[role['name']] = role

        for s in servers:
            if s['state'] != 'allocated':
                continue

            server_role = server_roles[s['role']]

            s['cpu-assignments'] = {}
            if 'cpu-model' in server_role:

                server_cpus = []
                cpu_model = cpu_models[server_role['cpu-model']]

                if cpu_model.get('vm-size', {}):
                    s['vm_no_of_vcpus'] = cpu_model.get('vm-size')['vcpus']

                for service_data in cpu_model.get('assignments', []):

                    comp_on_server = False
                    for comp_name in service_data['components']:
                        if comp_name in s['components']:
                            comp_on_server = True
                            break

                    if not comp_on_server:
                        msg = ("CPU Assignment for components %s in '%s' "
                               "has not been applied to server '%s' (id: %s role: %s) "
                               "because it does not host any of the listed components." %
                               (str(service_data['components']).strip('[]'),
                                cpu_model['name'],
                                s['name'], s['id'], s['role']))
                        self.add_warning(msg)
                        continue

                    assignment_data = {}
                    for cpu_data in service_data.get('cpu', []):

                        cpu_list = cpu_data['processor-ids']
                        if cpu_data.get('isolate', True):
                            server_cpus.extend(cpu_list)

                        assignment_data[cpu_data['role']] = \
                            {'processor_ids': cpu_list,
                             'bitmask': "0x%04x" % _get_bitmask(cpu_list),
                             'processor_list': str(sorted(cpu_list)).strip('[]').replace(' ', '')}

                    for comp_name in service_data['components']:
                        mnemonic = components[comp_name]['mnemonic'].replace('-', '_')
                        s['cpu-assignments'][mnemonic] = deepcopy(assignment_data)

                # Add Server level data
                s['cpu-assignments']['server'] = {}
                if server_cpus:
                    s['cpu-assignments']['server'] = \
                        {'processor_ids': server_cpus,
                         'bitmask': "0x%04x" % _get_bitmask(server_cpus),
                         'processor_list': str(sorted(server_cpus)).strip('[]').replace(' ', '')}

    def get_dependencies(self):
        return ['encryption-key',
                'internal-model-2.0',
                'cloud-cplite-2.0']
