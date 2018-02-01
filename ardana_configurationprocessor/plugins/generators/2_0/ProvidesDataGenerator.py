#
# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
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
import logging
import logging.config

from copy import deepcopy
from ardana_configurationprocessor.cp.model.CPLogging import \
    CPLogging as KenLog
from ardana_configurationprocessor.cp.model.GeneratorPlugin \
    import GeneratorPlugin
from ardana_configurationprocessor.cp.model.v2_0.CloudModel \
    import CloudModel


LOG = logging.getLogger(__name__)


class ProvidesDataGenerator(GeneratorPlugin):
    def __init__(self, instructions, models, controllers):
        super(ProvidesDataGenerator, self).__init__(
            2.0, instructions, models, controllers,
            'provides-data-generator-2.0')
        LOG.info('%s()' % KenLog.fcn())

    def generate(self):
        LOG.info('%s()' % KenLog.fcn())

        self._action = KenLog.fcn()
        cloud_internal = CloudModel.internal(self._models['CloudModel'])

        self.services = CloudModel.get(cloud_internal, 'services', [])
        control_planes = CloudModel.get(cloud_internal, 'control-planes')
        components = CloudModel.get(cloud_internal, 'components')

        # Resolve the service data relationships.
        for cp_name, cp in control_planes.iteritems():
            for comp_name, comp_data in cp.get('components', []).iteritems():
                provider = components[comp_name]
                provider_service = self.services.get(provider['service'], {})
                self._set_provided_data(provider, provider_service,
                                        comp_data, cp, control_planes)

    #
    # Build the set of service data relationships in the context of a
    # specific control plane
    #
    def _set_provided_data(self, provider, service, comp_data, cp, control_planes):

        for provider_data in provider.get('provides-data', []):

            for target in provider_data.get('to', []):

                scope = provider_data.get('scope', 'cloud')
                target_name = target['name']

                target_cp_name = self._get_target_cp(target_name, cp, control_planes,
                                                     scope)

                if target_cp_name:
                    target_cp = control_planes[target_cp_name]
                    if 'provided-data' not in target_cp['components'][target_name]:
                        target_cp['components'][target_name]['provided-data'] = []

                    if provider_data.get('per-cluster', False):
                        for cluster in comp_data['clusters']:
                            data = {'provided_by': {'name': provider['mnemonic'],
                                                    'cluster': cluster},
                                    'data': deepcopy(provider_data['data'])}
                            if provider['name'] in cp.get('service-vips', {}):
                                data['provided_by']['service_vip'] = cp['service-vips'][provider['name']][cluster]

                            # A pain but we have to search both clusters and resouces to find config data
                            for cp_cluster in cp.get('clusters', []):
                                if cp_cluster['name'] != cluster:
                                    continue
                                for config_data_service, config_data in cp_cluster.get('config-data', {}).iteritems():
                                    if config_data_service == service.get('mnemonic'):
                                        data['provided_by']['config_data'] = deepcopy(config_data)

                            for r_name, r in cp.get('resources', {}).iteritems():
                                if r_name != cluster:
                                    continue
                                for config_data_service, config_data in r.get('config-data', {}).iteritems():
                                    if config_data_service == service.get('mnemonic'):
                                        data['provided_by']['config_data'] = deepcopy(config_data)

                            target_cp['components'][target_name]['provided-data'].append(data)
                    else:
                        data = {'provided_by': {'name': provider['mnemonic']},
                                'data': deepcopy(provider_data['data'])}
                        target_cp['components'][target_name]['provided-data'].append(data)
                else:

                    # Not having the target may be optional
                    if target.get('optional', True):
                        continue

                    msg = ("%s: %s expects to provide-data to %s, but %s "
                           "is not in scope." %
                           (cp['name'], provider['name'], target_name,
                            target_name))
                    self.add_error(msg)
                    continue

    #
    # Find the endpoint of a service looking up through the
    # control planes
    #
    def _get_target_cp(self, target_component_name, cp, control_planes, scope):
        #
        # Get the endpoint for a component from the control plane
        # or its parent
        #
        target_cp = None

        if target_component_name in cp['components']:
            target_cp = cp['name']

        elif scope != 'control-plane':
            for uses in cp.get('uses', []):
                uses_from_cp = uses.get('service-components', [])
                if 'any' in uses_from_cp or 'all' in uses_from_cp or target_component_name in uses_from_cp:
                    target_cp = self._get_target_cp(target_component_name, control_planes[uses['from']],
                                                    control_planes, scope)

        return target_cp

    def get_dependencies(self):
        return ['encryption-key',
                'cloud-cplite-2.0',
                'configuration-data-generator-2.0']
