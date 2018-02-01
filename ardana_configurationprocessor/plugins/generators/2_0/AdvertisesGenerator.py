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
import logging
import logging.config


from ardana_configurationprocessor.cp.model.CPLogging import \
    CPLogging as KenLog
from ardana_configurationprocessor.cp.model.GeneratorPlugin \
    import GeneratorPlugin
from ardana_configurationprocessor.cp.model.v2_0.CloudModel \
    import CloudModel


LOG = logging.getLogger(__name__)


class AdvertisesGenerator(GeneratorPlugin):
    def __init__(self, instructions, models, controllers):
        super(AdvertisesGenerator, self).__init__(
            2.0, instructions, models, controllers,
            'advertises-generator-2.0')
        LOG.info('%s()' % KenLog.fcn())

    def generate(self):
        LOG.info('%s()' % KenLog.fcn())

        self._action = KenLog.fcn()
        cloud_internal = CloudModel.internal(self._models['CloudModel'])

        components = CloudModel.get(cloud_internal, 'components', [])
        # If we have an error in an earlier generator we may not have
        # components in the internal model
        if not components:
            return

        components_by_mnemonic = CloudModel.get(cloud_internal, 'components_by_mnemonic')
        control_planes = CloudModel.get(cloud_internal, 'control-planes')

        # Resolve the service level consumes for all control planes before we
        # do the component level consumes - as a component may need to find
        # the service relationship in a parent control plane
        #
        for cp_name, cp in control_planes.iteritems():
            for component_name, endpoints in cp.get('advertises', {}).iteritems():

                component = components[component_name]
                for adv_to in component.get('advertises-to-services', []):

                    adv_to_name = adv_to['service-name']
                    if adv_to_name in components:
                        adv_to_mnemonic = components[adv_to_name]['mnemonic']
                    else:
                        # We have some cases where a service advertises to a dummy
                        # component
                        if adv_to_name not in components_by_mnemonic:
                            continue
                        adv_to_mnemonic = adv_to_name
                        adv_to_name = components_by_mnemonic[adv_to_mnemonic]['name']

                    for entry in adv_to.get('entries', []):
                        adv = {'service_name': entry['service-name'],
                               'service_type': entry['service-type'],
                               'service_description': entry.get('service-description'),
                               'regions': [],
                               'component_name': component_name,
                               'from_cp_name': cp_name}

                        for role in ['public', 'internal', 'admin']:
                            if role in endpoints:
                                adv[role + '_url'] = endpoints[role]['url'] + entry.get('url-suffix', '')

                        for region_name in sorted(cp.get('regions', {})):
                            region_services = cp['regions'][region_name]
                            service = component.get('service', 'foundation')
                            if service in region_services:
                                adv['regions'].append(region_name)

                        self._advertised(adv_to_name, cp, adv, control_planes)

    #
    # Add the advertised data to the service according to the control plane relationships
    #
    def _advertised(self, adv_to_name, cp, data, control_planes):

        if adv_to_name in cp['components']:
            if 'advertised' not in cp:
                cp['advertised'] = {}

            if adv_to_name not in cp['advertised']:
                cp['advertised'][adv_to_name] = []

            # Can only advetise the same service once per region
            valid = True
            if 'service_name' in data:

                region_list = {}

                for adv in (cp['advertised'][adv_to_name]):
                    if data['service_name'] == adv.get('service_name', ""):
                        for region in adv.get('regions', []):
                            region_list[region] = [adv.get('from_cp_name', '??')]

                for region in data.get('regions', []):
                    if region not in region_list:
                        region_list[region] = []
                    region_list[region].append(data.get('from_cp_name', '??'))

                for region_name, cp_list in region_list.iteritems():
                    if len(cp_list) > 1:
                        msg = ("Region '%s': service '%s' is included from more than one "
                               "control plane: %s" %
                               (region, data['service_name'], str(cp_list).strip('[]')))
                        self.add_error(msg)
                        valid = False

            if valid:
                cp['advertised'][adv_to_name].append(data)

        else:
            # Find the service we're advetirsing to in another control plane
            for uses in cp.get('uses', []):
                if ('any' in uses.get('service-components', []) or
                    'all' in uses.get('service-components', []) or
                        adv_to_name in uses.get('service-components', [])):
                    self._advertised(adv_to_name, control_planes[uses['from']],
                                     data, control_planes)

    def get_dependencies(self):
        return ['encryption-key',
                'internal-model-2.0',
                'cloud-cplite-2.0']
