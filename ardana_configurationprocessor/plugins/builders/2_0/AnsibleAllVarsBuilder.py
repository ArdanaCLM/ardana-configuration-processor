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
from ardana_configurationprocessor.cp.model.v2_0.CloudDescription \
    import CloudDescription

from ardana_configurationprocessor.cp.model.BuilderPlugin \
    import BuilderPlugin
from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog
from ardana_configurationprocessor.cp.model.BuilderPlugin \
    import ArtifactMode
from ardana_configurationprocessor.cp.lib.DataTransformer \
    import DataTransformer

LOG = logging.getLogger(__name__)


class AnsibleAllVarsBuilder(BuilderPlugin):
    def __init__(self, instructions, models, controllers):
        super(AnsibleAllVarsBuilder, self).__init__(
            2.0, instructions, models, controllers,
            'ansible-all-vars-2.0')
        LOG.info('%s()' % KenLog.fcn())
        self.cloud_desc = self._models['CloudDescription']['cloud']
        self._file_path = ArdanaPaths.get_output_path(self._instructions, self.cloud_desc)
        self._file_path = os.path.join(self._file_path, 'ansible')

        self._cloud_model = self._models['CloudModel']
        self._cloud_version = CloudModel.version(self._cloud_model, self._version)
        self._cloud_internal = CloudModel.internal(self._cloud_model)

        ArdanaPaths.make_path(self._file_path)

    def build(self):
        LOG.info('%s()' % KenLog.fcn())

        filename = "%s/group_vars/all" % (self._file_path)
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))
        self.add_artifact(filename, ArtifactMode.CREATED)

        global_vars = {'global': {'ansible_vars': [],
                                  'all_servers': []}}
        control_planes = CloudModel.get(self._cloud_internal, 'control-planes')
        components = CloudModel.get(self._cloud_internal, 'components')
        service_view = CloudModel.get(self._cloud_internal, 'service_view')
        service_view = service_view['by_region']
        ring_specifications = CloudModel.get(self._cloud_internal,
                                             'ring-specifications', [])
        pass_through = CloudModel.get(self._cloud_internal, 'pass_through')
        cloud_name = CloudDescription.get_cloud_name(self.cloud_desc)
        ntp_servers = self.cloud_desc.get('ntp-servers', {})
        dns_settings = self.cloud_desc.get('dns-settings', {})

        if ntp_servers:
            global_vars['global']['ntp_servers'] = ntp_servers

        if dns_settings:
            global_vars['global']['dns_nameservers'] = dns_settings['nameservers']

        global_vars['global']['control_planes'] = []
        for cp_name in control_planes:
            global_vars['global']['control_planes'].append("%s-%s" % (cloud_name, cp_name))

        #
        # Add a list of all vips
        #
        vips = set()
        vip_addresses = set()
        for cp_name, cp in control_planes.iteritems():
            for ep_name, ep_data in cp['endpoints'].iteritems():
                for role, role_data in ep_data.iteritems():
                    if role not in ['internal', 'admin']:
                        continue
                    for data in role_data:
                        access = data.get('access', {})
                        if 'hostname' in access:
                            vips.add(data['access']['hostname'])
                            vip_addresses.add(data['access']['address'])
                        for host_data in access.get('members', []):
                            vips.add(host_data['hostname'])

        if ring_specifications:
            ring_specifications = DataTransformer(
                ring_specifications).all_output('-', '_')
            global_vars['global']['all_ring_specifications'] =\
                ring_specifications
        else:
            global_vars['global']['all_ring_specifications'] = []

        if pass_through:
            global_vars['global']['pass_through'] = pass_through['global']

        global_vars['global']['vips'] = sorted(vips)
        global_vars['global']['vip_addresses'] = sorted(vip_addresses)

        global_vars['topology'] = {'cloud_name': cloud_name,
                                   'control_planes': []}
        for cp_name in sorted(service_view):
            cp = service_view[cp_name]
            cp_data = {'name': cp_name,
                       'services': []}
            for service_name in sorted(cp):
                service_components = cp[service_name]
                service_data = {'name': service_name,
                                'components': []}

                for component_name in sorted(service_components):
                    hosts = service_components[component_name]
                    component_data = {'name': component_name,
                                      'hosts': sorted(hosts)}
                    service_data['components'].append(component_data)

                cp_data['services'].append(service_data)

            global_vars['topology']['control_planes'].append(cp_data)

        #
        # Add region and service topologies
        #
        rt = global_vars['region_topology'] = CloudModel.get(self._cloud_internal, 'region-topology')
        global_vars['service_topology'] = CloudModel.get(self._cloud_internal, 'service-topology')

        #
        # BUG 4227: provide a view onto the region topology suitable for use by Ansible to generate
        # multiple slices for different Tempest configurations
        #

        region_by_cp_by_service = set()
        for region_name, region in rt['regions'].iteritems():
            for cp_name, control_plane in region['control_planes'].iteritems():
                for service_name, scs in control_plane['services'].iteritems():
                    region_by_cp_by_service.update((region_name, cp_name, service_name, sc)
                                                   for sc in scs)

        global_vars['region_by_cp_by_service'] = [{'region': r,
                                                   'control_plane': c,
                                                   'service': s,
                                                   'service_component': sc,
                                                   }
                                                  for r, c, s, sc in sorted(region_by_cp_by_service)]

        #
        # Add Cert data
        #
        global_vars['cert_data'] = {'hosts': [],
                                    'services': {}}
        for cp_name, cp in control_planes.iteritems():
            cp_cert_data = cp['cert-data']
            for host_cert in cp_cert_data['hosts']:
                global_vars['cert_data']['hosts'].append(host_cert)

            for component_name, certs in cp_cert_data['services'].iteritems():
                mnemonic = components[component_name]['mnemonic'].replace('-', '_')
                if mnemonic not in global_vars['cert_data']['services']:
                    global_vars['cert_data']['services'][mnemonic] = []
                global_vars['cert_data']['services'][mnemonic].extend(certs)

        global_vars['cp_tempest_data'] = self._get_tempest_vars(control_planes)
        global_vars['cp_tempest_test_plans'] = self._get_tempest_test_plans(control_planes)

        global_vars['deployer_media_legacy_layout'] = False
        with open(filename, 'w') as fp:
            yaml.dump(global_vars, fp, default_flow_style=False, indent=4)

    #
    # Extract the data specifically needed by tempest.
    #
    def _get_tempest_vars(self, control_planes):
        result = {}

        def _get_external_nets(config_data, nets):
            for service, data in config_data.iteritems():
                if 'neutron_external_networks' in data:
                    for net in data['neutron_external_networks']:
                        if net['name'] not in nets:
                            nets.append(net['name'])
            return nets

        def _get_flat_nets(config_data, nets):
            for service, data in config_data.iteritems():
                if 'neutron_provider_networks' in data:
                    for net in data['neutron_provider_networks']:
                        for provider in net.get('provider', []):
                            if provider['network_type'] == 'flat':
                                if net['name'] not in nets:
                                    nets.append(net['name'])
            return nets

        # Seed the result structure with all regions
        for cp_name, cp in control_planes.iteritems():
            for region_name in cp.get('regions', []):
                result[region_name] = {}

        for cp_name, cp in control_planes.iteritems():
            for advertised_to, endpoints in cp.get('advertised', {}).iteritems():
                for endpoint in endpoints:
                    if 'public_url' in endpoint:
                        for region_name in endpoint.get('regions', []):
                            if 'public_endpoints' not in result[region_name]:
                                result[region_name]['public_endpoints'] = {}
                            url = endpoint['public_url'].split(':')
                            if len(url) > 2:
                                port = url[2].split('/')[0]
                            else:
                                port = ""
                            result[region_name]['public_endpoints'][endpoint['service_name']] =\
                                ('%s:%s:%s' % (url[0], url[1], port))

            external_nets = []
            flat_nets = []
            for cluster in cp.get('clusters', []):
                _get_external_nets(cluster.get('config-data', {}), external_nets)
                _get_flat_nets(cluster.get('config-data', {}), flat_nets)
            for res_name, res in cp.get('resources', {}).iteritems():
                _get_external_nets(res.get('config-data', {}), external_nets)
                _get_flat_nets(cluster.get('config-data', {}), flat_nets)
            if external_nets:
                for region_name in cp.get('regions', []):
                    if 'external_networks' not in result[region_name]:
                        result[region_name]['external_networks'] = external_nets
                    else:
                        result[region_name]['external_networks'].extend(external_nets)
            if flat_nets:
                for region_name in cp.get('regions', []):
                    if 'flat_networks' not in result[region_name]:
                        result[region_name]['flat_networks'] = flat_nets
                    else:
                        result[region_name]['flat_networks'].extend(flat_nets)

        # remove any empty regions
        for region_name in sorted(result):
            if not result[region_name]:
                del result[region_name]

        return result

    def _get_tempest_test_plans(self, control_planes):

        test_plans = {'by_region': [],
                      'by_control_plane': []}

        region_services = {}
        cp_testable = {}
        # Build a list of all services in each region, and the list
        # of all testable services in each control plane. Do this from
        # the advertised list as we're only looking for services with an
        # endpoint in keystone (i.e we don't want to know about "monasca"
        # in a contorl plane if that only includes the monasca_agent)
        for cp_name, cp in control_planes.iteritems():
            for advertised_to, endpoints in cp.get('advertised', {}).iteritems():
                for endpoint in endpoints:
                    if endpoint['from_cp_name'] not in cp_testable:
                        cp_testable[endpoint['from_cp_name']] = {}
                    for region_name in endpoint.get('regions', []):
                        if region_name not in cp_testable[endpoint['from_cp_name']]:
                            cp_testable[endpoint['from_cp_name']][region_name] = []
                        cp_testable[endpoint['from_cp_name']][region_name].append(endpoint['service_name'])

                        if region_name not in region_services:
                            region_services[region_name] = []
                        region_services[region_name].append(endpoint['service_name'])

        # Build the per region test plans - always test all services in the region
        for region_name, service_list in region_services.iteritems():
            test_plan = {'region': region_name,
                         'services': {}}
            for service_name in service_list:
                test_plan['services'][service_name] = True

            test_plans['by_region'].append(test_plan)

        # Build the per control plane test plans.   There will be a test plan per
        # region that only marks a services as testable if:
        #   - it is in the control plane
        #   - it is not included in any other test plan for this control plane
        #     (so we don't test the same services more than once per control plane)
        for cp_name, cp_regions in cp_testable.iteritems():
            tested_services = set()

            region_size = []
            for region_name, cp_region_services in cp_regions.iteritems():
                region_size.append({'name': region_name, 'size': len(cp_region_services)})

            # Sort by the number of services from the region, so we test the most we
            # can from the same control plane together.  In most cases this will mean
            # that we only need one test plan per control plane
            for cp_region_info in sorted(region_size, key=lambda x: x['size'], reverse=True):

                region_name = cp_region_info['name']
                cp_region_services = cp_regions[region_name]

                test_plan = {'control_plane': cp_name,
                             'region': region_name,
                             'services': {}}

                testable = False
                for service_name in cp_region_services:
                    if service_name not in tested_services:
                        test_plan['services'][service_name] = True
                        testable = True
                        tested_services.add(service_name)

                # Skip this region if there's noting to test
                if not testable:
                    continue

                # Add any other services for the region
                for service_name in region_services[region_name]:
                    if service_name not in test_plan['services']:
                        test_plan['services'][service_name] = False

                test_plans['by_control_plane'].append(test_plan)

        return test_plans

    def get_dependencies(self):
        return ['persistent-state-2.0']
