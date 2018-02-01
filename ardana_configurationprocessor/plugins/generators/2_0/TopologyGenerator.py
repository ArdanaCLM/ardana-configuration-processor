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


class TopologyGenerator(GeneratorPlugin):
    def __init__(self, instructions, models, controllers):
        super(TopologyGenerator, self).__init__(
            2.0, instructions, models, controllers,
            'topology-generator-2.0')
        LOG.info('%s()' % KenLog.fcn())

    def generate(self):
        LOG.info('%s()' % KenLog.fcn())

        self._action = KenLog.fcn()
        cloud_internal = CloudModel.internal(self._models['CloudModel'])

        control_planes = CloudModel.get(cloud_internal, 'control-planes')
        networks = CloudModel.get(cloud_internal, 'networks')
        network_groups = CloudModel.get(cloud_internal, 'network-groups')
        components = CloudModel.get(cloud_internal, 'components')

        cp_topology = self._generate_cp_topology(control_planes, components)
        CloudModel.put(cloud_internal, 'cp-topology',
                       cp_topology)

        CloudModel.put(cloud_internal, 'region-topology',
                       self._generate_region_topology(control_planes))

        CloudModel.put(cloud_internal, 'service-topology',
                       self._generate_service_topology(cp_topology))

        CloudModel.put(cloud_internal, 'network-topology',
                       self._generate_network_topology(network_groups, networks, control_planes))

    #
    # Generate Physical Topology:
    #
    #  Control-planes:
    #    Clusters:
    #      Services:
    #        Components
    #      Hosts
    #    Resources:
    #      Services:
    #        Components
    #      Hosts
    #
    def _generate_cp_topology(self, control_planes, components):

        topology = {'control_planes': {}}

        def _build_data(services, regions, servers):
            cluster_topology = {'services': {},
                                'failure_zones': {}}

            for service, components in services.iteritems():
                cluster_topology['services'][service] = {'components': components,
                                                         'regions': []}
                for region_name in sorted(regions):
                    region_services = regions[region_name]
                    if service in region_services:
                        cluster_topology['services'][service]['regions'].append(region_name)

            zones = cluster_topology['failure_zones']
            for server in servers:
                zone = server.get('failure-zone', 'default')
                if zone not in zones:
                    zones[zone] = []
                zones[zone].append(server['hostname'])

            return cluster_topology

        for cp_name, cp in control_planes.iteritems():

            cp_topology = {'clusters': {},
                           'resources': {}}

            for cluster in cp.get('clusters'):

                cp_topology['clusters'][cluster['name']] = \
                    _build_data(cluster['services'], cp['regions'], cluster.get('servers'))

            for r_name, r in cp.get('resources', {}).iteritems():
                cp_topology['resources'][r_name] = \
                    _build_data(r['services'], cp['regions'], r.get('servers'))

            # Build a summary of the LB configurtaion
            lb_info = {}
            for lb in cp['load-balancers']:
                lb_info[lb['name']] = {'provider': lb['provider'],
                                       'roles': lb['roles'],
                                       'external-name': lb.get('external-name', ''),
                                       'cert-file': lb.get('cert-file', ''),
                                       'network-group': lb['network-group'],
                                       'services': {}}

            for provider, comp_data in cp['load-balancer-config'].iteritems():
                for comp_name, vip_data in comp_data.iteritems():
                    service = components[comp_name]['service']
                    for net_data in vip_data['networks']:
                        lb_info[net_data['lb-name']]['address'] = net_data['ip-address']
                        lb_info[net_data['lb-name']]['network'] = net_data['network']
                        comp_info = {'aliases': net_data['aliases'],
                                     'port': net_data['vip-port'],
                                     'hosts': [],
                                     'vip-tls': net_data['vip-tls'],
                                     'host-tls': vip_data['host-tls']}
                        for h in vip_data['hosts']:
                            comp_info['hosts'].append(h['hostname'])
                        if service not in lb_info[net_data['lb-name']]['services']:
                            lb_info[net_data['lb-name']]['services'][service] = {}
                        lb_info[net_data['lb-name']]['services'][service][comp_name] = comp_info

            cp_topology['load-balancers'] = lb_info

            topology['control_planes'][cp_name] = cp_topology

        return topology

    #
    # Generate Region Topology
    #
    #   Regions:
    #     Control Planes:
    #       Services:
    #
    def _generate_region_topology(self, control_planes):

        topology = {'regions': {}}

        def _add_services(services, region_services, cp_data):
            for service_name, components in services.iteritems():
                if service_name in region_services:
                    for c in components:
                        cp_data['services'][service_name].add(c)

        for cp_name, cp in control_planes.iteritems():

            for region_name, region_services in cp.get('regions', {}).iteritems():
                if region_name not in topology['regions']:
                    topology['regions'][region_name] = {'control_planes': {}}

                cp_data = {'services': {}}

                for service in region_services:
                    cp_data['services'][service] = set()

                for cluster in cp.get('clusters'):
                    _add_services(cluster.get('services'), region_services, cp_data)

                for r_name, r_group in cp.get('resources', {}).iteritems():
                    _add_services(r_group.get('services'), region_services, cp_data)

                for service in region_services:
                    cp_data['services'][service] = list(cp_data['services'][service])

                topology['regions'][region_name]['control_planes'][cp_name] = cp_data

        return topology

    #
    # Generate Service Topology
    #
    #   Services:
    #      Components:
    #         Control Planes:
    #            Clusters:
    #            Resources:
    #            Regions:
    #
    def _generate_service_topology(self, physical_topology):

        topology = {'services': {}}

        def _add_services(services, cp_name, zones, cluster_name=None, resource_name=None):
            for service_name, service_data in services.iteritems():
                if service_name not in topology['services']:
                    topology['services'][service_name] = {'components': {}}
                service_components = topology['services'][service_name]['components']

                for component_name in service_data['components']:
                    if component_name not in service_components:
                        service_components[component_name] = {'control_planes': {}}

                    if cp_name not in service_components[component_name]['control_planes']:
                        service_components[component_name]['control_planes'][cp_name] = {}
                    cp_info = service_components[component_name]['control_planes'][cp_name]

                    if 'regions' not in cp_info:
                        cp_info['regions'] = [r for r in sorted(service_data['regions'])]

                    host_list = []
                    for zone_name, hosts in zones.iteritems():
                        host_list.extend(hosts)
                    if cluster_name:
                        if 'clusters' not in cp_info:
                            cp_info['clusters'] = {}
                        cp_info['clusters'][cluster_name] = host_list
                    else:
                        if 'resources' not in cp_info:
                            cp_info['resources'] = {}
                        cp_info['resources'][resource_name] = host_list

        for cp_name, cp_data in physical_topology['control_planes'].iteritems():
            for cluster_name, cluster_data in cp_data['clusters'].iteritems():
                _add_services(cluster_data['services'], cp_name,
                              cluster_data['failure_zones'], cluster_name=cluster_name)

            for r_name, r_data in cp_data.get('resources', {}).iteritems():
                _add_services(r_data['services'], cp_name,
                              r_data['failure_zones'], resource_name=r_name)

        return topology

    #
    # Generate Network Topology
    #
    # Network Groups:
    #   Networks:
    #     Control Planes:
    #        Clusters:
    #        Resources:
    #        VIPs:
    #
    def _generate_network_topology(self, network_groups, networks, control_planes):

        topology = {'network_groups': {}}

        def _add_server(server, net, vips, cp_info, group_name, group_type):
            if group_type not in cp_info:
                cp_info[group_type] = {}
            if group_name not in cp_info[group_type]:
                cp_info[group_type][group_name] = {'servers': {}}
            cp_info[group_type][group_name]['servers'][server['name']] = net.get('addr')

            for vip_service, vip_addrs in vips.iteritems():
                if vip_service not in server['components']:
                    continue
                if 'vips' not in cp_info[group_type][group_name]:
                    cp_info[group_type][group_name]['vips'] = vip_addrs

        def _add_servers(cp_name, vips, servers, cluster_name=None, resource_name=None):

            for server in servers:
                for iface_name, iface_data in server['interfaces'].iteritems():
                    for net_name, net in iface_data.get('networks', {}).iteritems():
                        net_group = net['network-group']
                        if cp_name not in topology['network_groups'][net_group][net_name]['control_planes']:
                            topology['network_groups'][net_group][net_name]['control_planes'][cp_name] = {}

                        cp_info = topology['network_groups'][net_group][net_name]['control_planes'][cp_name]

                        if cluster_name:
                            _add_server(server, net, vips.get(net_name, {}), cp_info, cluster_name, 'clusters')
                        else:
                            _add_server(server, net, vips.get(net_name, {}), cp_info, resource_name, 'resources')

        def _add_service_ips(cp_name, service_ips, cluster_name=None, resource_name=None):

            for service, net in service_ips.iteritems():
                for net_name, net_data in net.iteritems():
                    net_group = networks[net_name]['network-group']
                    cp_info = topology['network_groups'][net_group][net_name]['control_planes'][cp_name]
                    if cluster_name:
                        cp_info = cp_info['clusters'][cluster_name]
                    else:
                        cp_info = cp_info['resources'][resource_name]

                    service_ip_info = {'hosts': {}}

                    for host in net_data.get('hosts', []):
                        service_ip_info['hosts'][host['name']] = host['ip_address']

                    if 'cluster-ip' in net_data:
                        service_ip_info['vip'] = net_data['cluster-ip']['ip_address']

                    if service_ip_info['hosts']:
                        if 'service_ips' not in cp_info:
                            cp_info['service_ips'] = {}
                        cp_info['service_ips'][service] = service_ip_info

        for net_group_name, net_group_data in network_groups.iteritems():
            topology['network_groups'][net_group_name] = {}
            for net in net_group_data.get('networks', []):
                topology['network_groups'][net_group_name][net['name']] = {'control_planes': {}}

        for cp_name, cp in control_planes.iteritems():

            vips = {}
            for lb_service, lb_data in cp.get('load-balancer-config', {}).iteritems():
                for service, service_data in lb_data.iteritems():
                    for vip_net in service_data['networks']:
                        net_name = vip_net['network']
                        vip_addr = vip_net['ip-address']
                        if net_name not in vips:
                            vips[net_name] = {}
                        if lb_service not in vips[net_name]:
                            vips[net_name][lb_service] = {}
                        if vip_addr not in vips[net_name][lb_service]:
                            vips[net_name][lb_service][vip_addr] = vip_net['lb-name']

            for cluster in cp.get('clusters'):
                _add_servers(cp_name, vips, cluster.get('servers'), cluster_name=cluster['name'])
                _add_service_ips(cp_name, cluster.get('service-ips', {}), cluster_name=cluster['name'])

            for r_name, r in cp.get('resources', {}).iteritems():
                _add_servers(cp_name, vips, r.get('servers'), resource_name=r_name)
                _add_service_ips(cp_name, r.get('service-ips', {}), resource_name=r_name)

        return topology

    def get_dependencies(self):
        return ['encryption-key',
                'internal-model-2.0',
                'cloud-cplite-2.0']
