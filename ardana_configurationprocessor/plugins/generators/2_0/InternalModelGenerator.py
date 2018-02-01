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

from ardana_configurationprocessor.cp.model.v2_0.CloudModel \
    import CloudModel
from ardana_configurationprocessor.cp.model.v2_0.ServerGroup \
    import ServerGroup

from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog
from ardana_configurationprocessor.cp.model.GeneratorPlugin \
    import GeneratorPlugin


from copy import deepcopy

LOG = logging.getLogger(__name__)


class InternalModelGenerator(GeneratorPlugin):

    def __init__(self, instructions, models, controllers):
        super(InternalModelGenerator, self).__init__(
            2.0, instructions, models, controllers,
            'internal-model-2.0')

        LOG.info('%s()' % KenLog.fcn())

        self.cloud_desc = self._models['CloudDescription']['cloud']

    def generate(self):
        LOG.info('%s()' % KenLog.fcn())

        cloud_data = self._models['CloudDescription']['cloud']
        cloud_version = CloudModel.version(self._models['CloudModel'], self._version)
        cloud_internal = CloudModel.internal(self._models['CloudModel'])

        services = {}
        components = {}
        components_by_mnemonic = {}

        for service in CloudModel.get(cloud_version, 'services'):
            services[service['name']] = service

        for component in CloudModel.get(cloud_version, 'service-components'):
            components[component['name']] = component
            components_by_mnemonic[component['mnemonic']] = component

        control_planes = {}
        iface_models = {}
        disk_models = {}
        nic_mappings = {}
        nic_device_types = {}
        nic_device_families = {}
        server_roles = {}
        server_groups = {}
        bm_servers = []
        pass_through = {'global': {}, 'servers': {}}

        # Servers
        if 'servers' in cloud_version:
            bm_servers.extend(cloud_version['servers'])

        # Build a list of server addresses so we can
        # reserve them
        server_addresses = {}
        for s in bm_servers:
            server_addresses[s['ip-addr']] = s['id']

        # Control Planes
        for cp in CloudModel.get(cloud_version, 'control-planes'):
            control_planes[cp['name']] = dict(cp)

        # Network Groups
        network_groups = CloudModel.get(cloud_internal, 'network-groups')

        # Networks
        networks = CloudModel.get(cloud_internal, 'networks')

        # Interface Models
        for iface in CloudModel.get(cloud_version, 'interface-models'):
            iface_models[iface['name']] = iface

        # Disk Models
        for disk_model in CloudModel.get(cloud_version, 'disk-models'):
            disk_models[disk_model['name']] = disk_model

        # NIC Device Families
        for nic_family in CloudModel.get(cloud_version, 'nic-device-families', []):
            nic_device_families[nic_family['name']] = nic_family

        # NIC Device Types
        for nic_dev in CloudModel.get(cloud_version, 'nic-device-types', []):
            nic_device_types[nic_dev['name']] = nic_dev
            nic_device_types[nic_dev['name']]['family_data'] = \
                nic_device_families[nic_dev['family']]

        # NIC Mapping
        for nic_map in CloudModel.get(cloud_version, 'nic-mappings', []):
            for port in nic_map.get('physical-ports', []):
                # Add in any data from the NIC device type
                if 'nic-device-type' in port:
                    port['nic-device-type'] = nic_device_types[port['nic-device-type']]
            nic_mappings[nic_map['name']] = nic_map

        # Server Roles
        for role in CloudModel.get(cloud_version, 'server-roles'):
            server_roles[role['name']] = role

        # Server Groups
        for group in CloudModel.get(cloud_version, 'server-groups', []):
            server_groups[group['name']] = group

        # Pass Through
        pt_data = CloudModel.get(cloud_version, 'pass-through', [])

        ####################################
        #
        # End of reading input data
        #
        ###################################

        # Combine pass through data which maybe in multiple
        # input files into a single dict structured by server and
        # control plane.
        for pt in pt_data:
            for key in pt.get('global', {}):
                if key in pass_through['global']:
                    msg = ("Key %s is defined more than once in global "
                           "pass-through data" % (key, ))
                    self.add_error(msg)

                pass_through['global'][key] = pt['global'][key]

            for server in pt.get('servers', []):
                if server['id'] not in pass_through['servers']:
                    pass_through['servers'][server['id']] = {}
                server_data = pass_through['servers'][server['id']]

                for key in server.get('data'):
                    if key in server_data:
                        msg = ("Key %s is defined more than once for server %s "
                               "in pass-through data" % (key, server['id']))
                        self.add_error(msg)
                    server_data[key] = server['data'][key]

        # Add proxy relationships
        for component_name, component in components.iteritems():
            for container_data in component.get('has-container', []):
                container_name = container_data['service-name']
                if container_name in components_by_mnemonic:
                    container_name = components_by_mnemonic[container_name]['name']
                if 'contains' not in components[container_name]:
                    components[container_name]['contains'] = {}
                components[container_name]['contains'][component_name] = {
                    'name': component['mnemonic'].replace('-', '_'),
                    'data': container_data
                }
                component['container-name'] = container_name

        # Can't do any more if we have errors in the network groups
        if self._errors:
            return

        # Create a default interface-model for any roles that don't define one
        default_net_iface = [{'name': 'default_iface',
                              'network-groups': [x for x in network_groups],
                              'ports': ['ethX']}]

        # Create a deafult server group to hold any networks and servers not
        # specificially assigned
        default_server_group = {}

        # Fix up relationships between server groups
        for group_name, group in server_groups.iteritems():
            for child in ServerGroup.server_groups(group):
                ServerGroup.add_group(group, server_groups[child])

        # Map networks to net_groups in server groups
        networks_in_a_group = set()
        for group_name, group in server_groups.iteritems():
            for net in ServerGroup.networks(group):
                ServerGroup.add_network(group, net, networks[net]['network-group'])
                networks_in_a_group.add(net)

        # Add any unassinged networks to the default server group
        for net_name, net in networks.iteritems():
            if net_name not in networks_in_a_group and not net.get('neutron_network', False):
                if server_groups:
                    self.add_warning("Network %s is not listed in a server "
                                     "group." % (net_name))
                ServerGroup.add_network(default_server_group, net_name,
                                        net['network-group'])

        # Establish the min and max size of each cluster and resource group
        for cp_name, cp in control_planes.iteritems():
            for cluster in cp.get('clusters', []):
                if 'member-count' in cluster:
                    cluster['min-count'] = cluster['member-count']
                    cluster['max-count'] = cluster['member-count']
                else:
                    cluster['min-count'] = cluster.get('min-count', 1)

            for rgroup in cp.get('resources', []):
                if 'member-count' in rgroup:
                    rgroup['min-count'] = rgroup['member-count']
                    rgroup['max-count'] = rgroup['member-count']
                else:
                    rgroup['min-count'] = rgroup.get('min-count', 0)

        # Create a list of servers with the network details for each resolved
        servers = []
        for s in bm_servers:

            server_role = server_roles[s['role']]

            # resolve the networking

            # Find the interface model, and take a copy of the interfaces, as we may only use part of the model
            # If there is no interface-model in the server role then all networks map to the existing NIC
            fcoe_interfaces = []
            if 'interface-model' in server_role:
                iface_model = iface_models[server_role['interface-model']]
                server_interfaces = deepcopy(iface_model['network-interfaces'])
                if 'fcoe-interfaces' in iface_model:
                    fcoe_interfaces = iface_model['fcoe-interfaces']
            else:
                server_interfaces = deepcopy(default_net_iface)

            # Find the disk model, and take a copy
            if 'disk-model' in server_role:
                disk_model = deepcopy(disk_models[server_role['disk-model']])
            else:
                disk_model = {'drives': {}}

            # Translate network groups to the specific networks for this server
            # Note:  At this stage we have all possible networks groups defined
            #        by the interface model.  We will reduce that to just those
            #        needed once we have assinged the server to a particular role
            for iface in server_interfaces:
                iface['networks'] = {}
                iface_net_groups = (iface.get('network-groups', []) +
                                    iface.get('forced-network-groups', []) +
                                    iface.get('passthrough-network-groups', []))
                for net_group in iface_net_groups:
                    # Find network in the group for this server
                    if 'server-group' in s:
                        server_group = server_groups[s['server-group']]
                    else:
                        server_group = None
                    net_name = ServerGroup.find_network(server_group, net_group,
                                                        default_server_group)
                    if net_name:
                        network = networks[net_name]
                        iface['networks'][network['name']] = deepcopy(network)
                        if net_group in iface.get('forced-network-groups', []):
                            iface['networks'][network['name']]['forced'] = True
                        else:
                            iface['networks'][network['name']]['forced'] = False

                        # Marked the network as passthrough if its network group is
                        # in the list of passthought network groups.
                        if net_group not in iface.get('passthrough-network-groups', []):
                            iface['networks'][network['name']]['passthrough'] = False
                            iface['networks'][network['name']]['passthrough-only'] = False
                        else:
                            iface['networks'][network['name']]['passthrough'] = True

                            # Mark the network as passthrough-only if its network group is
                            # not listed in network-groups or forced-network-groups
                            if net_group not in (iface.get('network-groups', []) +
                                                 iface.get('forced-network-groups', [])):
                                iface['networks'][network['name']]['passthrough-only'] = True
                            else:
                                iface['networks'][network['name']]['passthrough-only'] = False

            server = {'id': s['id'],
                      'hostname': s.get('hostname', None),
                      'hypervisor-id': s.get('hypervisor-id', None),
                      'role': s['role'],
                      'server_group': s.get('server-group'),
                      'rack': s.get('rack'),
                      'addr': s['ip-addr'],
                      'if-model': server_role.get('interface-model', 'default'),
                      'disk-model': disk_model,
                      'interfaces': server_interfaces,
                      'fcoe_interfaces': fcoe_interfaces,
                      'nic_map': nic_mappings.get(s.get('nic-mapping', 'none')),
                      'ansible_options': s.get('ansible-options'),
                      'state': None,
                      'vm-factory': s.get('vm-factory', False),
                      'port-groups': s.get('port-groups', []),
                      'previous_config': {}}

            servers.append(server)

            # Add servers to ServerGroups
            if 'server-group' in s:
                sgrp = server_groups[s['server-group']]
                ServerGroup.add_server(sgrp, server)
                server['server-group-list'] = ServerGroup.get_group_list(sgrp)
            else:
                # If there are server groups defined it would be odd to have
                # a server which isn't a member of a group
                if server_groups:
                    self.add_warning("Server %s is not a member of a server "
                                     "group." % (s['ip-addr']))
                ServerGroup.add_server(default_server_group, server)
                server['server-group-list'] = []

        # Roles for a cluster/resource can be either a string or a list, so change to
        # always be a list
        for cp_name, cp in control_planes.iteritems():
            for cluster in cp['clusters']:
                if isinstance(cluster['server-role'], basestring):
                    cluster['server-role'] = [cluster['server-role']]

            for r in cp.get('resources', []):
                if isinstance(r['server-role'], basestring):
                    r['server-role'] = [r['server-role']]

        # Add a list of all services to each Control Plane
        for cp_name, cp in control_planes.iteritems():
            cp['services'] = {}
            for cluster in cp['clusters']:
                cluster['services'] = {}
                for comp_name in cluster['service-components']:
                    service_name = components[comp_name]['service']
                    if service_name not in cluster['services']:
                        cluster['services'][service_name] = []
                    cluster['services'][service_name].append(comp_name)
                    cp['services'][service_name] = {}

            for r in cp.get('resources', []):
                r['services'] = {}
                for comp_name in r['service-components']:
                    service_name = components[comp_name]['service']
                    if service_name not in r['services']:
                        r['services'][service_name] = []
                    r['services'][service_name].append(comp_name)
                    cp['services'][service_name] = {}

        ntp_servers = cloud_data.get('ntp-servers', [])
        dns_settings = cloud_data.get('dns-settings', {})
        smtp_settings = cloud_data.get('smtp-settings', {})
        firewall_settings = cloud_data.get('firewall-settings', {})

        CloudModel.put(cloud_internal, 'control-planes', control_planes)
        CloudModel.put(cloud_internal, 'networks', networks)
        CloudModel.put(cloud_internal, 'servers', servers)
        CloudModel.put(cloud_internal, 'server-groups', server_groups)
        CloudModel.put(cloud_internal, 'default-server-group', default_server_group)
        CloudModel.put(cloud_internal, 'services', services)
        CloudModel.put(cloud_internal, 'components', components)
        CloudModel.put(cloud_internal, 'components_by_mnemonic', components_by_mnemonic)
        CloudModel.put(cloud_internal, 'ntp_servers', ntp_servers)
        CloudModel.put(cloud_internal, 'dns_settings', dns_settings)
        CloudModel.put(cloud_internal, 'smtp_settings', smtp_settings)
        CloudModel.put(cloud_internal, 'firewall_settings', firewall_settings)
        CloudModel.put(cloud_internal, 'pass_through', pass_through)
        CloudModel.put(cloud_internal, 'iface_models', iface_models)
        CloudModel.put(cloud_internal, 'disk_models', disk_models)
        CloudModel.put(cloud_internal, 'nic_mappings', nic_mappings)
        CloudModel.put(cloud_internal, 'server_roles', server_roles)

    def get_dependencies(self):
        return ['encryption-key',
                'network-generator-2.0']
