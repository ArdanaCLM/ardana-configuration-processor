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
import netaddr
import os
import logging
import logging.config
import yaml
from copy import deepcopy

from ardana_configurationprocessor.cp.model.v2_0.ArdanaPaths \
    import ArdanaPaths
from ardana_configurationprocessor.cp.model.v2_0.CloudDescription \
    import CloudDescription
from ardana_configurationprocessor.cp.model.v2_0.CloudModel \
    import CloudModel

from ardana_configurationprocessor.cp.model.BuilderPlugin \
    import BuilderPlugin
from ardana_configurationprocessor.cp.model.BuilderPlugin \
    import ArtifactMode
from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog
from ardana_configurationprocessor.cp.lib.DataTransformer \
    import DataTransformer


LOG = logging.getLogger(__name__)


class AnsHostVarsBuilder(BuilderPlugin):
    def __init__(self, instructions, models, controllers):
        super(AnsHostVarsBuilder, self).__init__(
            2.0, instructions, models, controllers,
            'ans-host-vars-2.0')
        LOG.info('%s()' % KenLog.fcn())
        self.cloud_desc = self._models['CloudDescription']['cloud']
        self._file_path = ArdanaPaths.get_output_path(self._instructions, self.cloud_desc)
        self._file_path = os.path.join(self._file_path, 'ansible')

        self._cloud_model = self._models['CloudModel']
        self._cloud_version = CloudModel.version(self._cloud_model, self._version)
        self._cloud_internal = CloudModel.internal(self._cloud_model)

        self._cloud_firewall = {}

    def build(self):
        LOG.info('%s()' % KenLog.fcn())
        cloud_name = CloudDescription.get_cloud_name(self.cloud_desc)
        ntp_servers = CloudModel.get(self._cloud_internal, 'ntp_servers')
        dns_settings = CloudModel.get(self._cloud_internal, 'dns_settings')
        smtp_settings = CloudModel.get(self._cloud_internal, 'smtp_settings')
        control_planes = CloudModel.get(self._cloud_internal, 'control-planes')
        net_group_firewall = CloudModel.get(self._cloud_internal, 'net-group-firewall')
        firewall_settings = CloudModel.get(self._cloud_internal, 'firewall_settings')
        pass_through = CloudModel.get(self._cloud_internal, 'pass_through')
        components = CloudModel.get(self._cloud_internal, 'components')
        services = CloudModel.get(self._cloud_internal, 'services')

        for cp_name, cp in control_planes.iteritems():
            for cluster in cp['clusters']:
                for s in cluster['servers']:
                    self._build_ansible_host_vars(cloud_name, s, cp['endpoints'],
                                                  cp, cluster['name'],
                                                  ntp_servers, dns_settings, smtp_settings,
                                                  pass_through, components, services,
                                                  net_group_firewall, firewall_settings)

            for r_name, resources in cp.get('resources', {}).iteritems():
                for s in resources['servers']:
                    self._build_ansible_host_vars(cloud_name, s, cp['endpoints'],
                                                  cp, resources['name'],
                                                  ntp_servers, dns_settings, smtp_settings,
                                                  pass_through, components, services,
                                                  net_group_firewall, firewall_settings)

        CloudModel.put(self._cloud_internal, 'cloud-firewall', self._cloud_firewall)

    def _build_ansible_host_vars(self, cloud_name, server, cp_endpoints, cp, cluster_name,
                                 ntp_servers=[], dns_settings={}, smtp_settings={}, pass_through={},
                                 components={}, services={},
                                 net_group_firewall={}, firewall_settings={}):
        LOG.info('%s()' % KenLog.fcn())

        components = CloudModel.get(self._cloud_internal, 'components')
        components_by_mnemonic = CloudModel.get(self._cloud_internal, 'components_by_mnemonic')
        filename = "%s/host_vars/%s" % (self._file_path, server['ardana_ansible_host'])
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))
        self.add_artifact(filename, ArtifactMode.CREATED)

        host_vars = {
            'host': {
                'vars': {
                    'member_id': server.get('member_id', 'cpn'),
                    'my_hostname_address': server['hostname_address'],
                    'my_network_name': server['hostname'],
                    'my_network_interfaces': {}
                },
                'bind': {},
                'tls_in': [],
                'tls_out': [],
                'my_id': server['id'],
                'fcoe_interfaces': server['fcoe_interfaces'],
                'pass_through': pass_through['servers'].get(server['id'], {}),
                'my_service_ips': {},
                'failure_zone': server.get('failure-zone'),
                'role': server.get('role'),
                'my_dimensions': server['dimensions'],
                'my_logical_volumes': {},
                'my_device_groups': {},
                'cpu_assignments': server.get('cpu-assignments', {}),
                'my_ardana_ansible_name': server['ardana_ansible_host']
            },
            'ntp_servers': ntp_servers,
            'dns': dns_settings,
            'smtp': smtp_settings,
        }

        nic_mapping = {}
        if server.get('nic_map', {}):
            nic_mapping['nic_mappings'] = []
            for dev in server['nic_map']['physical-ports']:
                nic_map = {'logical_name': dev['logical-name'],
                           'bus_address': dev['bus-address'],
                           'type': dev['type']}
                if 'port-attributes' in dev:
                    nic_map['port_attributes'] = {}
                    for key, val in dev['port-attributes'].iteritems():
                        new_key = key.replace('-', '_')
                        nic_map['port_attributes'][new_key] = str(val)
                nic_mapping['nic_mappings'].append(nic_map)

        #
        #  Add per-service ips if they exist
        #
        if 'service-ips' in server:
            host_vars['host']['my_service_ips'] = server['service-ips']

        #
        #  Add list of bind addresses
        #
        for component_name, endpoint_data in cp_endpoints.iteritems():

            if component_name in server['components']:
                mnemonic = components[component_name]['mnemonic'].replace('-', '_')

                if mnemonic not in host_vars['host']['bind']:
                    host_vars['host']['bind'][mnemonic] = {}

                for role, role_data in endpoint_data.iteritems():
                    for data in role_data:

                        if 'address' in data['bind']:
                            bind_address = data['bind']['address']
                        else:
                            # May have to map to a network
                            for if_name, if_data in server['interfaces'].iteritems():
                                for net_name, net_data in if_data['networks'].iteritems():
                                    if data['bind']['network_group'] == net_data['network-group']:
                                        bind_address = net_data['addr']
                                        break
                        bind_port = data['bind']['port']
                        tls = data['bind']['tls']
                        host_vars['host']['bind'][mnemonic][role] = {'ip_address': bind_address,
                                                                     'port': bind_port,
                                                                     'tls': tls}
                        # Add cert-file when the service is terminating tls
                        if tls and component_name in cp['cert-data']['services']:
                            cert_name = ""
                            for cert in cp['cert-data']['services'][component_name]:
                                if server['ardana_ansible_host'] in cert['ansible_hosts']:
                                    cert_name = cert['cert_name']
                                    break
                            if cert_name:
                                host_vars['host']['bind'][mnemonic][role]['cert_name'] = cert_name

        #
        # Add list of tls terminations
        #
        for component_name, endpoint_data in cp_endpoints.iteritems():
            if component_name in server['components']:
                for role, role_data in endpoint_data.iteritems():
                    for data in role_data:

                        if 'tls-term'in data:
                            # Find the addesss in the right group
                            accept_addr = None
                            for if_name, if_data in server['interfaces'].iteritems():
                                for net_name, net_data in if_data['networks'].iteritems():
                                    if data['tls-term']['network_group'] == net_data['network-group']:
                                        accept_addr = net_data['addr']
                                        break

                            if not accept_addr:
                                msg = ("Can't find address in Net Group %s on %s when "
                                       "configuring tls for %s port %s" %
                                       (data['tls-term']['network_group'], server['name'],
                                        component_name, data['tls-term']['port']))
                                self.add_error(msg)

                            accept = {'ip_address': accept_addr,
                                      'port': data['tls-term']['port']}
                            connect = {'ip_address': data['bind']['address'],
                                       'port': data['bind']['port']}
                            term = {'name': component_name,
                                    'role': role,
                                    'accept': accept,
                                    'connect': connect}
                            host_vars['host']['tls_in'].append(term)

        #
        # Add a list of tls initiations
        #
        #  Build a list of all consumed services from this host
        consumed = set()
        for component_name in server['components']:
            if component_name not in components:
                print "Warning: No data for %s when buiding tls list" % component_name
                continue

            component_data = components[component_name]
            for consumes in component_data.get('consumes-services', []):
                consumes_name = consumes['service-name']
                if consumes_name not in components:
                    consumes_name = components_by_mnemonic[consumes_name]['name']
                consumed.add(consumes_name)

        for component_name in consumed:
            if component_name in cp_endpoints:
                endpoint_data = cp_endpoints[component_name]
                for role, role_data in endpoint_data.iteritems():
                    for data in role_data:
                        if 'tls-init'in data:
                            accept = {'ip_address': data['access']['address'],
                                      'host': data['access']['hostname'],
                                      'port': data['access']['port']}
                            connect = {'ip_address': data['tls-init']['address'],
                                       'host': data['tls-init']['hostname'],
                                       'port': data['tls-init']['port']}
                            init = {'name': component_name,
                                    'role': role,
                                    'accept': accept,
                                    'connect': connect}
                            host_vars['host']['tls_out'].append(init)

        #
        # Add Disk info
        #
        disk_model = DataTransformer(server['disk-model']).all_output('-', '_')
        host_vars['host']['my_disk_models'] = disk_model

        #
        # Add Memory info
        #
        memory_model = DataTransformer(server['memory-model']).all_output('-', '_')
        host_vars['host']['my_memory_model'] = memory_model

        #
        # Add a list of logical volumes by consuming component. Makes it
        # possible for a service to find its mountpoint
        #
        for vg in disk_model.get('volume_groups', []):
            for lv in vg.get('logical_volumes', []):
                if 'consumer' in lv:
                    component_name = lv['consumer'].get('name')
                    if not component_name:
                        msg = ("Consumer attribute on %s:%s in "
                               "disk-model %s does not have a 'name' value ." %
                               (vg['name'], lv['name'], disk_model['name']))
                        self.add_error(msg)
                        continue

                    # ardana-hypervisors are still known as vm-factories internally
                    elif ((component_name == 'ardana-hypervisor') and
                          server.get('vm-factory', False)):
                        pass

                    elif (component_name == 'ardana-hypervisor') and not server.get('vm-factory', False):
                        msg = ("The 'ardana-hypervisor' "
                               "consumer is being used in '%s:%s' from "
                               "disk-model '%s' on server '%s' which is not "
                               "an ardana-hypervisor" %
                               (vg['name'], lv['name'], disk_model['name'],
                                server['id']))
                        self.add_warning(msg)

                    elif component_name not in components:
                        mnemonic = component_name
                        if not lv['consumer'].get('suppress_warnings', False):
                            # Make this a warning, as it could be the customer is passing this
                            # to some playbook we don't know about
                            msg = ("Unknown component '%s' as consumer of "
                                   "%s:%s in disk-model %s." %
                                   (component_name, vg['name'], lv['name'], disk_model['name']))
                            self.add_warning(msg)

                    else:
                        if component_name not in server['components'] and not \
                                lv['consumer'].get('suppress_warnings', False):
                            msg = ("Server %s (%s) uses disk-model %s which includes a logical "
                                   "volume to be consumed by '%s', but that component does not "
                                   "run on this server." %
                                   (server['id'], server['hostname'], disk_model['name'],
                                    component_name))
                            self.add_warning(msg)

                        mnemonic = components[component_name]['mnemonic'].replace('-', '_')

                    if mnemonic not in host_vars['host']['my_logical_volumes']:
                        host_vars['host']['my_logical_volumes'][mnemonic] = []

                    host_vars['host']['my_logical_volumes'][mnemonic].append(deepcopy(lv))

        #
        # Add a list of device-groups volumes by consumer
        #
        for device_group in disk_model.get('device_groups', []):
            if 'consumer' in device_group:
                consumer_name = device_group['consumer'].get('name')
                if not consumer_name:
                    msg = ("Consumer attribute on device-group %s in "
                           "disk-model %s does not have a 'name' value ." %
                           (device_group['name'], disk_model['name']))
                    self.add_error(msg)
                    continue

                # ardana-hypervisors are still known as vm-factories internally
                elif ((consumer_name == 'ardana-hypervisor') and
                      server.get('vm-factory', False)):
                    pass

                elif ((consumer_name == 'ardana-hypervisor') and
                      not server.get('vm-factory', False)):
                    msg = ("The 'ardana-hypervisor' "
                           "consumer is being used in device-group '%s' "
                           "from disk-model '%s' on server '%s' which is "
                           "not an ardana-hypervisor" %
                           (device_group['name'], disk_model['name'],
                            server['id']))
                    self.add_warning(msg)

                elif consumer_name not in services and consumer_name not in components and not \
                        device_group['consumer'].get('suppress_warnings', False):
                    msg = ("Unknown consumer '%s' of device-group %s "
                           "in disk-model %s." %
                           (consumer_name, device_group['name'], disk_model['name']))
                    self.add_warning(msg)

                elif consumer_name not in server['services'] and consumer_name not in server['components'] \
                        and not device_group['consumer'].get('suppress_warnings', False):
                    msg = ("Server %s (%s) uses disk-model %s which includes a device-group "
                           "be consumed by '%s', but there are no components of that service "
                           "on this server." %
                           (server['id'], server['hostname'], disk_model['name'],
                            consumer_name))
                    self.add_warning(msg)

                if consumer_name not in host_vars['host']['my_device_groups']:
                    host_vars['host']['my_device_groups'][consumer_name] = []

                host_vars['host']['my_device_groups'][consumer_name].append(deepcopy(device_group))

        #
        # Generate os-config network data
        #
        # create network_interface role compatible host_vars
        (service_tags, ovs_bridge_host_vars, vlan_host_vars,
         bond_host_vars, ether_host_vars, net_group_dict,
         pci_pt_sriov_list, sriov_driver_list, dpdk_network_devices) = self._build_network_host_vars(server)
        host_vars['host']['my_network_tags'] = service_tags

        #
        # Generate the set of host my_network_groups
        #
        host_vars['host']['my_network_groups'] = self._create_my_network_groups(net_group_dict)

        #
        # Add Hosted-VM info
        #
        self._add_bridge_to_vms(server.get('vms', []), server.get('interfaces'), ovs_bridge_host_vars)
        host_vars['host']['my_vms'] = DataTransformer(server.get('vms', [])).all_output('-', '_')

        #
        # Generate a structure to tell keepalived what device to bind vips to.
        # Also supply the server address for each VIP, as we have to set up a route
        # when the VIP is on the server to avoid the VIP being used as a source IP.
        #
        net_iface_vars = {}
        for vip_net_name, vip_net_data in cp['vip_networks'].iteritems():
            #
            # Build a list of all VIPs on this network
            #
            vips = set()
            for vip_data in vip_net_data:
                if vip_data['provider'] in server['components']:
                    vips.add(vip_data['address'])

            # Find the device for this network from the network groups
            device = None
            for ng_name, ng_data in net_group_dict.items():
                for net in ng_data.get('networks', []):
                    if net['name'] == vip_net_name:
                        device = ng_data['device']
                        break

            if device:
                for vip in vips:
                    # Find the server's address for the network with the VIP
                    server_address = ""
                    for iface__name, iface_data in server.get('interfaces').iteritems():
                        if vip_net_name in iface_data.get('networks'):
                            server_address = iface_data['networks'][vip_net_name]['addr']
                            break
                    device_data = {'device': device,
                                   'interface': vip_net_name,
                                   'vip_address': vip,
                                   'server_address': server_address}
                    if 'network_interfaces' not in net_iface_vars:
                        net_iface_vars['network_interfaces'] = []
                    net_iface_vars['network_interfaces'].append(device_data)

        self.add_vips_to_network_host_vars(net_iface_vars, bond_host_vars,
                                           ether_host_vars, ovs_bridge_host_vars,
                                           vlan_host_vars)

        # Get server firewall settings
        host_vars['firewall'] = self.getFirewall(server, cp, net_group_firewall, firewall_settings,
                                                 net_group_dict)

        # Save the firewall settings for this server
        self._cloud_firewall[server['name']] = host_vars['firewall']

        if ovs_bridge_host_vars['ovs_bridge_interfaces']:
            host_vars.update(ovs_bridge_host_vars)
        if vlan_host_vars['network_vlan_interfaces']:
            host_vars.update(vlan_host_vars)
        if bond_host_vars['network_bond_interfaces']:
            host_vars.update(bond_host_vars)
        if ether_host_vars['network_ether_interfaces']:
            host_vars.update(ether_host_vars)
        if nic_mapping:
            host_vars.update(nic_mapping)
        if net_iface_vars:
            host_vars.update(net_iface_vars)
        if pci_pt_sriov_list:
            host_vars.update({'network_pci_pt_sriov_interfaces': pci_pt_sriov_list})
        if sriov_driver_list:
            host_vars.update({'network_sriov_drivers': sriov_driver_list})
        if dpdk_network_devices:
            host_vars.update({'dpdk_network_devices': self._int_to_str(dpdk_network_devices)})

        with open(filename, 'w') as fp:
            # Have to set default_style to ensure the bus address is in quotes
            yaml.dump(host_vars, fp, default_style='\'', default_flow_style=False, indent=4)

    def _create_my_network_groups(self, net_group_dict):
        return {key: net_group_dict[key]['nets']
                for key in net_group_dict if 'nets' in net_group_dict[key]}

    def _add_bridge_to_vms(self, vms, interfaces, ovs_bridge_host_vars):
        if not vms:
            return
        for vm in vms:
            for net_bridge in vm['net-bridge-info']:
                intf_dev = interfaces[net_bridge['host-interface-name']]['device']
                intf_name = self.getInterfaceName(intf_dev)
                pt_bridge_name = self.getBridgeName(intf_name)
                pt_mtu = self._get_passthrough_mtu(pt_bridge_name, ovs_bridge_host_vars)
                net_bridge['bridge_name'] = pt_bridge_name
                if pt_mtu:
                    net_bridge['bridge_mtu'] = pt_mtu
                del net_bridge['host-interface-name']

    def add_vips_to_network_host_vars(self, net_iface_vars, bond_host_vars,
                                      ether_host_vars, ovs_bridge_host_vars,
                                      vlan_host_vars):
        #
        # Modify the network host vars to add in a list of vips on each
        # interface so that we can add routing rules for them.
        #
        devices_to_vips = {}
        for iface in net_iface_vars.get('network_interfaces', []):
            device = iface['device']
            if device not in devices_to_vips:
                devices_to_vips[device] = set()
            devices_to_vips[device].add(iface['vip_address'])

        for interface in ovs_bridge_host_vars['ovs_bridge_interfaces'] \
                + vlan_host_vars['network_vlan_interfaces'] \
                + bond_host_vars['network_bond_interfaces'] \
                + ether_host_vars['network_ether_interfaces']:
            if interface['device'] in devices_to_vips:
                interface['vips'] = list(devices_to_vips[interface['device']])

    def _cidr_to_mask(self, cidr):

        mask = int(str.split(cidr, '/')[1])
        bits = 0
        for i in xrange(32 - mask, 32):
            bits |= (1 << i)
        return "%d.%d.%d.%d" % ((bits & 0xff000000) >> 24,
                                (bits & 0xff0000) >> 16,
                                (bits & 0xff00) >> 8,
                                (bits & 0xff))

    def _build_network_host_vars(self, server):
        server_bond_dictionary = {}
        server_ether_dictionary = {}
        server_vlan_dictionary = {}
        server_ovs_bridge_dictionary = {}
        server_service_tags_list = []
        server_network_groups_dict = {}
        server_bond_dictionary['network_bond_interfaces'] = []
        server_ether_dictionary['network_ether_interfaces'] = []
        server_vlan_dictionary['network_vlan_interfaces'] = []
        server_ovs_bridge_dictionary['ovs_bridge_interfaces'] = []
        server_pci_pt_sriov_list = []
        server_sriov_driver_list = []
        server_sriov_driver_set = set()
        server_dpdk_network_devices = server.get('dpdk-data', {})

        # get all the interfaces on this server
        interfaces = server.get('interfaces', None)

        for interface, interface_attrs in interfaces.items():

            interface_is_ethernet = self._interface_is_ethernet(interface_attrs)
            interface_is_bond, bond_is_ovs = self._interface_is_bond(interface_attrs)
            interface_is_passthrough = self._interface_is_passthrough(interface_attrs)
            interface_is_dpdk, dpdk_needs_bridge = self._interface_is_dpdk(interface_attrs)

            dpdk_data = interface_attrs.get('dpdk-data', {})

            # get the device definition
            interface_name = self.getInterfaceName(interface_attrs.get('device', None))

            # get the pci-pt and srio attributes
            device_data = interface_attrs['device']
            pci_pt = device_data.get('pci-pt', False)
            sriov_only = device_data.get('sriov-only', False)
            vf_count = device_data.get('vf-count', 0)

            # Need to keep track of network tags on this interface that are relevent to
            # pci-pt and sriov
            pci_pt_sriov_tags = []

            # get all networks on this interface
            networks = interface_attrs.get('networks', None)

            # Pre-scan all networks on this interface:
            # - What is the maximum MTU specified?
            # - Does this interface have at least one untagged network?
            # - Do any untagged networks have needs-bridge set?
            interface_explicit_mtu = False
            interface_max_mtu = 0
            interface_has_explicit_untagged = False
            untagged_needs_bridge = False
            for network_name, network_attrs in networks.iteritems():
                network_has_explicit_mtu, network_mtu = self._network_has_explicit_mtu(network_attrs)
                if network_has_explicit_mtu:
                    interface_explicit_mtu = True
                    interface_max_mtu = max(interface_max_mtu, network_mtu)

                if self._network_is_untagged(network_attrs):
                    interface_has_explicit_untagged = True
                    service_tags = network_attrs.get('service-tags', None)
                    untagged_needs_bridge = untagged_needs_bridge or self.getBridgeInfo(service_tags)

            bond_dictionary = {}
            ether_dictionary = {}
            lower_bridge_dictionary = {}

            # A 'base-bridge' is a bridge directly over the interface,
            # and can be required for the following reasons.
            # A base-bridge forces VLAN Interfaces to be OVS based
            needs_base_bridge = (bond_is_ovs or
                                 interface_is_passthrough or
                                 dpdk_needs_bridge)
            # a 'lower-bridge' is a bridge directly over the interface,
            # and can be required for the following reasons
            needs_lower_bridge = ((needs_base_bridge or
                                   untagged_needs_bridge) and
                                  not sriov_only and not pci_pt)
            lower_bridge_name = ''
            lower_bridge_port = ''

            # What type of Physical interface are we dealing with?
            if interface_is_bond:
                bond_data = interface_attrs.get('bond-data')

                # Gather the bonding options
                bond_options = bond_data.get('options')
                # promote bonding mode (Linux or OVS form) and
                # primary specification out of the options
                bond_mode = bond_options.pop('mode',
                                             bond_options.pop('bond_mode',
                                                              None))
                bond_primary = bond_options.pop('primary', None)
                ports = self.getPorts(bond_data)

                if bond_is_ovs:
                    # Create a default, minimal 'lower-bridge' as
                    # an OVS-Bond-Bridge
                    lower_bridge_name = self.getBridgeName(interface_name)
                    lower_bridge_port = interface_name
                    lower_bridge_dictionary['device'] = lower_bridge_name
                    lower_bridge_dictionary['port'] = lower_bridge_port
                    lower_bridge_dictionary['route'] = []
                    lower_bridge_dictionary['bootproto'] = self.getBootProto("")

                    lower_bridge_dictionary['bond_mode'] = bond_mode
                    lower_bridge_dictionary['bond_primary'] = bond_primary
                    lower_bridge_dictionary['bond_options'] = bond_options
                    lower_bridge_dictionary['bond_slaves'] = [port for port in ports]
                    self._set_interface_mtu(lower_bridge_dictionary,
                                            interface_explicit_mtu,
                                            interface_max_mtu)
                    if dpdk_data:
                        lower_bridge_dictionary['dpdk_port'] = True
                else:
                    # Create a default, minimal version of the Linux-Bond
                    bond_dictionary['device'] = interface_name
                    bond_dictionary['route'] = []
                    bond_dictionary['bootproto'] = self.getBootProto("")

                    bond_dictionary['bond_mode'] = bond_mode
                    bond_dictionary['bond_primary'] = bond_primary
                    bond_dictionary['bond_options'] = bond_options
                    bond_dictionary['bond_slaves'] = [port for port in ports]
                    self._set_mtu_if_explicit(bond_dictionary,
                                              interface_explicit_mtu,
                                              interface_max_mtu)
                    if needs_lower_bridge:
                        # Create a default, minimal 'lower-bridge' as
                        # an OVS-Bridge over a Linux-Bond
                        lower_bridge_name = self.getBridgeName(interface_name)
                        lower_bridge_port = interface_name
                        lower_bridge_dictionary['device'] = lower_bridge_name
                        lower_bridge_dictionary['port'] = lower_bridge_port
                        lower_bridge_dictionary['route'] = []
                        lower_bridge_dictionary['bootproto'] = self.getBootProto("")
                        self._set_interface_mtu(lower_bridge_dictionary,
                                                interface_explicit_mtu,
                                                interface_max_mtu)
                        bond_dictionary['ovs_bridge'] = lower_bridge_name
            else:

                # Create a default, minimal version of the Ethernet device
                ether_dictionary['device'] = interface_name
                ether_dictionary['route'] = []
                ether_dictionary['bootproto'] = self.getBootProto("")
                self._set_mtu_if_explicit(ether_dictionary,
                                          interface_explicit_mtu,
                                          interface_max_mtu)
                if sriov_only:
                    ether_dictionary['sriov_only'] = True
                if pci_pt:
                    ether_dictionary['pci_pt'] = True

                if needs_lower_bridge:
                    # Create a default 'lower-bridge'
                    lower_bridge_name = self.getBridgeName(interface_name)
                    lower_bridge_port = interface_name
                    lower_bridge_dictionary['device'] = lower_bridge_name
                    lower_bridge_dictionary['port'] = lower_bridge_port
                    lower_bridge_dictionary['route'] = []
                    lower_bridge_dictionary['bootproto'] = self.getBootProto("")
                    self._set_interface_mtu(lower_bridge_dictionary,
                                            interface_explicit_mtu,
                                            interface_max_mtu)
                    if interface_is_ethernet and \
                       not interface_has_explicit_untagged and \
                       interface_explicit_mtu:
                        # We will not be creating an interface config file later
                        # so any MTU specified here must be forced via the
                        # lower-bridge configuration
                        lower_bridge_dictionary['force_interface_mtu'] = True
                    if dpdk_data:
                        lower_bridge_dictionary['dpdk_port'] = True
                    ether_dictionary['ovs_bridge'] = lower_bridge_name

            # for all networks on this interface
            networks = interface_attrs.get('networks', None)
            for network_name, network_attrs in networks.iteritems():
                addr = network_attrs.get('addr', None)
                cidr = network_attrs.get('cidr', None)
                gateway_ip = network_attrs.get('gateway-ip', None)
                tagged_vlan = network_attrs.get('tagged-vlan', True)

                routes = network_attrs.get('routes', None)
                service_tags = network_attrs.get('service-tags', None)
                network_is_passthrough = network_attrs.get('passthrough', False)
                passthrough_only = network_attrs.get('passthrough-only', False)
                intf_route_list = self.getRoutes(routes, gateway_ip, addr, cidr)

                network_mtu = network_attrs.get('mtu')
                explicit_mtu = network_attrs.get('explicit_mtu')
                if network_is_passthrough:
                    network_attrs['passthrough-device'] = lower_bridge_name
                    if interface_explicit_mtu:
                        network_attrs['passthrough-mtu'] = interface_max_mtu
                        if not explicit_mtu:
                            # Since we are setting a passthrough-mtu we need to
                            # ensure a network MTU (which may be smaller)
                            # is also recorded, set "default" if none specified.
                            network_mtu = 1500
                            explicit_mtu = True
                            network_attrs['explicit_mtu'] = explicit_mtu
                            network_attrs['mtu'] = network_mtu

                if not tagged_vlan:
                    # Untagged or VLAN-Trunked network
                    if needs_lower_bridge:
                        # For untagged networks with a lower_bridge, extend
                        # the lower_bridge attributes and register the service.
                        # The lower_bridge will be instantiated only after all
                        # networks on this interface are processed
                        # Note: There can be at most 1 non-passthrough_only
                        #       untagged network
                        network_group_device = lower_bridge_dictionary['device']
                        if not passthrough_only:
                            # Set the untagged network specific MTU
                            self._set_mtu_or_default(lower_bridge_dictionary,
                                                     explicit_mtu,
                                                     network_mtu,
                                                     interface_explicit_mtu)
                            self.getInterfaceInfo(lower_bridge_dictionary, network_attrs)
                            lower_bridge_dictionary['route'].extend(intf_route_list)

                            untagged_service_tag_dict = {}
                            untagged_service_tag_dict['tags'] = self.getServiceTags(service_tags)
                            if untagged_service_tag_dict.get('tags', None):
                                untagged_service_tag_dict['network'] = network_name
                                untagged_service_tag_dict['device'] = lower_bridge_name
                                untagged_service_tag_dict['bridge_port'] = lower_bridge_port
                                untagged_service_tag_dict['address'] = addr
                                server_service_tags_list.append(untagged_service_tag_dict)
                                # Tags on an untagged VLAN may be needed by pci-pt / sriov
                                pci_pt_sriov_tags.extend(untagged_service_tag_dict['tags'])

                    else:
                        if interface_is_bond:
                            # Extend the Bond
                            network_group_device = bond_dictionary['device']
                            if not passthrough_only:
                                # Look for and configure for IP-addressing
                                self.getInterfaceInfo(bond_dictionary, network_attrs)
                                bond_dictionary['route'].extend(intf_route_list)
                                bond_service_tag_dict = {}
                                bond_service_tag_dict['tags'] = self.getServiceTags(service_tags)
                                # save service tag info if a tag exists
                                if bond_service_tag_dict.get('tags', None):
                                    bond_service_tag_dict['address'] = addr
                                    bond_service_tag_dict['network'] = network_name
                                    bond_service_tag_dict['device'] = interface_name
                                    server_service_tags_list.append(bond_service_tag_dict)
                        else:
                            # Extend the Ethernet
                            network_group_device = ether_dictionary['device']
                            if not passthrough_only:
                                # Look for and configure for IP-addressing
                                self.getInterfaceInfo(ether_dictionary, network_attrs)
                                ether_dictionary['route'].extend(intf_route_list)
                                ether_service_tag_dict = {}
                                ether_service_tag_dict['tags'] = self.getServiceTags(service_tags)
                                if ether_service_tag_dict.get('tags', None):
                                    ether_service_tag_dict['network'] = network_name
                                    ether_service_tag_dict['device'] = interface_name
                                    ether_service_tag_dict['address'] = addr
                                    server_service_tags_list.append(ether_service_tag_dict)
                                # Tags on an untagged VLAN may be needed by pci-pt / sriov
                                if ether_service_tag_dict.get('tags', None):
                                    pci_pt_sriov_tags.extend(ether_service_tag_dict['tags'])

                    # add to server network groups
                    self.getNetworkByGroup(server_network_groups_dict, network_name,
                                           network_group_device, network_attrs)

                else:
                    # Tagged network (VLAN)
                    # Create VLAN interface
                    # Note:
                    #   VLAN interfaces are not required for passthrough-only
                    #   networks
                    if passthrough_only:
                        network_group_device = lower_bridge_dictionary['device']
                    else:
                        # Don't add a VLAN bridge for pci-pt or sriov-only
                        if pci_pt or sriov_only:
                            needs_bridge = False
                        else:
                            # use service tags to determine if a bridge is needed
                            needs_bridge = self.getBridgeInfo(service_tags)

                        vlanid = network_attrs.get('vlanid', None)
                        vlan_name = self.getVlanName(vlanid)

                        if needs_base_bridge and needs_bridge:   # 'has_base_bridge' in VLAN context
                            # OVS-bridged-VLAN over base-bridge,
                            # handled as an ovs-bridge later
                            upper_bridge_name = self.getBridgeName(vlan_name)
                        else:
                            # VLAN interface over Ethernet, Bond or base-bridge
                            # Create a minimal VLAN
                            vlan_dictionary = {}
                            vlan_dictionary['device'] = vlan_name
                            vlan_dictionary['route'] = []
                            vlan_dictionary['bootproto'] = self.getBootProto("")
                            vlan_dictionary['vlanid'] = vlanid
                            self._set_mtu_or_default(vlan_dictionary,
                                                     explicit_mtu,
                                                     network_mtu,
                                                     interface_explicit_mtu)
                            # The following explictly does not use needs_lower_bridge
                            # We need to be able to create Linux VLANs over Linux
                            # Ethernet and Bonds when the reason for the
                            # Lower bridge was only 'untagged_needs_bridge'
                            if needs_base_bridge:   # 'has_base_bridge' in VLAN context
                                # OVS-VLAN over base-bridge (inc. OVS-bond)
                                vlan_dictionary['provider'] = "openvswitch"
                                vlan_dictionary['vlanrawdevice'] = lower_bridge_name
                            else:
                                # Linux-VLAN over Linux Ethernet or Bond
                                vlan_dictionary['provider'] = "linux"
                                vlan_dictionary['vlanrawdevice'] = interface_name
                                # It is only necessary to set the vlanrawdevice_mtu
                                # for ethernet interfaces with no untagged.
                                # In that case there will be no interface
                                # configuration created to set the MTU so the
                                # interface MTU is set indirectly using the VLAN
                                # configuration(s).
                                # But, for compatibility with previous releases
                                # and to avoid unnecessary network-restarts it
                                # continues to be set whenever there is an MTU
                                # on the interface
                                if interface_explicit_mtu:
                                    vlan_dictionary['vlanrawdevice_mtu'] = interface_max_mtu
                            if needs_bridge:
                                upper_bridge_name = self.getBridgeName(vlan_name)
                                vlan_dictionary['ovs_bridge'] = upper_bridge_name
                            else:
                                # Extend the VLAN with potential IP-configuration
                                # and register the service
                                network_group_device = vlan_dictionary['device']
                                self.getInterfaceInfo(vlan_dictionary, network_attrs)
                                vlan_dictionary['route'].extend(intf_route_list)
                                vlan_service_tag_dict = {}
                                vlan_service_tag_dict['tags'] = self.getServiceTags(service_tags)
                                # save service tag info if a tag exists
                                if vlan_service_tag_dict.get('tags', None):
                                    vlan_service_tag_dict['address'] = addr
                                    vlan_service_tag_dict['network'] = network_name
                                    vlan_service_tag_dict['device'] = vlan_name
                                    server_service_tags_list.append(vlan_service_tag_dict)
                            # clean out any null values
                            vlan_dict_clean = self._clean_dict(vlan_dictionary)
                            server_vlan_dictionary['network_vlan_interfaces'].append(vlan_dict_clean)

                        if needs_bridge:
                            # Bridged-VLAN
                            # - create an upper bridge base on this network
                            #   The vlan_name and upper_bridge_name were set when
                            #   the VLAN was created above
                            network_group_device = upper_bridge_name
                            upper_bridge_dictionary = {}
                            upper_bridge_dictionary['device'] = upper_bridge_name
                            upper_bridge_dictionary['route'] = []
                            upper_bridge_dictionary['bootproto'] = self.getBootProto("")

                            self._set_mtu_or_default(upper_bridge_dictionary,
                                                     explicit_mtu,
                                                     network_mtu,
                                                     interface_explicit_mtu)
                            upper_bridge_dictionary['route'].extend(intf_route_list)

                            self.getInterfaceInfo(upper_bridge_dictionary, network_attrs)

                            tagged_service_tag_dict = {}
                            if needs_base_bridge:    # has-base-bridge in this case
                                # OVS-Bridged-VLAN over lower-bridge (inc. OVS-bond)
                                upper_bridge_dictionary['port'] = lower_bridge_name
                                upper_bridge_dictionary['vlanid'] = vlanid
                                tagged_service_tag_dict['bridge_port'] = lower_bridge_name
                            else:
                                # OVS-Bridge over Linux VLAN,
                                upper_bridge_dictionary['port'] = vlan_name
                                tagged_service_tag_dict['bridge_port'] = vlan_name

                            # clean out any null values
                            upper_bridge_dict_clean = self._clean_dict(upper_bridge_dictionary)
                            server_ovs_bridge_dictionary['ovs_bridge_interfaces'].append(upper_bridge_dict_clean)

                            tagged_service_tag_dict['tags'] = self.getServiceTags(service_tags)
                            # save service tag info if a tag exists
                            if tagged_service_tag_dict.get('tags', None):
                                tagged_service_tag_dict['network'] = network_name
                                tagged_service_tag_dict['device'] = upper_bridge_name
                                tagged_service_tag_dict['address'] = addr
                                server_service_tags_list.append(tagged_service_tag_dict)

                    # add to server network groups
                    self.getNetworkByGroup(server_network_groups_dict, network_name,
                                           network_group_device, network_attrs)

            # The 'interface' specification may have been updated with
            # 'untagged' network information
            if interface_is_bond:
                if not bond_is_ovs:
                    # Add the Linux bond we were building
                    bond_dict_clean = self._clean_dict(bond_dictionary)
                    server_bond_dictionary['network_bond_interfaces'].append(bond_dict_clean)
            else:
                # We don't create a configuration for Ethernets that only
                # have tagged networks.
                if interface_has_explicit_untagged or pci_pt or sriov_only:
                    # Add the Ethernet we were building
                    ether_dict_clean = self._clean_dict(ether_dictionary)
                    server_ether_dictionary['network_ether_interfaces'].append(ether_dict_clean)

            if needs_lower_bridge:
                # Add the Lower bridge (or ovs-bond) we've built
                lower_bridge_dict_clean = self._clean_dict(lower_bridge_dictionary)
                server_ovs_bridge_dictionary['ovs_bridge_interfaces'].append(lower_bridge_dict_clean)

            # Build pci-pt and sriov data
            if vf_count > 0 or pci_pt:

                nic_device_data = self.getNICDeviceData(interface_name,
                                                        server['nic_map'])

                pci_pt_sriov = {'device': interface_name,
                                'bus_address': nic_device_data['bus-address'],
                                'type': nic_device_data['type'],
                                'tags': pci_pt_sriov_tags}

                if 'port-attributes' in nic_device_data:
                    pci_pt_sriov['port_attributes'] = {}
                    for k, v in nic_device_data['port-attributes'].iteritems():
                        pci_pt_sriov['port_attributes'][str(k).replace('-', '_')] = str(v)

                if pci_pt:
                    pci_pt_sriov['pf_mode'] = 'pci-passthrough'
                elif sriov_only:
                    pci_pt_sriov['pf_mode'] = 'sriov-only'
                else:
                    pci_pt_sriov['pf_mode'] = 'normal'

                dev_type = nic_device_data['nic-device-type']
                dev_family = dev_type['family_data']
                pci_pt_sriov['nic_device_type'] = {'name': dev_type['name'],
                                                   'family': dev_type['family'],
                                                   'device_id': dev_type['device-id'],
                                                   'vendor_id': dev_family['vendor-id']}
                driver = dev_family['driver']
                pci_pt_sriov['driver'] = driver

                if vf_count > 0:
                    pci_pt_sriov['vf_count'] = str(vf_count)
                    driver_data = {'vf_count': str(vf_count),
                                   'config_script': dev_family['config-script']}
                    if dev_family.get('vf-count-type') == 'driver':
                        if driver not in server_sriov_driver_set:
                            server_sriov_driver_list.append(driver_data)
                            server_sriov_driver_set.add(driver)
                    else:
                        pci_pt_sriov.update(driver_data)

                server_pci_pt_sriov_list.append(pci_pt_sriov)

            # Build dpdk driver data
            if dpdk_data:
                def _build_dpdk_info(component, interface_name, dpdk_data, nic_data):
                    nic_device_data = self.getNICDeviceData(interface_name, nic_data)

                    dpdk_info = {'device': interface_name,
                                 'bus_address': nic_device_data['bus-address']}

                    if 'driver' in dpdk_data:
                        dpdk_info['driver'] = dpdk_data.get('driver')

                    if 'port-attributes' in nic_device_data:
                        dpdk_info['port_attributes'] = {}
                        for k, v in nic_device_data['port-attributes'].iteritems():
                            dpdk_info['port_attributes'][str(k).replace('-', '_')] = str(v)

                    component['devices'].append(dpdk_info)

                if dpdk_data['component'] not in server_dpdk_network_devices:
                    server_dpdk_network_devices[dpdk_data['component']] = []

                component = server_dpdk_network_devices[dpdk_data['component']]
                nic_data = server['nic_map']

                if not dpdk_data['composite']:
                    _build_dpdk_info(component, interface_name, dpdk_data, nic_data)
                else:
                    for device in dpdk_data['devices']:
                        _build_dpdk_info(component, device['name'], device, nic_data)

        # If any ovs bridge has a dpdk port then make all ovs bridges of type netdev
        dp_type = next(('netdev' for bridge in server_ovs_bridge_dictionary['ovs_bridge_interfaces']
                        if 'dpdk_port' in bridge), 'system')
        for bridge in server_ovs_bridge_dictionary['ovs_bridge_interfaces']:
            bridge['datapath_type'] = dp_type

        self._clean_implicit_mtus(server_ovs_bridge_dictionary['ovs_bridge_interfaces'],
                                  server_vlan_dictionary['network_vlan_interfaces'],
                                  server_bond_dictionary['network_bond_interfaces'],
                                  server_ether_dictionary['network_ether_interfaces'])

        return (server_service_tags_list, server_ovs_bridge_dictionary,
                server_vlan_dictionary, server_bond_dictionary,
                server_ether_dictionary, server_network_groups_dict,
                server_pci_pt_sriov_list, server_sriov_driver_list,
                server_dpdk_network_devices)

    def _interface_is_ethernet(self, interface_attrs):
        return 'bond-data' not in interface_attrs

    def _interface_is_bond(self, interface_attrs):
        # Return: interface_is_bond and bond_is_ovs
        bond_data = interface_attrs.get('bond-data', None)
        if bond_data:
            return True, bond_data.get('provider', '') == 'openvswitch'
        else:
            return False, False

    def _interface_is_passthrough(self, interface_attrs):
        return len(interface_attrs.get('passthrough-network-groups', [])) > 0

    def _interface_is_dpdk(self, interface_attrs):
        # Return: dpdk and dpdk_needs_bridge
        dpdk_data = interface_attrs.get('dpdk-data', {})
        if dpdk_data:
            return True, dpdk_data['component'] == 'FND_OVS'
        else:
            return False, False

    def _network_is_tagged(self, network_attrs):
        return network_attrs.get('tagged-vlan', True)

    def _network_is_untagged(self, network_attrs):
        return not self._network_is_tagged(network_attrs)

    def _network_has_explicit_mtu(self, network_attrs):
        # Return: has_explicit_mtu and mtu
        has_explicit_mtu = network_attrs.get('explicit_mtu', False)
        if has_explicit_mtu:
            return has_explicit_mtu, network_attrs.get('mtu')
        else:
            return has_explicit_mtu, 0

    def _set_mtu_if_explicit(self, network_dict, explicit_mtu, mtu):
        if explicit_mtu:
            self._set_mtu(network_dict, explicit_mtu, mtu)

    def _set_mtu_or_default(self, network_dict, explicit_mtu, mtu, interface_explicit_mtu):
        if explicit_mtu:
            self._set_mtu(network_dict, explicit_mtu, mtu)
        elif interface_explicit_mtu:
            self._set_mtu(network_dict, interface_explicit_mtu, 1500)

    def _set_mtu(self, network_dict, explicit_mtu, mtu):
        network_dict.update({'explicit_mtu': explicit_mtu,
                             'mtu': mtu})

    def _set_interface_mtu(self, network_dict, explicit_mtu, mtu):
        if explicit_mtu:
            network_dict['interface_mtu'] = mtu

    def _get_passthrough_mtu(self, pt_bridge_name, ovs_bridge_host_vars):
        for bridge in ovs_bridge_host_vars['ovs_bridge_interfaces']:
            if bridge['device'] == pt_bridge_name:
                return bridge.get('interface_mtu', None)
        else:
            return None

    def _int_to_str(self, data):
        if isinstance(data, dict):
            for k, v in data.iteritems():
                data[k] = self._int_to_str(v)
            return data
        elif isinstance(data, list):
            new = [self._int_to_str(v) for v in data]
            return new
        elif isinstance(data, int):
            return str(data)
        else:
            return data

    def _clean_dict(self, dirty_dict):
        return {k: v for k, v in dirty_dict.items() if v or isinstance(v, bool)}

    def _find_max_vlan_mtu(self, interface_name, server_vlan_ifaces):
        max_mtu = -1
        for vlan_iface in (iface for iface in server_vlan_ifaces
                           if iface['vlanrawdevice'] == interface_name):
            if vlan_iface['mtu'] > max_mtu:
                max_mtu = vlan_iface['mtu']
        return max_mtu

    def _any_explicit_vlan_mtu(self, interface_name, server_vlan_ifaces):
        any_explicit_vlan_mtu = False
        for vlan_iface in (iface for iface in server_vlan_ifaces
                           if iface['vlanrawdevice'] == interface_name):
            if vlan_iface['explicit_mtu']:
                any_explicit_vlan_mtu = True
        return any_explicit_vlan_mtu

    def _clean_implicit_mtus(self, ovsbr_list, vlan_list, bond_list, ether_list):
        # remove mtu attributes which weren't explicitly set
        for iface in ovsbr_list + vlan_list + bond_list + ether_list:
            if 'explicit_mtu' in iface:
                if not iface['explicit_mtu']:
                    iface.pop('mtu')
                    iface.pop('vlanrawdevice_mtu', None)
                iface.pop('explicit_mtu')

    def getInterfaceInfo(self, interface_dict, network_attrs):
        addr = network_attrs.get('addr', None)
        if addr:
            if netaddr.valid_ipv6(addr):
                interface_dict['family'] = 'IPv6'
            else:
                interface_dict['family'] = 'IPv4'
            interface_dict['address'] = addr
            cidr = network_attrs.get('cidr', None)
            interface_dict['cidr'] = cidr
            interface_dict['netmask'] = self.getNetmask(cidr)
            interface_dict['gateway'] = network_attrs.get('gateway-ip', None)
            interface_dict['routing_table'] = network_attrs.get('network-group', None)
        # Update the bootproto based on the current state of the interface
        interface_dict['bootproto'] = self.getBootProto(interface_dict.get('address', None))

    def getRoutes(self, routes, gateway_ip, addr, onlink_cidr):
        route_list = []
        for route in routes:
            if route['cidr'] != onlink_cidr:
                rte_network, rte_netmask, rte_gateway = self.getRouteInfo(route, gateway_ip, addr)
                route_dictionary = {}
                route_dictionary['network'] = rte_network
                route_dictionary['netmask'] = rte_netmask
                route_dictionary['gateway'] = rte_gateway
                if route_dictionary not in route_list:
                    route_list.append(route_dictionary)
        return route_list

    def getNetworkByGroup(self, network_groups_dict, network_name, device_name, network_attrs):
        # for each network, put it into the desired network group.
        # this is currently building two sets of data
        # 1) The original data:
        #    Flat within the network group plus the list of IP-network data
        # 2) The 'nets' list of dicts.
        #    This second set is flattened later to become
        #    host.my_network_groups

        # First the original content
        network_group = network_attrs.get('network-group', None)
        addr = network_attrs.get('addr', None)
        cidr = network_attrs.get('cidr', None)
        gateway_ip = network_attrs.get('gateway-ip', None)
        if network_group not in network_groups_dict.keys():
            network_groups_dict[network_group] = {}
            network_groups_dict[network_group]['name'] = network_group
            network_groups_dict[network_group]['networks'] = []
            network_groups_dict[network_group]['nets'] = []
        network_groups_dict[network_group]['device'] = device_name
        if addr:
            network_groups_dict[network_group]['address'] = addr
        if cidr:
            network_dict = {}
            network_dict['name'] = network_name
            network_dict['cidr'] = cidr
            network_dict['gateway'] = gateway_ip
            network_groups_dict[network_group]['networks'].append(network_dict)

        # Second set of data
        net_dict = {
            'network-name': network_name,
            'passthrough-device': network_attrs.get('passthrough-device', None),
            'passthrough-mtu': network_attrs.get('passthrough-mtu', None),
            'tagged-vlan': network_attrs.get('tagged-vlan', True),
            'vlanid': network_attrs.get('vlanid', None),
            'device': device_name,
            'address': addr,
            'cidr': cidr,
            'gateway-ip': gateway_ip
        }
        if network_attrs.get('explicit_mtu', False):
            net_dict['mtu'] = network_attrs.get('mtu', None)
        clean_net_dict = self._clean_dict(net_dict)
        network_groups_dict[network_group]['nets'].append(clean_net_dict)

    def getBridgeInfo(self, service_tags):
        needs_bridge = False
        for tag in service_tags:
            # get the definition dictionary from each tag
            definition = tag.get('definition', None)
            if definition:
                needs_bridge = definition.get('needs-bridge', False)
            # Stop as soon as we find a tag that needs a bridge
            if needs_bridge:
                break
        return needs_bridge

    def getBridgeName(self, interface):
        return "br-" + interface

    def getVlanName(self, vlanid):
        return "vlan" + str(vlanid)

    def getBootProto(self, addr):
        # We don't need to support dhcp
        if addr:
            return 'static'
        else:
            return 'manual'

    def getRouteInfo(self, route, gateway, addr):
        rte_network = ''
        rte_netmask = ''
        if route['default']:
            if addr and netaddr.valid_ipv6(addr):
                rte_network = '::/0'
                rte_netmask = '::/0'
            else:
                rte_network = '0.0.0.0'
                rte_netmask = '0.0.0.0'
        else:
            # If route is not 'default',
            ipNetwork = netaddr.IPNetwork(route['cidr'])
            rte_network = str(ipNetwork.network)
            rte_netmask = str(ipNetwork.netmask)
        return rte_network, rte_netmask, gateway

    def getNetmask(self, netmask):
        # netmask could be xx.xx.xx.xx or xx.xx.xx.xx/yy
        if netmask and '/' in netmask:
            ip, routing_prefix = netmask.split("/")
            return int(routing_prefix)
        else:
            return netmask

    def getInterfaceName(self, device):
        name = device.get('name', None)
        return name

    def getServiceTags(self, service_tags):
        service_tag_list = []
        for tag in service_tags:
            service_tag_dict = {}
            service_tag_dict['tag'] = tag.get('name', None)
            service_tag_dict['service'] = tag.get('service', None)
            service_tag_dict['data_values'] = deepcopy(tag.get('values', None))
            service_tag_dict['component'] = tag.get('component', None)
            service_tag_list.append(service_tag_dict)
        return service_tag_list

    def getPorts(self, bond_data):
        ports = []
        if not bond_data:
            return ports
        devices = bond_data.get('devices', None)
        if not devices:
            return ports

        for device in devices:
            name = device.get('name', None)
            ports.append(name)
        return ports

    def getNICDeviceData(self, device_name, nic_mappings):
        device_data = None
        for dev in nic_mappings['physical-ports']:
            if dev['logical-name'] == device_name:
                device_data = dev
                break
        return device_data

    def getFirewall(self, server, cp, net_group_firewall, firewall_settings, net_group_dict):
        #
        # Build a list of firwall rules, indexed by IP
        # address
        #
        firewall = {}
        rules = {}
        managed_networks = []
        load_balancers = cp.get('load-balancer-config', {})

        # Build a mapping

        # Loop though interfaces adding rules for each component on that interface

        for iface_name, iface_data in server.get('interfaces', {}).iteritems():
            for net_name, net_data in iface_data.get('networks', {}).iteritems():

                if 'addr' not in net_data:
                    continue

                firewall_rules = net_group_firewall.get(net_data['network-group'], {})
                component_rules = firewall_rules.get('component', [])
                user_rules = firewall_rules.get('user', [])
                vips = {}

                # Get the device for this interface
                interface = net_group_dict[net_data['network-group']]['device']

                managed_network = {'name': net_data['network-group'],
                                   'interface': interface}
                managed_networks.append(managed_network)

                ip_prefix = self.get_remote_ip_prefix(net_data['addr'])

                # if net_data['addr'] equals server['addr'] then a rule
                # is needed to allow ssh for Ansible since the 'os-install'
                # interface has been 'subsumed' into an Ardana managed network
                if net_data['addr'] == server['addr']:
                    if net_data['addr'] not in rules:
                        rules[net_data['addr']] = []
                    ssh_rule = {'type': 'allow',
                                'remote-ip-prefix': ip_prefix,
                                'port-range-min': 22,
                                'port-range-max': 22,
                                'protocol': 'tcp',
                                'chain': net_data['network-group'],
                                'component': 'ssh'}
                    rules[net_data['addr']].append(ssh_rule)

                for comp_name in net_data['endpoints']:
                    if comp_name in component_rules:
                        addrs = []
                        # If the component has its own IP address then the
                        # ports are associated with that not the server address
                        if comp_name in server.get('service-ips', {}):
                            addrs.append(server['service-ips'][comp_name])
                            if comp_name in server.get('service-vips', {}):
                                addrs.append(server['service-vips'][comp_name])
                        else:
                            addrs.append(net_data['addr'])

                        for addr in addrs:
                            if addr not in rules:
                                rules[addr] = []
                            fw_ip_prefix = self.get_remote_ip_prefix(addr)
                            for firewall_rule in component_rules[comp_name]:
                                firewall_rule['chain'] = net_data['network-group']
                                firewall_rule['component'] = comp_name
                                firewall_rule['remote-ip-prefix'] = fw_ip_prefix
                            rules[addr].extend(deepcopy(component_rules[comp_name]))

                    # Check for Load balancers
                    for name, data in load_balancers.get(comp_name, {}).iteritems():
                        for vip in data['networks']:
                            vip_address = vip['ip-address']
                            vip_prefix = self.get_remote_ip_prefix(vip_address)
                            if vip_address not in rules:
                                rules[vip_address] = []
                                vips[vip_address] = vip

                            vip_rule = {'type': 'allow',
                                        'remote-ip-prefix': vip_prefix,
                                        'port-range-min': vip['vip-port'],
                                        'port-range-max': vip['vip-port'],
                                        'protocol': 'tcp',
                                        'chain': vip['network-group'],
                                        'component': vip['component-name']}
                            rules[vip_address].append(vip_rule)

                # Add any rules defined by a network tag
                for tag_data in net_data.get('service-tags'):
                    for tag_ep in tag_data['definition'].get('endpoints', []):
                        tag_rule = {'type': 'allow',
                                    'remote-ip-prefix': ip_prefix,
                                    'port-range-min': tag_ep['port'],
                                    'port-range-max': tag_ep['port'],
                                    'protocol': tag_ep.get('protocol', 'tcp'),
                                    'chain': net_data['network-group'],
                                    'component': tag_data['component']}
                        if net_data['addr'] not in rules:
                            rules[net_data['addr']] = []
                        rules[net_data['addr']].append(tag_rule)

                # Add any user defined rules
                if user_rules:
                    if net_data['addr'] not in rules:
                        rules[net_data['addr']] = []
                    for rule_data in user_rules:
                        user_rule = deepcopy(rule_data)
                        user_rule['chain'] = net_data['network-group']
                        rules[net_data['addr']].append(user_rule)
                        # Make a separate copy as teh vip may be in a different chain
                        for vip, vip_data in vips.iteritems():
                            vip_rule = deepcopy(user_rule)
                            vip_rule['chain'] = vip_data['network-group']
                            rules[vip].append(vip_rule)

        firewall['rules'] = rules
        firewall['managed_networks'] = managed_networks
        firewall['enable'] = firewall_settings.get('enable', True)
        firewall['settings'] = firewall_settings

        return firewall

    def get_remote_ip_prefix(self, address):
        if netaddr.valid_ipv6(address):
            return '::/0'
        return '0.0.0.0/0'

    def get_dependencies(self):
        return ['persistent-state-2.0']
