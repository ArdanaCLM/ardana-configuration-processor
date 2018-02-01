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
import string

from ardana_configurationprocessor.cp.model.GeneratorPlugin \
    import GeneratorPlugin
from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog
from ardana_configurationprocessor.cp.model.v2_0.CloudModel \
    import CloudModel
from ardana_configurationprocessor.cp.model.v2_0 \
    import ServerState


LOG = logging.getLogger(__name__)


class VMFactoryGenerator(GeneratorPlugin):
    def __init__(self, instructions, models, controllers):
        super(VMFactoryGenerator, self).__init__(
            2.0, instructions, models, controllers,
            'vm-factory-2.0')
        LOG.info('%s()' % KenLog.fcn())

    def generate(self):
        LOG.info('%s()' % KenLog.fcn())

        cloud_internal = CloudModel.internal(self._models['CloudModel'])
        servers = CloudModel.get(cloud_internal, 'servers', {})
        self._add_vm_info_to_factory(servers)

    def _add_vm_info_to_factory(self, servers):
        for server in servers:
            if server['state'] == ServerState.ALLOCATED and server.get('vm-factory', False):
                vms = []
                for s in servers:
                    if s['state'] == ServerState.ALLOCATED and s.get('hypervisor-id', None) == server['id']:
                        for disk in s['disk-model']['vm-size']['disks']:
                            # Convert disk size to decimal bytes
                            disk['size'] = self._disk_size(disk['size'])
                        self._check_vm_network_interfaces(s)
                        self._add_vlan_ids(s['port-groups'], s['interfaces'])
                        #
                        # Get network prefix and vm device used for ansible
                        #
                        (address, ardana_net_dev) = self._get_ardana_network(s, s['nic_map']['name'],
                                                                             sorted(s['nic_map']['physical-ports'],
                                                                                    key=lambda
                                                                                    x: x['bus-address']))
                        vm_dict = {'vm': "-".join(["ardana", s['id']]),
                                   'disks': s['disk-model']['vm-size']['disks'],
                                   'vcpus': s['vm_no_of_vcpus'],
                                   'ram': s['memory-model']['vm_ram_size_in_k'],
                                   'net-bridge-info': sorted(s['port-groups'],
                                                             key=lambda x: x['interface']),
                                   'address': address,
                                   'ardana_ansible_host': s['ardana_ansible_host'],
                                   'ardana_net_interface': ardana_net_dev}
                        vms.append(vm_dict)
                server['vms'] = vms

    def _check_vm_network_interfaces(self, vm):
        #
        # Check which vm host interfaces have information generated for them
        # Remove port-group entries for vm interfaces which don't have information
        # generated for them
        #
        vm_devices = []
        for intf_name, intf in vm['interfaces'].iteritems():
            vm_devices.append(intf['device']['name'])
        for pg in vm['port-groups']:
            if pg['interface'] not in vm_devices:
                vm['port-groups'].remove(pg)

    def _get_ardana_network(self, server, nic_map_name, nic_map_ports):
        #
        # Get the network prefix and vm device used for ansible
        # We append the prefix to the address for convenience when creating
        # the vms
        # We check that the vm device used for ansible is the first entry
        # in the vm's nic-mapping
        #
        for intf_name, intf in server['interfaces'].iteritems():
            for net_name, net in intf['networks'].iteritems():
                if net.get('addr') == server['addr']:
                    ardana_dev = intf['device']['name']
                    if nic_map_ports and ardana_dev != nic_map_ports[0]['logical-name']:
                        self.add_error("Server '%s' which is to be a vm and which has a nic-mapping "
                                       "does not have its ansible network assigned to the "
                                       "entry with the lowest pci-address in its nic-mapping '%s'" %
                                       (server['id'], nic_map_name))
                    return ("%s/%s" % (server['addr'], net['cidr'].split('/')[-1]),
                            ardana_dev)

    def _add_vlan_ids(self, port_groups, interfaces):
        for port_group in port_groups:
            intf = interfaces[port_group['vm-interface-name']]
            networks = []
            for net_grp in port_group['groups']:
                network = {'name': net_grp,
                           'vlan-ids': []}
                for net_name, net in intf['networks'].iteritems():
                    if net['network-group'] == net_grp:
                        if 'vlanid' in net:
                            network['vlan-ids'].append(net['vlanid'])
                        if not net.get('tagged-vlan', True):
                            network['untagged'] = True
                if not network['vlan-ids']:
                    del network['vlan-ids']
                networks.append(network)
            port_group['groups'] = networks
            port_group['provider'] = 'openvswitch'
            del port_group['vm-interface-name']

    def _disk_size(self, size):
        multiplier = {'K': 1000,
                      'M': 1000 * 1000,
                      'G': 1000 * 1000 * 1000,
                      'T': 1000 * 1000 * 1000 * 1000}

        num = str(size).strip("KMGT")
        qual = str(size).lstrip(string.digits)
        return int(num) * multiplier[qual]

    def get_dependencies(self):
        return ['internal-model-2.0',
                'cloud-cplite-2.0',
                'cpu-assignment-generator-2.0',
                'memory-model-generator-2.0']
