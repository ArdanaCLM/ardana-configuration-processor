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

from ardana_configurationprocessor.cp.model.ValidatorPlugin \
    import ValidatorPlugin
from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog


LOG = logging.getLogger(__name__)


class VMFactoryValidator(ValidatorPlugin):
    def __init__(self, instructions, config_files):
        super(VMFactoryValidator, self).__init__(
            2.0, instructions, config_files,
            'vm-factory-2.0')
        self._valid = True
        LOG.info('%s()' % KenLog.fcn())

    def validate(self):
        LOG.info('%s()' % KenLog.fcn())
        version = float(self.version())
        input = self._create_content(version, "servers")
        servers = input.get('servers', [])
        nic_mappings = self._get_dict_from_config_value(version, 'nic-mappings')
        if not nic_mappings:
            nic_mappings = {}
        iface_models = self._get_dict_from_config_value(version, 'interface-models')
        server_roles = self._get_dict_from_config_value(version, 'server-roles')
        disk_models = self._get_dict_from_config_value(version, 'disk-models')
        cpu_models = self._get_dict_from_config_value(version, 'cpu-models')
        memory_models = self._get_dict_from_config_value(version, 'memory-models')
        self._identify_vms_and_hosts(servers, server_roles, disk_models, cpu_models,
                                     memory_models, iface_models, nic_mappings)

    def _identify_vms_and_hosts(self, servers, server_roles, disk_models, cpu_models,
                                memory_models, iface_models, nic_mappings):
        # Process hypervisor-id
        for server in servers:
            if server.get('hypervisor-id', None):
                valid_hyp = self._validate_hypervisor_id(server, servers)
                server_role = server_roles.get(server.get('role', None), {})
                self._validate_disk_size(server, server_role, disk_models)
                self._validate_no_of_disks(server, server_role, disk_models)
                self._validate_vcpu_cores(server, server_role, cpu_models)
                self._validate_memory_size(server, server_role, memory_models)
                valid_intf = self._check_for_vm_bonds(server, server_role.get('interface-model', None),
                                                      iface_models)
                if valid_hyp and valid_intf:
                    self._validate_iface_models(server, servers, server_role, server_roles,
                                                iface_models, nic_mappings)

        # Process ardana-hypervisor
        for server in servers:
            if (server.get('ardana-hypervisor', False)):
                server['vm-factory'] = True

        # Validate passthrough-network-groups
        for server in servers:
            server_role = server_roles.get(server.get('role', None), {})
            self._validate_passthrough(server, server_role.get('interface-model', None),
                                       iface_models)

    def _check_for_vm_bonds(self, vm, vm_iface_name, iface_models):
        for iface_name, iface in iface_models.iteritems():
            if iface_name == vm_iface_name:
                valid = True
                for vm_intf in iface['network-interfaces']:
                    if vm_intf.get('bond-data', {}):
                        self.add_error("Server '%s' which is defined to be a vm "
                                       "is using a network "
                                       "interface '%s' in interface model '%s' "
                                       "which is a bond" %
                                       (vm['id'], vm_intf['name'], vm_iface_name))
                        self._valid = False
                        valid = False
                return valid

    def _validate_vm_bus_address(self, vm, dev):
        if dev['bus-address'].split('.')[-1] != '0':
            self.add_error("Server '%s' which is defined to be a vm is using device "
                           "'%s' in nic-mapping '%s' whose bus-address doesn't end "
                           "in '.0'" %
                           (vm['id'], dev['logical-name'], vm['nic-mapping']))
            self._valid = False

    def _validate_passthrough(self, server, server_iface_name, iface_models):
        passthrough = False
        for s_intf in iface_models.get(server_iface_name, {}).get('network-interfaces', []):
            if s_intf.get('passthrough-network-groups', []):
                passthrough = True
                break

        if not passthrough and server.get('ardana-hypervisor', False) \
                and not server.get('hypervisor-id', None):
            msg = "Server '%s' which is defined to be a hypervisor doesn't have " \
                  "'passthrough-network-groups' set for any interface in its " \
                  "interface model '%s'" % \
                  (server.get('id'), server_iface_name)
            self.add_error(msg)
            self._valid = False

    def _validate_iface_models(self, vm, servers, vm_server_role, server_roles, iface_models,
                               nic_mappings):
        hypervisor_role = None
        for server in servers:
            if server.get('id') == vm['hypervisor-id']:
                hypervisor_role = server.get('role', None)
                break
        hypervisor_iface_name = server_roles.get(hypervisor_role, {}).get('interface-model', None)
        vm_iface_name = vm_server_role.get('interface-model', None)

        vm_iface = {}
        hypervisor_iface = {}
        for iface_name, iface in iface_models.iteritems():
            if iface_name == vm_iface_name:
                vm_iface = iface
            if iface_name == hypervisor_iface_name:
                hypervisor_iface = iface

        nic_map = vm.get('nic-mapping', None)
        if not nic_map:
            self.add_error("Server '%s' which is defined to be a vm does not "
                           "have a nic-mapping" % vm['id'])
            self._valid = False

        nic_mapping = nic_mappings.get(nic_map, None)
        if nic_mapping:
            nic_map_dev = set()
            for dev in nic_mapping['physical-ports']:
                nic_map_dev.add(dev['logical-name'])
        else:
            nic_map_dev = None

        vm_dev = set()
        for vm_intf in vm_iface.get('network-interfaces', []):
            vm_int_groups = set(vm_intf.get('network-groups', []) +
                                vm_intf.get('forced-network-groups', []))
            vm_dev.add(vm_intf['device']['name'])
            match = False
            for h_intf in hypervisor_iface.get('network-interfaces', []):
                # Enforce passthrough-network-groups
                if vm_int_groups.issubset(set(h_intf.get('passthrough-network-groups', []))):
                    match = True
                    if 'port-groups' not in vm:
                        vm['port-groups'] = []
                    port_group = 'ardana-%s-%s' % (vm['id'], vm_intf['device']['name'])
                    found = False
                    if nic_mapping:
                        for dev in nic_mapping['physical-ports']:
                            found = False
                            if dev['logical-name'] == vm_intf['device']['name']:
                                found = True
                                self._validate_vm_bus_address(vm, dev)
                                bus_address = dev['bus-address']
                                break

                    if found:
                        pg = {'name': port_group,
                              'bus-address': bus_address,
                              'interface': vm_intf['device']['name'],
                              'vm-interface-name': vm_intf['name'],
                              'host-interface-name': h_intf['name'],
                              'groups': deepcopy(vm_intf.get('network-groups', []) +
                                                 vm_intf.get('forced-network-groups', []))}
                        vm['port-groups'].append(pg)

                    continue
            if not match:
                self.add_error("The set of 'network-groups' and 'forced-network-groups' for "
                               "vm '%s' network-interface '%s' "
                               "in interface model '%s' is not a subset of any of the "
                               "'passthrough-network-groups' in the interfaces in interface model "
                               "'%s' on the 'hypervisor-id' '%s'" %
                               (vm.get('id'), vm_intf['name'], vm_iface_name, hypervisor_iface_name,
                                vm['hypervisor-id']))
                self._valid = False

        if nic_map_dev and nic_map_dev != vm_dev:
            self.add_warning("Server '%s' which is defined to be a vm is using a set of "
                             "network devices in its interface model '%s' which isn't "
                             "exactly equal to the set of devices in its nic-mapping '%s'" %
                             (vm['id'], vm_iface_name, nic_map))

    def _validate_vcpu_cores(self, vm, server_role, cpu_models):
        cpu_model_name = server_role.get('cpu-model', None)
        if not cpu_model_name:
            self.add_error("Server '%s' is defined to be a vm, but its role '%s' "
                           "does not have a cpu-model" % (vm.get('id'), vm.get('role')))
            self._valid = False
        elif not cpu_models.get(cpu_model_name, {}).get('vm-size', {}):
            self.add_error("Server '%s' is defined to be a vm, but the cpu-model "
                           "'%s' assigned to its role '%s' does not "
                           "have a 'vm-size' stanza." %
                           (vm.get('id'), cpu_model_name, vm.get('role')))
            self._valid = False

    def _validate_memory_size(self, vm, server_role, memory_models):
        mem_model_name = server_role.get('memory-model', None)
        if not mem_model_name:
            self.add_error("Server '%s' is defined to be a vm but its role '%s' "
                           "does not have a memory-model" % (vm.get('id'), vm.get('role')))
            self._valid = False
        elif not memory_models.get(mem_model_name, {}).get('vm-size', None):
            self.add_error("Server '%s' is defined to be a vm, but the memory-model "
                           "'%s' assigned to its role '%s' does not "
                           "have a 'vm-size' stanza." %
                           (vm.get('id'), mem_model_name, vm.get('role')))
            self._valid = False

    def _validate_disk_size(self, vm, server_role, disk_models):
        disk_model = disk_models.get(server_role.get('disk-model', None), {})
        if not disk_model.get('vm-size', None):
            self.add_error("Server '%s' is defined to be a vm, but the disk-model "
                           "'%s' assigned to its role '%s' does not "
                           "have a 'vm-size' stanza." %
                           (vm.get('id'), disk_model.get('name'), vm.get('role')))
            self._valid = False

    def _validate_no_of_disks(self, vm, server_role, disk_models):
        disk_model = disk_models.get(server_role.get('disk-model', None), {})
        no_of_disks = 0
        if 'volume-groups' in disk_model.keys():
            for vg in disk_model['volume-groups']:
                no_of_disks += len(vg['physical-volumes'])
        if 'device-groups' in disk_model.keys():
            for dg in disk_model['device-groups']:
                no_of_disks += len(dg['devices'])
        if no_of_disks >= 31:
            self.add_error("Server '%s' is defined to be a vm, but the disk-model "
                           "'%s' assigned to its role '%s' has >= 31 disks" %
                           (vm['id'], disk_model.get('name'), vm.get('role')))
            self._valid = False

    def _validate_hypervisor_id(self, vm, servers):
        if vm.get('hypervisor-id', None) and vm.get('ardana-hypervisor', False):
            msg = "Server '%s' is defined to be a vm and also a vm hypervisor" % vm.get('id')
            self.add_error(msg)
            self._valid = False

        valid = False
        for server in servers:
            if vm.get('hypervisor-id') == server.get('id'):
                valid = True
                if server.get('hypervisor-id', None):
                    msg = "Server '%s' is a vm on 'hypervisor-id' '%s' that is also a vm" % \
                          (vm.get('id'), vm.get('hypervisor-id'))
                    self.add_error(msg)
                    self._valid = False
                if vm.get('server-group', None):
                    if vm['server-group'] != server['server-group']:
                        msg = "Server '%s' that is a vm on 'hypervisor-id' '%s' isn't in the same " \
                              "server-group as its hypervisor '%s'" % \
                              (vm.get('id'), vm.get('hypervisor-id'), server['server-group'])
                        self.add_error(msg)
                        self._valid = False
                else:
                    vm['server-group'] = server['server-group']
                if not server.get('ardana-hypervisor', False) and not server.get('hypervisor-id', None):
                    msg = ("Server '%s' which is defined to be a hypervisor "
                           "for vm '%s' does not have the 'ardana-hypervisor' "
                           "field set" %
                           (server.get('id'), vm.get('id')))
                    self.add_error(msg)
                    self._valid = False
                server['vm-factory'] = True
                break

        if not valid:
            msg = "Server '%s' references a 'hypervisor-id' '%s' that doesn't exist in " \
                  "the model" % (vm.get('id'), vm.get('hypervisor-id'))
            self.add_error(msg)
            self._valid = False
        return valid

    @property
    def instructions(self):
        return self._instructions

    def get_dependencies(self):
        return ['nic-mappings-2.0',
                'interface-models-2.0',
                'server-roles-2.0',
                'disk-model-2.0',
                'memory-model-2.0',
                'cpu-model-2.0']
