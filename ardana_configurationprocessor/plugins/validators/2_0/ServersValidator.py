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
import collections
import logging
import logging.config

from ardana_configurationprocessor.cp.model.ValidatorPlugin \
    import ValidatorPlugin
from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog

from netaddr import IPNetwork, IPAddress, AddrFormatError
import re

LOG = logging.getLogger(__name__)


class ServersValidator(ValidatorPlugin):
    def __init__(self, instructions, config_files):
        super(ServersValidator, self).__init__(
            2.0, instructions, config_files,
            'servers-2.0')
        self._valid = True
        LOG.info('%s()' % KenLog.fcn())

    def validate(self):
        LOG.info('%s()' % KenLog.fcn())
        version = float(self.version())

        input = self._create_content(version, "servers")
        schema_valid = self.validate_schema(input, "server")
        if schema_valid:
            servers = input.get('servers', [])
            baremetal = {}
            try:
                baremetal = self._create_content(version, 'baremetal')['baremetal'][0]
            except TypeError:
                try:
                    # baremetal_networks is still suppoted for backwards compatibility
                    baremetal = self._create_content(version, 'baremetal_network')['baremetal_network'][0]
                except TypeError:
                    # Possible to have servers with no baremetal section if not using
                    # cobbler to deploy
                    pass

            nic_mappings = self._get_dict_from_config_value(version, 'nic-mappings')
            if not nic_mappings:
                nic_mappings = {}
            iface_models = self._get_dict_from_config_value(version, 'interface-models')
            server_roles = self._get_dict_from_config_value(version, 'server-roles')
            server_groups = self._get_dict_from_config_value(version, 'server-groups')
            nic_device_types = self._get_dict_from_config_value(version, 'nic-device-types')
            if not nic_device_types:
                nic_device_types = {}
            nic_device_families = self._get_dict_from_config_value(version, 'nic-device-families')
            if not nic_device_families:
                nic_device_families = {}

            if baremetal:
                self._validate_baremetal_net(baremetal)
            self._validate_unique_ids(servers)
            self._validate_ip_addresses(servers)
            self._validate_mac_addresses(servers)
            self._validate_server_groups(servers, server_groups)
            self._validate_net_devices(servers, nic_mappings, server_roles, iface_models,
                                       nic_device_types, nic_device_families)

        LOG.info('%s()' % KenLog.fcn())
        return self._valid

    def _validate_unique_ids(self, servers):
        id_set = {}
        for s in servers:
            if s['id'] in id_set:
                id_set[s['id']].append(s['ip-addr'])
                msg = ("Duplicate server id: %s (%s)" %
                       (s['id'], id_set[s['id']]))
                self.add_error(msg)
                self._valid = False
            else:
                id_set[s['id']] = [s['ip-addr']]

    def _validate_baremetal_net(self, baremetal):
        try:
            IPNetwork(baremetal['subnet'])
        except AddrFormatError:
            msg = ("Invalid baremetal subnet: %s" % baremetal['subnet'])
            self.add_error(msg)
            self._valid = False

        try:
            IPNetwork(baremetal['netmask'])
        except AddrFormatError:
            msg = ("Invalid baremetal netmask: %s" % baremetal['netmask'])
            self.add_error(msg)
            self._valid = False

    def _validate_ip_addresses(self, servers):
        for server in servers:
            try:
                IPAddress(server['ip-addr'])
            except AddrFormatError:
                msg = ("Server '%s' has an invalid IP address for 'ip-addr': %s" %
                       (server['id'], server['ip-addr']))
                self.add_error(msg)
                self._valid = False

            if 'ilo-ip' in server:
                try:
                    IPAddress(server['ilo-ip'])
                except AddrFormatError:
                    msg = ("Server '%s' has an invalid IP address for 'ilo-ip': %s" %
                           (server['id'], server['ilo-ip']))
                    self.add_error(msg)
                    self._valid = False

    def _validate_mac_addresses(self, servers):
        mac_addr_regex = r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$'
        for server in servers:
            if 'mac-addr' in server:
                if not re.match(mac_addr_regex, server['mac-addr'].lower()):
                    msg = ("Server '%s' has an invalid MAC address: '%s'. "
                           "Here is an example format: "
                           "'01:23:45:67:89:ab'" %
                           (server['id'], server['mac-addr']))
                    self.add_error(msg)
                    self._valid = False

    def _validate_server_groups(self, servers, server_groups):

        for s in servers:
            if 'server-group' in s:
                if s['server-group'] not in server_groups:
                    msg = ("Server Group '%s' used by server %s "
                           "is not defined" % (s['server-group'], s['id']))
                    self.add_error(msg)
                    self._valid = False

    def _validate_multiport_pcipt(self, server_iface_model, server_nic_map, server_id):
        device_map = {
            i['device']['name']: {
                'pci_pt': i['device'].get('pci-pt', False),
                'sriov_only': i['device'].get('sriov-only', False)}
            for i in server_iface_model['network-interfaces']}
        bus_addr_map = collections.defaultdict(set)
        for port in server_nic_map['physical-ports']:
            if port['type'] == 'multi-port':
                bus_addr_map[port['bus-address']].add(port['logical-name'])
        multiport_nic_sets = bus_addr_map.values()

        for multiport_nic_set in multiport_nic_sets:
            for port in multiport_nic_set:
                if device_map.get(port, {}).get('pci_pt', False):
                    for peer_port in (multiport_nic_set - {port}):
                        if not (device_map.get(peer_port, {}).get('pci_pt', False) or
                                device_map.get(peer_port, {}).get('sriov_only', False)):
                            msg = ("Server '%s' using interface-model '%s' "
                                   "and nic-mapping '%s': device '%s' has specified "
                                   "'pci-pt: True', but device '%s' is neither 'pci-pt' "
                                   "nor 'sriov-only'. If any port on a multi-port device "
                                   "has 'pci-pt: True', then all other ports on the same "
                                   "device must have either 'pci-pt: True' or "
                                   "'sriov-only: True'" %
                                   (server_id, server_iface_model['name'],
                                    server_nic_map['name'], port, peer_port))
                            self.add_error(msg)
                            self._valid = False

    def _validate_net_devices(self, servers, nic_mappings, server_roles, iface_models,
                              nic_device_types, nic_device_families):

        for s in servers:
            # Keep track of the vf counts by driver
            driver_vf_counts = {}

            s_role = server_roles.get(s['role'], {})
            if not s_role:
                msg = ("Server role '%s' used by server %s "
                       "is not defined" % (s['role'], s['id']))
                self.add_error(msg)
                self._valid = False
                continue

            s_iface_model = iface_models.get(s_role['interface-model'], {})

            # We can only validate the device if we have a NIC mapping
            if 'nic-mapping' not in s:
                if nic_mappings:
                    msg = ("NIC mappings definition provided but server '%s' does "
                           "not have a nic-mapping attribute" % s.get('id'))
                    self.add_warning(msg)
                continue

            s_nic_map = nic_mappings.get(s['nic-mapping'], {})
            if not s_nic_map:
                msg = ("NIC Mapping '%s' used by server %s "
                       "is not defined" % (s['nic-mapping'], s['ip-addr']))
                self.add_error(msg)
                self._valid = False
                continue

            self._validate_multiport_pcipt(s_iface_model, s_nic_map, s['id'])

            for iface in s_iface_model.get('network-interfaces', []):
                devices = []
                nic_devices = []
                if 'bond-data' in iface:
                    for bond_dev in iface['bond-data']['devices']:
                        devices.append(bond_dev['name'])
                else:
                    devices.append(iface['device']['name'])

                for port in s_nic_map['physical-ports']:
                    nic_devices.append(port['logical-name'])

                for device in devices:
                    if device not in nic_devices:
                        msg = ("Server %s needs device %s for interface %s "
                               "in interface model %s, but this device is "
                               "not defined in its nic-mapping %s." %
                               (s['id'], device, iface['name'],
                                s_iface_model['name'], s_nic_map['name']))
                        self.add_error(msg)
                        self._valid = False

                vf_count = iface['device'].get('vf-count')
                if vf_count:
                    for port in s_nic_map['physical-ports']:
                        if port['logical-name'] != iface['device']['name']:
                            continue

                        if 'nic-device-type' not in port:
                            msg = ("Server '%s' uses interface model '%s' which "
                                   "defines a 'vf-count' of %s for device '%s', "
                                   "but '%s' in nic_mapping '%s' does not define "
                                   "the nic-device-type." %
                                   (s['id'], s_role['interface-model'],
                                    vf_count, iface['device']['name'],
                                    iface['device']['name'], s['nic-mapping']))
                            self.add_error(msg)
                            self._valid = False
                            continue

                        nic_type = nic_device_types.get(port['nic-device-type'], {})
                        nic_family = nic_device_families.get(nic_type['family'], {})

                        if 'max-vf-count' in nic_family and vf_count > nic_family['max-vf-count']:
                            msg = ("Server '%s' uses interface model '%s' which "
                                   "defines a 'vf-count' of %s for device '%s', "
                                   "which exceeds the maximum value of %s for nic device "
                                   "family '%s'." %
                                   (s['id'], s_role['interface-model'],
                                    vf_count, iface['device']['name'],
                                    nic_family['max-vf-count'], nic_family['name']))
                            self.add_error(msg)
                            self._valid = False
                            continue

                        if nic_family['vf-count-type'] == 'driver':
                            if nic_family['driver'] not in driver_vf_counts:
                                driver_vf_counts[nic_family['driver']] = {'counts': set(),
                                                                          'ifaces': set()}
                            driver_vf_counts[nic_family['driver']]['counts'].add(vf_count)
                            driver_vf_counts[nic_family['driver']]['ifaces'].add(iface['name'])

                if iface['device'].get('pci-pt', False):
                    for port in s_nic_map['physical-ports']:
                        if port['logical-name'] != iface['device']['name']:
                            continue

                        if 'nic-device-type' not in port:
                            msg = ("Server '%s' uses interface model '%s' which "
                                   "defines '%s' as a pci-passthrough device "
                                   "but '%s' in nic_mapping '%s' does not define "
                                   "the nic-device-type." %
                                   (s['id'], s_role['interface-model'],
                                    iface['device']['name'],
                                    iface['device']['name'], s['nic-mapping']))
                            self.add_error(msg)
                            self._valid = False

            # Check to see the per driver vf counts are valid
            for driver, data in driver_vf_counts.iteritems():
                if len(data['counts']) > 1:
                    msg = ("The following interfaces on server '%s' using interface "
                           "model '%s' are using the driver '%s' which has a constraint "
                           "that all vf-counts must be the same value: %s" %
                           (s['id'], s_role['interface-model'], driver,
                            str(list(data['ifaces'])).strip('[]')))
                    self.add_error(msg)
                    self._valid = False

    @property
    def instructions(self):
        return self._instructions

    def get_dependencies(self):
        return ['nic-mappings-2.0',
                'interface-models-2.0',
                'nic-device-types-2.0',
                'nic-device-families-2.0',
                'server-roles-2.0',
                'server-groups-2.0',
                'disk-model-2.0',
                'cpu-model-2.0',
                'memory-model-2.0',
                'vm-factory-2.0']
