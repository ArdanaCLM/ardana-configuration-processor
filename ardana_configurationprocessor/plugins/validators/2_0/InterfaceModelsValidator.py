#
# (c) Copyright 2015, 2016 Hewlett Packard Enterprise Development LP
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

from ardana_configurationprocessor.cp.model.ValidatorPlugin \
    import ValidatorPlugin
from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog


LOG = logging.getLogger(__name__)

DEFAULT_MTU = 1500


class InterfaceModelsValidator(ValidatorPlugin):
    def __init__(self, instructions, config_files):
        super(InterfaceModelsValidator, self).__init__(
            2.0, instructions, config_files,
            'interface-models-2.0')
        self._valid = False
        LOG.info('%s()' % KenLog.fcn())

    def validate(self):
        LOG.info('%s()' % KenLog.fcn())

        version = float(self.version())

        input = self._create_content(version, "interface-models")
        self._valid = self.validate_schema(input, "interface_model")
        if self._valid:
            components = self._get_dict_from_config_value(version, 'service-components')
            interface_models = input['interface-models']
            self._validate_names(interface_models)
            for model in interface_models:
                self._validate_interface_names(model)
                self._validate_devices_only_used_once(model)
                self._validate_untagged_vlans_on_iface(model)
                self._validate_mtu(model)
                self._validate_vxlan_netgroup(model)
                self._validate_sriov(model)
                self._validate_pci_pt(model)
                self._validate_dpdk(model, components)
            self._validate_bond_options(interface_models)

        return self._valid

    def _validate_names(self, interface_models):
        names = set()
        for model in interface_models:
            if model['name'] in names:
                msg = ("Interface model '%s' is defined more than once." %
                       (model['name']))
                self.add_error(msg)
                self._valid = False
            else:
                names.add(model['name'])

    def _validate_interface_names(self, interface_model):
        names = set()
        for iface in (interface_model['network-interfaces'] +
                      interface_model.get('fcoe-interfaces', [])):
            if iface['name'] in names:
                msg = ("Interface model '%s': interface '%s' is defined "
                       "more than once." %
                       (interface_model['name'], iface['name']))
                self.add_error(msg)
                self._valid = False
            else:
                names.add(iface['name'])

    def _validate_devices_only_used_once(self, interface_model):
        used_devices = set()
        devices = []
        for iface in interface_model['network-interfaces']:
            devices.append((iface['name'], iface['device']['name']))
            if 'bond-data' in iface:
                for device in iface['bond-data']['devices']:
                    devices.append((iface['name'], device['name']))

        for fcoe_iface in interface_model.get('fcoe-interfaces', []):
            for device in fcoe_iface['devices']:
                devices.append((fcoe_iface['name'], device))

        for iface_name, device in devices:
            if device not in used_devices:
                used_devices.add(device)
            else:
                msg = ("Network interface '%s' in '%s': device '%s' is "
                       "already used. A device can only be used once per "
                       "interface model." %
                       (iface_name, interface_model['name'], device))
                self.add_error(msg)
                self._valid = False

    def _validate_sriov(self, interface_model):
        for iface in interface_model['network-interfaces']:
            sriov_only = iface['device'].get('sriov-only', False)
            vf_count = iface['device'].get('vf-count', 0)

            if sriov_only and vf_count == 0:
                msg = ("Network interface '%s' in '%s': 'vf-count' must  "
                       "be specified when 'sriov-only' is set." %
                       (iface['name'], interface_model['name']))
                self.add_error(msg)
                self._valid = False

            if vf_count > 0 and 'bond-data' in iface:
                msg = ("Network interface '%s' in '%s': 'vf-count' cannot "
                       "be specified on bonded interfaces." %
                       (iface['name'], interface_model['name']))
                self.add_error(msg)
                self._valid = False

            if sriov_only and 'passthrough-network-groups' in iface:
                msg = ("Network interface '%s' in '%s': "
                       "'passthrough-network-groups' cannot "
                       "be specified on 'sriov-only' interfaces." %
                       (iface['name'], interface_model['name']))
                self.add_error(msg)
                self._valid = False

    def _validate_pci_pt(self, interface_model):
        for iface in interface_model['network-interfaces']:
            pci_pt = iface['device'].get('pci-pt', False)
            sriov_only = iface['device'].get('sriov-only', False)

            if pci_pt and sriov_only:
                msg = ("Network interface '%s' in '%s': 'sriov-only' and  "
                       "'pci-pt' cannot both be set on the same interface." %
                       (iface['name'], interface_model['name']))
                self.add_error(msg)
                self._valid = False

            if pci_pt and 'bond-data' in iface:
                msg = ("Network interface '%s' in '%s': 'pci-pt' cannot "
                       "be specified on bonded interfaces." %
                       (iface['name'], interface_model['name']))
                self.add_error(msg)
                self._valid = False

            if pci_pt and 'passthrough-network-groups' in iface:
                msg = ("Network interface '%s' in '%s': "
                       "'passthrough-network-groups' cannot "
                       "be specified on 'pci-pt' interfaces." %
                       (iface['name'], interface_model['name']))
                self.add_error(msg)
                self._valid = False

    def _validate_dpdk(self, interface_model, components):
        def _validate_single_use(check_device, interface_model, iface_by_device):
            iface = iface_by_device[check_device]
            if iface['device'].get('pci-pt', False):
                msg = ("Interface Model '%s': "
                       "Device '%s' can not be configured for both DPDK and "
                       "PCI Passthrough." %
                       (interface_model['name'], check_device))
                self.add_error(msg)
                self._valid = False

            if iface['device'].get('sriov-only', False):
                msg = ("Interface Model '%s': "
                       "Device '%s' can not be configured for both DPDK and "
                       "sriov-only." %
                       (interface_model['name'], check_device))
                self.add_error(msg)
                self._valid = False

        # Create a structure indexed by device name
        iface_by_device = {}
        for iface in interface_model['network-interfaces']:
            iface_by_device[iface['device']['name']] = iface

        # Multiple dpdk devices can be grouped into a collection and there
        # are several dpdk applications that can use a dpdk collection.  There
        # also can be multiple collections for each network-interface.
        # The only dpdk collection currently understood is an Open vSwitch bond
        dpdk_collections = {}
        for iface in interface_model['network-interfaces']:
            if 'bond-data' in iface:
                for device in iface['bond-data']['devices']:
                    cg_name = iface['device']['name']
                    cg = dpdk_collections.get(cg_name, {})
                    new_cg = False if len(cg.keys()) > 0 else True
                    if 'devices' not in cg:
                        cg['devices'] = []
                    cg['devices'].append(device['name'])
                    if new_cg:
                        dpdk_collections[cg_name] = cg

        for dpdk_data in interface_model.get('dpdk-devices', []):
            for comp_name in dpdk_data['components']:
                if comp_name not in components:
                    msg = ("DPDK devices in Interface Model '%s': "
                           "Component '%s' is not defined." %
                           (interface_model['name'], comp_name))
                    self.add_error(msg)
                    self._valid = False

            for device in dpdk_data['devices']:
                check_device = device['name']

                dev_in_collection = False
                for k, v in dpdk_collections.iteritems():
                    if check_device in v['devices']:
                        check_device = k
                        dev_in_collection = True
                        break

                if not dev_in_collection and check_device not in iface_by_device:
                    msg = ("DPDK devices in Interface Model '%s': "
                           "Device '%s' is not used by any interface in network-interfaces." %
                           (interface_model['name'], check_device))
                    self.add_error(msg)
                    self._valid = False
                    continue

                _validate_single_use(check_device, interface_model, iface_by_device)

    def _validate_untagged_vlans_on_iface(self, interface_model):
        untagged_network_groups = self._get_untagged_network_groups()
        for iface in interface_model['network-interfaces']:
            untagged_netgroups_on_iface = set()
            for netgroup in self._get_netgroups_on_iface(iface):
                if netgroup in untagged_network_groups:
                    untagged_netgroups_on_iface.add(netgroup)
            if len(untagged_netgroups_on_iface) > 1:
                msg = ("Network interface '%s' in '%s' has multiple "
                       "network groups or forced network groups with "
                       "with untagged vlans on it (%s). "
                       "There can only be one untagged vlan per interface." %
                       (iface['name'], interface_model['name'],
                        ', '.join(untagged_netgroups_on_iface)))
                self.add_error(msg)
                self._valid = False

    def _validate_mtu(self, interface_model):
        for iface in interface_model['network-interfaces']:
            vlans = self._get_vlans(iface)
            tagged_vlans_on_iface = [vlan for vlan in vlans if vlan['tagged-vlan']]
            untagged_vlans_on_iface = [vlan for vlan in vlans if not vlan['tagged-vlan']]

            explicit_mtu_netgroups = {vlan['network-group'] for vlan in vlans
                                      if vlan['explicit_mtu']}
            implicit_mtu_netgroups = {vlan['network-group'] for vlan in vlans
                                      if not vlan['explicit_mtu']}
            if not (len(explicit_mtu_netgroups) == 0 or len(implicit_mtu_netgroups) == 0):
                msg = ("Network interface '%s' in '%s' has network groups with a "
                       "specified MTU (%s) and network groups with an unspecified "
                       "MTU (%s). Network groups with an unspecified MTU will be "
                       "set to the default %s. Please explicitly set an MTU for "
                       "these network groups to remove this warning." %
                       (iface['name'], interface_model['name'],
                        ", ".join(explicit_mtu_netgroups),
                        ", ".join(implicit_mtu_netgroups), DEFAULT_MTU))
                self.add_warning(msg)

            max_mtu = -1
            for untagged_vlan in untagged_vlans_on_iface:
                untagged_mtu = untagged_vlan['mtu']
                for tagged_vlan in tagged_vlans_on_iface:
                    tagged_mtu = tagged_vlan['mtu']
                    if untagged_mtu < tagged_mtu and tagged_mtu > max_mtu:
                        max_mtu = tagged_mtu
            if max_mtu != -1:
                msg = ("Network interface '%s' in '%s' has both untagged and tagged "
                       "vlan network groups, and their MTUs are in conflict. "
                       "Untagged network group %s (mtu: %s) must have an MTU greater "
                       "than or equal to the highest MTU of the tagged vlan network "
                       "groups on the same interface (%s)." %
                       (iface['name'], interface_model['name'],
                        untagged_vlan['network-group'], untagged_vlan['mtu'], max_mtu))
                self.add_error(msg)
                self._valid = False

    def _get_vlans(self, interface):
        version = float(self.version())
        net_groups = self._get_dict_from_config_value(version, 'network-groups')
        networks = self._get_dict_from_config_value(version, 'networks')

        vlans_on_iface = []
        for iface_net_group in self._get_netgroups_on_iface(interface):
            for net in (net for net in networks.values()
                        if net.get('network-group', None) and
                        net['network-group'] == iface_net_group):
                vlan = {'network': net['name'],
                        'tagged-vlan': net.get('tagged-vlan', True),
                        'mtu': net_groups[net['network-group']].get('mtu', DEFAULT_MTU),
                        'explicit_mtu': 'mtu' in net_groups[net['network-group']],
                        'network-group': net['network-group']}
                vlans_on_iface.append(vlan)
        return vlans_on_iface

    def _get_passthrough_vlans(self, interface):
        version = float(self.version())
        net_groups = self._get_dict_from_config_value(version, 'network-groups')
        networks = self._get_dict_from_config_value(version, 'networks')

        vlans_on_iface = []
        for iface_net_group in self._get_passthrough_netgroups_on_iface(interface):
            for net in (net for net in networks.values()
                        if net.get('network-group', None) and
                        net['network-group'] == iface_net_group):
                vlan = {'network': net['name'],
                        'tagged-vlan': net.get('tagged-vlan', True),
                        'mtu': net_groups[net['network-group']].get('mtu', DEFAULT_MTU),
                        'explicit_mtu': 'mtu' in net_groups[net['network-group']],
                        'network-group': net['network-group']}
                vlans_on_iface.append(vlan)
        return vlans_on_iface

    def _get_netgroups_on_iface(self, iface):
        netgroups = set()
        netgroups |= set(iface.get('network-groups', []))
        netgroups |= set(iface.get('forced-network-groups', []))

        return list(netgroups)

    def _get_passthrough_netgroups_on_iface(self, iface):
        netgroups = set()
        netgroups |= set(iface.get('passthrough-network-groups', []))

        return list(netgroups)

    def _get_untagged_network_groups(self):
        networks = self._get_dict_from_config_value(float(self.version()), 'networks')
        untagged_netgroups = set()
        for net in networks.values():
            if not net.get('tagged-vlan', True):
                untagged_netgroups.add(net['network-group'])
        return untagged_netgroups

    def _validate_vxlan_netgroup(self, interface_model):
        vxlan_tag = 'neutron.networks.vxlan'
        network_groups = self._get_network_groups()
        vxlan_netgroups_in_model = set()
        for iface in interface_model['network-interfaces']:
            for netgroup in self._get_netgroups_on_iface(iface):
                for tag in network_groups.get(netgroup, {}).get('tags', []):
                    if tag == vxlan_tag or (
                            isinstance(tag, dict) and vxlan_tag in tag):
                        vxlan_netgroups_in_model.add(netgroup)
                        break
        if len(vxlan_netgroups_in_model) > 1:
            msg = ("Interface model '%s' contains multiple network groups "
                   "with the '%s' tag (%s). Each interface model may only "
                   "contain one network group with the '%s' tag." %
                   (interface_model['name'], vxlan_tag,
                    ', '.join(vxlan_netgroups_in_model), vxlan_tag))
            self.add_error(msg)
            self._valid = False

    def _get_network_groups(self):
        return self._get_dict_from_config_value(float(self.version()), 'network-groups')

    def _validate_bond_options(self, interface_models):
        for interface_model in interface_models:
            for iface in interface_model['network-interfaces']:
                if 'bond-data' in iface:
                    self._validate_bond_mode(iface)
                    self._validate_bond_primary(iface, interface_model['name'])
                    self._validate_bond_slaves(iface, interface_model['name'])

    def _valid_bond_provider(self, bond_provider):
        valid_bond_providers = ['linux', 'windows', 'openvswitch']
        return (bond_provider in valid_bond_providers), valid_bond_providers

    def _validate_bond_mode(self, interface):
        valid_bond_modes = {'linux': ['balance-rr', 0,
                                      'active-backup', 1,
                                      'balance-xor', 2,
                                      'broadcast', 3,
                                      '802.3ad', 4,
                                      'balance-tlb', 5,
                                      'balance-alb', 6],
                            'windows': ['SwitchIndependent',
                                        'Static',
                                        'LACP'],
                            'openvswitch': ['active-backup',
                                            'balance-tcp',
                                            'balance-slb']}

        bond_options = interface['bond-data']['options']
        bond_provider = interface['bond-data'].get('provider', None)
        if bond_provider is None:
            msg = ("Network interface '%s' is a bond but has not specified "
                   "'provider' as one of its options.  Assuming 'linux' "
                   "by default." % (interface['name']))
            self.add_warning(msg)
            bond_provider = 'linux'
            # update so the html builder doesn't fail
            interface['bond-data']['provider'] = bond_provider
        bond_provider_is_valid, valid_bond_providers = self._valid_bond_provider(bond_provider)
        if not bond_provider_is_valid:
            msg = ("Network interface '%s': the chosen bond provider '%s' "
                   "is invalid. Please choose a valid bond provider: %s" %
                   (interface['name'], bond_provider, valid_bond_providers))
            self.add_error(msg)
            self._valid = False
            return
        # Accept bond mode specification via 'mode' or 'bond_mode'
        bond_mode = bond_options.get('mode', bond_options.get('bond_mode',
                                                              None))
        if bond_mode is None:
            msg = ("Network interface '%s' is a bond but has not specified "
                   "'mode' or 'bond_mode' as one of its options." %
                   (interface['name']))
            self.add_error(msg)
            self._valid = False
            return
        if bond_mode not in valid_bond_modes[bond_provider]:
            msg = ("Network interface %s: the chosen bond mode '%s' "
                   "is invalid. Please choose a valid %s bond mode: %s" %
                   (interface['name'], bond_mode, bond_provider,
                    valid_bond_modes[bond_provider]))
            self.add_error(msg)
            self._valid = False

    def _validate_bond_primary(self, interface, interface_model_name):
        bond_provider = interface['bond-data'].get('provider', 'linux')
        bond_primary_device = interface['bond-data']['options'].get('primary', None)
        if bond_provider == 'openvswitch' and bond_primary_device:
            msg = ("Network interface '%s' in '%s' specifies provider: '%s' and"
                   " bond primary: '%s', bond primary: is not supported by"
                   " provider, ignoring" %
                   (interface['name'], interface_model_name, bond_provider,
                    bond_primary_device))
            self.add_warning(msg)
        bond_devices = [dev['name'] for dev in interface['bond-data']['devices']]
        if bond_primary_device and bond_primary_device not in bond_devices:
            msg = ("Network interface '%s' in '%s' specifies the bond primary: "
                   "'%s', which does not appear in the bond's set of devices: %s" %
                   (interface['name'], interface_model_name, bond_primary_device,
                    bond_devices))
            self.add_error(msg)
            self._valid = False

    def _validate_bond_slaves(self, interface, interface_model_name):
        bond_slave_minimums = {'linux': 1,
                               'windows': 2,
                               'openvswitch': 2}
        bond_provider = interface['bond-data'].get('provider', 'linux')
        bond_devices = [dev['name'] for dev in interface['bond-data']['devices']]
        bond_provider_is_valid = self._valid_bond_provider(bond_provider)[0]
        if bond_provider_is_valid:
            if len(bond_devices) < bond_slave_minimums[bond_provider]:
                msg = ("Network interface '%s' in '%s' specifies provider: '%s'"
                       " and devices: '%s', the provider requires at least '%d'"
                       " device(s)" %
                       (interface['name'], interface_model_name, bond_provider,
                        bond_devices, bond_slave_minimums[bond_provider]))
                self.add_error(msg)
                self._valid = False

    @property
    def instructions(self):
        return self._instructions

    @property
    def valid(self):
        return self._valid

    @valid.setter
    def valid(self, is_valid):
        self._valid = is_valid

    def get_dependencies(self):
        return ['service-components-2.0',
                'network-groups-2.0',
                'networks-2.0']
