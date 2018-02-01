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

from netaddr import IPNetwork, IPAddress, IPRange, IPSet, AddrFormatError

LOG = logging.getLogger(__name__)


class NetworksValidator(ValidatorPlugin):
    def __init__(self, instructions, config_files):
        super(NetworksValidator, self).__init__(
            2.0, instructions, config_files,
            'networks-2.0')
        self._valid = False
        self._valid_cidr = True
        self._ipsets = {}
        LOG.info('%s()' % KenLog.fcn())

    def validate(self):
        LOG.info('%s()' % KenLog.fcn())
        version = float(self.version())

        input = self._create_content(version, "networks")
        self._valid = self.validate_schema(input, "network")

        if self._valid:
            networks = input.get('networks', [])
            self._validate_names(networks)
            for net in networks:
                self._validate_vlans(net)
                self._validate_cidr(net)
                self._validate_vxlan_net_has_cidr(net)
                self._validate_addresses_in_cidr(net)
                self._validate_no_network_overlaps()
            self._validate_gateways(networks)

        if self._valid:
            networks = input.get('networks', [])
            for net in networks:
                self._validate_vips_in_net(net)

        LOG.info('%s()' % KenLog.fcn())
        return self._valid

    def _validate_names(self, networks):

        #
        # Check each model is only defined once
        #
        names = set()
        for net in networks:
            if net['name'] in names:
                msg = ("Network %s is defined more than once." %
                       (net['name']))
                self.add_error(msg)
                self._valid = False
            else:
                names.add(net['name'])

    def _validate_no_network_overlaps(self):
        overlaps = {}
        for net_name, ipset in self._ipsets.iteritems():
            for other_net_name, other_ipset in self._ipsets.iteritems():
                if net_name == other_net_name:
                    continue
                if not ipset.isdisjoint(other_ipset):
                    if net_name not in overlaps:
                        overlaps[net_name] = []
                    overlaps[net_name].append(other_net_name)
                    if net_name not in overlaps.get(other_net_name, []):
                        msg = ("Network %s has address overlaps with "
                               "network %s." %
                               (net_name, other_net_name))
                        self.add_error(msg)
                        self._valid = False

    def _validate_ip_addresses(self, net):
        is_valid = True
        for ip_attribute in ['gateway-ip', 'start-address', 'end-address']:
            if ip_attribute in net:
                try:
                    IPAddress(net[ip_attribute])
                except AddrFormatError:
                    msg = ("Network %s: %s is not a valid IP address for '%s'." %
                           (net['name'], net[ip_attribute], ip_attribute))
                    self.add_error(msg)
                    is_valid = False
        return is_valid

    def _validate_cidr(self, net):
        valid_ip_addresses = self._validate_ip_addresses(net)
        if not valid_ip_addresses:
            self._valid_cidr = False
        elif 'cidr' in net:
            # Find the first and last address of the cidr
            try:
                ip_net = IPNetwork(unicode(net['cidr']))
                ip_version = ip_net.version
            except AddrFormatError:
                msg = ("Network %s: %s is not a valid CIDR."
                       % (net['name'], net['cidr']))
                self.add_error(msg)
                self._valid = False
                self._valid_cidr = False
                return
            else:
                if ip_net.size < 4:
                    msg = ("Network %s: CIDR %s range is too small. It must "
                           "have at least 4 IP addresses in its range." %
                           (net['name'], net['cidr']))
                    self.add_error(msg)
                    self._valid = False
                    self._valid_cidr = False
                    return
                cidr_start = IPAddress(ip_net.first, ip_version) + 1
                cidr_end = IPAddress(ip_net.last, ip_version) - (ip_version == 4)

            # Check gateway address is valid
            if 'gateway-ip' in net:
                gateway_ip = IPAddress(net['gateway-ip'])
                if gateway_ip < cidr_start or gateway_ip > cidr_end:
                    msg = ("Network %s: Gateway IP address %s is not in "
                           "cidr range %s (%s - %s)" %
                           (net['name'], gateway_ip, net['cidr'],
                            cidr_start, cidr_end))
                    self.add_error(msg)
                    self._valid = False

    def _validate_vxlan_net_has_cidr(self, net):
        net_vxlan_tag = 'neutron.networks.vxlan'
        if 'cidr' not in net:
            net_group_name = net.get('network-group', None)
            if net_group_name in self._get_net_groups_with_tag(net_vxlan_tag):
                msg = ("Network group %s has the tag '%s', but its "
                       "network %s has no CIDR. All networks in a network "
                       "group with the tag '%s' should have a CIDR." %
                       (net_group_name, net_vxlan_tag, net['name'], net_vxlan_tag))
                self.add_error(msg)
                self._valid = False

    def _validate_vips_in_net(self, net):
        net_vips = net.get('vips', [])
        net_cidr = net.get('cidr', None)
        if len(net_vips) > 0 and not net_cidr:
            msg = ("Network %s has vips specified but has no "
                   "CIDR.  A network that has vips specified "
                   "should have a CIDR specified as well." %
                   (net['name']))
            self.add_error(msg)
            self._valid = False
            return

        if net_cidr and len(net_vips) > 0:
            network = IPNetwork(unicode(net_cidr))
            for vip in net_vips:
                vip_addr = vip.get('address', None)
                if not vip_addr:
                    msg = ("Network %s has vips specified but no address "
                           "is specified on a vip.  A valid address must "
                           "be specified for a network vip." %
                           (net['name']))
                    self.add_error(msg)
                    self._valid = False
                else:
                    try:
                        addr = IPAddress(vip_addr)
                    except AddrFormatError:
                        msg = ("Network %s vip address %s is not a valid "
                               "address." % (net['name'], vip_addr))
                        self.add_error(msg)
                        self._valid = False
                    else:
                        if addr not in network:
                            msg = ("Network %s vip address %s is not within "
                                   "the network CIDR %s." %
                                   (net['name'], vip_addr, net_cidr))
                            self.add_error(msg)
                            self._valid = False

    def _validate_addresses_in_cidr(self, net):
        if 'cidr' not in net and 'addresses' in net:
            msg = ("Network %s has addresses specified, but it has "
                   "no CIDR.  A valid CIDR must be specified if "
                   "addresses are specified for a network." %
                   (net['name']))
            self.add_error(msg)
            self._valid = False
        elif 'cidr' in net:
            try:
                network = IPNetwork(net['cidr'])
                ip_version = network.version
            except AddrFormatError:
                msg = ("CIDR %s in network %s is not a valid CIDR." %
                       (net['cidr'], net['name']))
                self.add_error(msg)
                self._valid = False
            else:
                cidr_start = IPAddress(network.first, ip_version) + 1
                cidr_end = IPAddress(network.last, ip_version) - (ip_version == 4)
                if 'start-address' in net or 'end-address' in net:
                    msg = ("Network %s: start-address and end-address are "
                           "deprecated.  Instead specify an address range in "
                           "'addresses'" % net['name'])
                    self.add_warning(msg)
                    if 'addresses' not in net:
                        net['addresses'] = []
                    if 'start-address' in net and 'end-address' in net:
                        address_range = net['start-address'] + '-' + net['end-address']
                        net['addresses'].append(address_range)
                    elif 'start-address' in net:
                        net['addresses'].append(net['start-address'] + '-' + str(cidr_end))
                    elif 'end-address' in net:
                        net['addresses'].append(str(cidr_start) + '-' + net['end-address'])
                elif 'addresses' not in net:
                    net['addresses'] = [str(cidr_start) + '-' + str(cidr_end)]
                self._validate_addresses_helper(network, net)

    def _validate_addresses_helper(self, network, net):
        # Keep an IPSet of addresses/ranges that can be checked
        # against for overlaps
        current_set = IPSet()
        for address_list in net['addresses']:
            address = address_list.split('-')
            if len(address) == 1:
                try:
                    ip_addr1 = IPAddress(address[0].strip())
                except AddrFormatError:
                    msg = ("Address %s in network %s is not a valid "
                           "IP address."
                           % (address[0], net['name']))
                    self.add_error(msg)
                    self._valid = False
                else:
                    if ip_addr1 not in network:
                        msg = ("Address %s in network %s is not within "
                               "the specified CIDR %s." %
                               (address[0], net['name'], net['cidr']))
                        self.add_error(msg)
                        self._valid = False
                    elif ip_addr1 not in current_set:
                        current_set.add(ip_addr1)
            else:
                try:
                    ip_addr1 = IPAddress(address[0].strip())
                    ip_addr2 = IPAddress(address[1].strip())
                except AddrFormatError:
                    msg = ("The address range %s in network %s is not "
                           "a range of valid IP addresses." %
                           (address_list, net['name']))
                    self.add_error(msg)
                    self._valid = False
                else:
                    if ip_addr1 > ip_addr2:
                        msg = ("The address range %s specified in network %s "
                               "is invalid.  The specified first address %s "
                               "is greater than the specified last address %s." %
                               (address_list, net['name'], address[0], address[1]))
                        self.add_error(msg)
                        self._valid = False
                    else:
                        iprange = IPRange(ip_addr1, ip_addr2)
                        if iprange not in network:
                            msg = ("Address range %s in network %s is not within "
                                   "the specified CIDR %s." %
                                   (address_list, net['name'], net['cidr']))
                            self.add_error(msg)
                            self._valid = False
                        else:
                            if not current_set.isdisjoint(IPSet(iprange)):
                                msg = ("The address range %s in network %s overlaps "
                                       "with another range or address in the network." %
                                       (address_list, net['name']))
                                self.add_warning(msg)
                            current_set.add(iprange)
        self._ipsets[net['name']] = current_set

    def _validate_vlans(self, net):
        version = float(self.version())
        network_groups = self._create_content(version, "network-groups")
        network_groups = network_groups['network-groups']
        net_vlan_tag = 'neutron.networks.vlan'

        if ('vlanid' not in net and (
                'tagged-vlan' not in net or net['tagged-vlan'])):
            msg = ("Network %s: networks are tagged vlans by default, "
                   "but a vlanid was not set. Please set a vlanid for "
                   "this network or set tagged-vlan: false" % (net['name']))
            self.add_error(msg)
            self._valid = False

        vlan_min, vlan_max = (1, 4094)
        if 'vlanid' in net and not (vlan_min <= net['vlanid'] <= vlan_max):
            msg = ("Network %s: the vlan id %s is not valid. "
                   "It should be an integer in the range [%s, %s]."
                   % (net['name'], net['vlanid'], vlan_min, vlan_max))
            self.add_error(msg)
            self._valid = False

        if 'tagged-vlan' not in net or net['tagged-vlan']:
            network_group_name = net.get('network-group', None)
            for network_group in network_groups:
                if network_group['name'] == network_group_name and (
                        'tags' in network_group):
                    for tag in network_group['tags']:
                        if tag == net_vlan_tag or (
                                type(tag) is dict and net_vlan_tag in tag):
                            msg = ("Network %s is a tagged vlan, but its "
                                   "network group %s has the tag '%s', making "
                                   "it a provider vlan network. Provider "
                                   "vlans should not be associated with "
                                   "tagged vlan networks." %
                                   (net['name'], network_group_name,
                                    net_vlan_tag))
                            self.add_error(msg)
                            self._valid = False
                            break
                    break

    def _validate_gateways(self, networks):
        version = float(self.version())
        network_group_data = self._create_content(version, "network-groups")
        network_groups = {}
        for grp in network_group_data['network-groups']:
            network_groups[grp['name']] = grp

        # Build a list of how many networks there are in each group
        net_group_counts = {}
        for net in networks:
            if net.get('network-group', None):
                if net['network-group'] not in net_group_counts:
                    net_group_counts[net['network-group']] = 0
                net_group_counts[net['network-group']] += 1

        for net in networks:

            if net.get('network-group', None):
                # Check Group exists
                if net['network-group'] not in network_groups:
                    msg = ("Network group %s referenced by network %s "
                           "is not defined" % (net['network-group'], net['name']))
                    self.add_error(msg)
                    self._valid = False
                    continue

                net_group = network_groups[net['network-group']]

                # If group has routes check we have gateway
                if 'routes' in net_group and 'gateway-ip' not in net:
                    msg = ("Network %s is part of a network group that provides "
                           "routes, but it does not have a 'gateway-ip' value."
                           % (net['name']))
                    self.add_error(msg)
                    self._valid = False
                    continue

                # If there are more than one network in the group then we
                # need the gateway for routing within the group
                if net_group_counts[net['network-group']] > 1 and 'gateway-ip' not in net:
                    msg = ("Network %s is part of a network group with more than "
                           "one network, but it does not have a 'gateway-ip' value."
                           % (net['name']))
                    self.add_error(msg)
                    self._valid = False

    def _get_net_groups_with_tag(self, checked_tag):
        version = float(self.version())
        net_groups = self._create_content(version, "network-groups")
        net_groups = net_groups['network-groups']
        all_net_groups_with_tag = set()

        for net_group in net_groups:
            if 'tags' in net_group:
                for tag in net_group['tags']:
                    if tag == checked_tag or (
                            type(tag) is dict and checked_tag in tag):
                        all_net_groups_with_tag.add(net_group['name'])
                        break
        return all_net_groups_with_tag

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
        return ['network-groups-2.0']
