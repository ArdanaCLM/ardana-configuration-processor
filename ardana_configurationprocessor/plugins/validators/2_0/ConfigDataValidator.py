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

from copy import deepcopy

from ardana_configurationprocessor.cp.model.ValidatorPlugin \
    import ValidatorPlugin
from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog
from ardana_configurationprocessor.cp.lib.DataTransformer \
    import DataTransformer

from netaddr import IPNetwork, IPAddress, AddrFormatError

LOG = logging.getLogger(__name__)


class ConfigDataValidator(ValidatorPlugin):
    def __init__(self, instructions, config_files):
        super(ConfigDataValidator, self).__init__(
            2.0, instructions, config_files,
            'config-data-2.0')
        LOG.info('%s()' % KenLog.fcn())

    def validate(self):
        LOG.info('%s()' % KenLog.fcn())
        version = float(self.version())

        input = self._create_content(version, "configuration-data")
        # Configuration data is optional
        if not input:
            return

        schema_valid = self.validate_schema(input, "configuration-data")

        if schema_valid:
            config_data = input.get('configuration-data', [])
            services = self._get_dict_from_config_value(version, 'services')
            self._networks = self._get_dict_from_config_value(version, 'networks')
            self._network_groups = self._get_dict_from_config_value(version, 'network-groups')

            self._validate_names(config_data)
            for data in config_data:
                self._validate_services(data, services)
                for service_name in data.get('services', []):
                    validator = "_validate_%s_data" % service_name
                    if hasattr(self, validator):
                        getattr(self, validator)(data, config_data)

        LOG.info('%s()' % KenLog.fcn())

    def _validate_names(self, config_data):

        names = set()
        for data in config_data:
            if data['name'] in names:
                msg = ("Duplicate name '%s' for configuration-data" %
                       (data['name']))
                self.add_error(msg)
            names.add(data['name'])

    def _validate_services(self, data, services):

        for service_name in data.get('services', []):
            if service_name not in services:
                msg = ("Unrecognised service name '%s' in "
                       "configuration-data '%s'." %
                       (service_name, data['name']))
                self.add_warning(msg)

    #
    # Validation function for swift configuration data (rings)
    #
    def _validate_swift_data(self, config_data, all_config_data):
        version = float(self.version())
        input = self._create_content(version, "ring-specifications")
        if input:
            msg = "Using both ring-specifications and Swift configuration data - " \
                  "please remove the ring-specifications"
            self.add_error(msg)

        data = config_data['data']
        name = config_data['name']
        if 'control_plane_rings' not in data:
            msg = "No 'control_plane_rings' specified"
            self.add_error(msg)
            return

        schema_valid = self.validate_schema(data['control_plane_rings'], 'ring_config_data')

        if not schema_valid:
            msg = "Swift configuration data element '%s' is not valid" % name
            self.add_error(msg)

    #
    # Validation function for DCN data
    #
    def _validate_dcn_data(self, config_data, all_config_data):
        required = [
            'vsd_host_name',
            'vsd_user',
            'vsd_passwd',
            'vsc_active_ip',
        ]

        optional = [
            'vsd_cms_id',
            'vsc_passive_ip',
            'vsc_mgmt_net',
            'vsc_data_net',
            'vsc_image_name',
            'vsc_user_name',
            'vsc_user_pass',
            'vsc_start_delay',
            'vsc_start_timeout',
            'dns_domain_name',
        ]

        req_str_values = [
            'vsd_host_name',
            'vsd_user',
            'vsd_passwd',
            'vsc_active_ip',
            'vsd_cms_id',
            'vsc_passive_ip',
            'vsc_mgmt_net',
            'vsc_data_net',
            'vsc_image_name',
            'vsc_user_name',
            'vsc_user_pass',
            'dns_domain_name',
        ]

        req_int_values = [
            'vsc_start_delay',
            'vsc_start_timeout',
        ]

        all_keys = required + optional

        cfg_data = config_data.get('data', {})
        cfg_name = config_data.get('name', 'unnamed')

        for key in required:
            # add error for missing required parameters
            if key not in cfg_data:
                msg = ("in configuration data '%s' - "
                       "missing required parameter: '%s'"
                       % (cfg_name, key))
                self.add_error(msg)
            # add error for empty values in required parameters
            elif cfg_data[key] in (None, ''):
                msg = ("in configuration data '%s' - "
                       "value for required parameter '%s' is missing"
                       % (cfg_name, key))
                self.add_error(msg)

        for key, value in cfg_data.items():
            # warn about unrecognized parameters
            if key not in all_keys:
                msg = ("in configuration data '%s' - "
                       "skipping unrecognized parameter: '%s'"
                       % (cfg_name, key))
                self.add_warning(msg)
                continue

            # add error for values that aren't strings
            if key in req_str_values and not isinstance(value, str):
                msg = ("in configuration data '%s' - "
                       "parameter '%s' expects a string value"
                       % (cfg_name, key))
                self.add_error(msg)

            if key in req_int_values and not isinstance(value, int):
                msg = ("in configuration data '%s' - "
                       "parameter '%s' expects an integer value"
                       % (cfg_name, key))
                self.add_error(msg)

            if (key in ('vsc_active_ip', 'vsc_passive_ip') and
                    not self._is_valid_ip_address(value)):
                msg = ("in configuration data '%s' - "
                       "value for '%s' is not a valid IP address: '%s'"
                       % (cfg_name, key, value))
                self.add_error(msg)

            if (key in ('vsc_mgmt_net', 'vsc_data_net') and
                    value not in self._network_groups):
                msg = ("in configuration data '%s' - "
                       "value for '%s' ('%s') does not match any network group "
                       "in the model" % (cfg_name, key, value))
                self.add_error(msg)

            if (key in ('vsc_start_delay', 'vsc_start_timeout') and
                    isinstance(value, int) and value <= 0):
                msg = ("in configuration data '%s' - "
                       "value for parameter '%s' must be greater than 0"
                       % (cfg_name, key))
                self.add_error(msg)

    # Validation function for windriver configuration data
    #
    def _validate_windriver_data(self, config_data, all_config_data):
        schema_valid = self.validate_schema(config_data['data'], 'windriver_config_data')

        if not schema_valid:
            msg = "Windriver configuration data element '%s' is not valid" % config_data['name']
            self.add_error(msg)
            return

        version = float(self.version())
        networks = self._create_content(version, "networks")

        for l_intf in config_data['data']['property-groups']['properties']['logical-interface']:
            net_list = []
            for net_info in l_intf['networks']:
                found = False
                for net in networks['networks']:
                    if net_info['name'] == net['name']:
                        net_elem = deepcopy(net)
                        if 'dynamic-allocation' in net_info:
                            net_elem['dynamic_allocation'] = net_info['dynamic-allocation']
                        net_elem['start_address'], net_elem['end_address'] = \
                            net_elem['addresses'][0].split('-')
                        del net_elem['addresses']
                        net_list.append(net_elem)
                        found = True
                if not found:
                    msg = ("Network '%s' referenced in WindRiver configuration data object '%s'"
                           "is not present in the networks input" %
                           (net_info['name'], config_data['name']))
                    self.add_error(msg)
            l_intf['networks'] = net_list
        config_data['data'] = DataTransformer(config_data).all_output('-', '_')

    #
    # Validation function for neutron configuration data
    #
    def _validate_neutron_data(self, config_data, all_config_data):

        def check_item_warn(item, search, msg_data1, msg_data2):
            if item not in search:
                msg = ("in configuration data '%s'. "
                       "Skipping unrecognized entry: '%s' "
                       % (msg_data1, msg_data2))
                self.add_warning(msg)
                return False
            return True

        def check_name(key, key_value, cfg_name):
            # Verify that the name is not 'name' as this would confuse
            # the provider_net_create playbook.
            if key == 'name'and key_value == 'name':
                msg = ("in configuration data '%s'. "
                       "The name can not be called 'name'"
                       % (cfg_name))
                self.add_error(msg)

        def error_missing(cfg_name, net_name, req):
            msg = ("in configuration data '%s', network: '%s' "
                   "Missing required parameter: '%s'"
                   % (cfg_name, net_name, req))
            self.add_error(msg)

        def error_sub_missing(cfg_name, net_name, req, name):
            msg = ("in configuration data '%s', network: '%s' "
                   "Missing '%s' which is a required parameter for '%s'"
                   % (cfg_name, net_name, req, name))
            self.add_error(msg)

        def warn_unknown(cfg_name, net_name, sub_key):
            msg = ("in configuration data '%s'. network: '%s' "
                   "Skipping unrecognized entry '%s' "
                   % (cfg_name, net_name, sub_key))
            self.add_warning(msg)

        # generator for searching thru subkeys
        def next_subkey(key, key_value):
            # get each in subkeys list
            # e.g. alloc_pools, host_routes, provider
            for subkey in subkeys:
                # does this key require subkeys
                # e.g. alloc_pools requires start,end
                if key in subkey['name']:
                    # get each subkey in opt list
                    # e.g. the start, end in alloc_pools
                    for val in key_value:
                        yield (val, subkey['name'], subkey['opt'])

        required = ['name',
                    'provider',
                    'cidr']

        optional = ['shared',
                    'allocation_pools',
                    'host_routes',
                    'gateway_ip',
                    'no_gateway',
                    'enable_dhcp']

        req_ap = ['start', 'end']
        req_hr = ['nexthop', 'destination']
        req_pr = ['physical_network', 'network_type']
        opt_pr = ['segmentation_id']
        opt_hr = ['external']

        all_keys = required + optional
        all_subkeys = req_ap + req_hr + req_pr + opt_pr + opt_hr

        subkeys = [{'name': 'allocation_pools', 'opt': req_ap},
                   {'name': 'host_routes', 'opt': req_hr},
                   {'name': 'provider', 'opt': req_pr}]

        cfg_data = config_data.get('data', [])
        cfg_name = config_data.get('name', 'unnamed')

        # Its possible to have Neutron configuration data that only
        # defines network tags
        if not cfg_data:
            return

        # Warn about unrecognized sections in this neutron service
        for key in cfg_data:
            if not check_item_warn(key,
                                   ['neutron_provider_networks',
                                    'neutron_external_networks',
                                    'vlan_transparent'],
                                   cfg_name, key):
                continue

        # Verify the neutron_provider_networks section
        # e.g (in trove entry, cue entry, etc.)
        for npdata in cfg_data.get('neutron_provider_networks', []):

            if 'name' not in npdata:
                # will already have logged this as an error
                continue

            # Messages need the network name
            net_name = npdata.get('name', 'unnamed')

            # Verify the required keys are present
            for req in required:
                if req not in npdata:
                    error_missing(cfg_name, net_name, req)

            # Check every entry
            for key in npdata:

                key_value = npdata[key]

                # Warn about unrecognized entry
                if key not in all_keys:
                    warn_unknown(cfg_name, net_name, key)

                # Verify valid name
                check_name(key, key_value, cfg_name)

                # Verify required subkeys
                for (item, name, opt) in next_subkey(key, key_value):

                    # Verify required elements exist
                    for req in opt:
                        if req not in item:
                            error_sub_missing(cfg_name, net_name, req, name)

                    # Warn about unrecognized entry
                    for sub_key in item:
                        if sub_key not in all_subkeys:
                            warn_unknown(cfg_name, net_name, sub_key)

            # Check the network details
            self._validate_neutron_provider_net(net_name, npdata, config_data)

        if cfg_data.get('vlan_transparent', False):
            version = float(self.version())
            interface_input = self._create_content(version, "interface-models")
            interface_models = interface_input['interface-models']
            valid = any([model for model in interface_models if
                         'dpdk-devices' in model])
            if not valid:
                msg = ("Error in neutron configuration data : "
                       "vlan_transparent is only supported with DPDK "
                       "and there are no dpdk-devices defined in the "
                       "interface-models.")
                self.add_error(msg)
                self._valid = False

    #
    # Validation function for ironic configuration data
    #
    def _validate_ironic_data(self, config_data, all_config_data):

        if 'cleaning_network' in config_data['data']:
            # Must be a name of a network in a neutron config data set
            cleaning_net = config_data['data']['cleaning_network']
            if not self._valid_neutron_provider_net_exists(cleaning_net, all_config_data):
                msg = ("Error in ironic configuration data '%s': "
                       "neutron cleaning network '%s' not defined in "
                       "neutron configuration data" % (config_data['name'], cleaning_net))
                self.add_error(msg)

    #
    # A helper function to check that a provider network name has
    # been defined in a neutron network configuration data object
    #
    def _valid_neutron_provider_net_exists(self, net_name, all_config_data):

        for config in all_config_data:
            if 'neutron' in config['services']:
                neutron_data = config['data']
                for net in neutron_data.get('neutron_provider_networks', []):
                    if net.get('name') == net_name:
                        return True
        return False

    def _is_valid_ip_address(self, addr):
        try:
            IPAddress(addr)
        except AddrFormatError:
            return False
        return True

    #
    # Validate the network deatils of a provider network.  Ideally this would be
    # shared somehow with the rest of the network validation.
    #
    def _validate_neutron_provider_net(self, context, net, config_data):

        def _valid_ip_address(context, addr):
            is_valid = self._is_valid_ip_address(addr)
            if not is_valid:
                msg = ("Provider Network %s: '%s' is not a valid IP address." %
                       (context, addr))
                self.add_error(msg)
                self._valid = False
            return is_valid

        def _validate_net_type(context, type):
            valid_provider_net_types = ['vlan', 'flat', 'local']
            if type not in valid_provider_net_types:
                msg = ("Provider Network %s: '%s' is not a valid network type. "
                       "It must be one of %s"
                       % (context, type, valid_provider_net_types))
                self.add_error(msg)
                self._valid = False

        def _valid_cidr(context, cidr):
            is_valid = True
            _start = None
            _end = None
            try:
                ip_net = IPNetwork(unicode(net['cidr']))
                ip_version = ip_net.version
                _start = IPAddress(ip_net.first, ip_version) + 1
                _end = IPAddress(ip_net.last, ip_version) - (ip_version == 4)
            except AddrFormatError:
                msg = ("Provider Network %s: '%s' is not a valid CIDR."
                       % (context, cidr))
                self.add_error(msg)
                self._valid = False
                is_valid = False
            return is_valid, _start, _end

        for provider in net.get('provider', []):
            _validate_net_type(context, provider['network_type'])
            physnet_context = ("provider network '%s' defined in configuration-data '%s'" %
                               (context, config_data['name']))
            if 'physical_network' in provider:
                self._validate_physnet(physnet_context, provider['physical_network'], config_data)

        if 'cidr' in net:
            valid_cidr, cidr_start, cidr_end = _valid_cidr(context, net['cidr'])

        # Check gateway address is valid
        if 'gateway_ip' in net:
            gw_context = "%s gateway-ip" % (context)
            if _valid_ip_address(gw_context, net['gateway_ip']) and valid_cidr:
                gateway_ip = IPAddress(net['gateway_ip'])
                if gateway_ip < cidr_start or gateway_ip > cidr_end:
                    msg = ("Provider Network %s: Gateway IP address '%s' is not in "
                           "cidr range %s (%s - %s)" %
                           (context, gateway_ip, net['cidr'],
                            cidr_start, cidr_end))
                    self.add_error(msg)
                    self._valid = False

        # Check Allocation Pools are valid
        pool_context = "%s allocation pool" % (context)
        for pool in net.get('allocation_pools', []):
            for x in ['start', 'end']:
                if x not in pool:
                    # Will have already loged this as an error
                    continue
                if _valid_ip_address(pool_context, pool[x]) and valid_cidr:
                    ip = IPAddress(pool[x])
                    if ip < cidr_start or ip > cidr_end:
                        msg = ("Provider Network %s: IP address '%s' is not in "
                               "cidr range %s (%s - %s)" %
                               (pool_context, ip, net['cidr'],
                                cidr_start, cidr_end))
                        self.add_error(msg)
                        self._valid = False

        # Check the route is to a valid network
        for route in net.get('host_routes', []):
            route_context = "%s host_routes" % (context)
            dest_valid = False
            route_cidr_valid, _, _ = _valid_cidr(route_context, route['destination'])
            if route_cidr_valid:
                for net_name, net_data in self._networks.iteritems():
                    if route['destination'] == net_data.get('cidr'):
                        dest_valid = True
                        break
                if not dest_valid and not route.get('external', False):
                    msg = ("Provider network %s: destination '%s' is not defined as "
                           "a Network in the input model. Add 'external: True' to "
                           "this host_route if this is for an external network." %
                           (route_context, route['destination']))
                    self.add_error(msg)
                    self._valid = False

    #
    # We can't validate if a physnet is defined or not yet as we need to
    # have expanded all of the tags and that happens in the NetworkTagsGenerator,
    # so instead we create a list of names that need to be validated
    #
    def _validate_physnet(self, context, physnet, config_data):

        if 'neutron-provider-nets' not in config_data:
            config_data['neutron-provider-nets'] = []
        config_data['neutron-provider-nets'].append({'physnet': physnet,
                                                     'context': context})

    @property
    def instructions(self):
        return self._instructions

    def get_dependencies(self):
        return ['network-groups-2.0', 'networks-2.0', 'interface-models-2.0']
