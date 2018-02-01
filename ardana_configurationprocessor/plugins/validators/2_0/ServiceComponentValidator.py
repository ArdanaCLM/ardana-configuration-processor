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
import re

from ardana_configurationprocessor.cp.model.ValidatorPlugin \
    import ValidatorPlugin
from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog

from copy import deepcopy

LOG = logging.getLogger(__name__)


class ServiceComponentValidator(ValidatorPlugin):
    def __init__(self, instructions, config_files):
        super(ServiceComponentValidator, self).__init__(
            2.0, instructions, config_files,
            'service-components-2.0')
        LOG.info('%s()' % KenLog.fcn())

        self._valid = True

    def validate(self):
        LOG.info('%s()' % KenLog.fcn())
        version = float(self.version())

        input = self._create_content(version, "service-components")
        self._valid = self.validate_schema(input, "service_component")
        if not self._valid:
            return self._valid

        component_list = input['service-components']

        # Add any aliases.  Alias allow us to change the name of a component
        # without breaking compatibility with any existing input models
        aliased_components = []
        for component in component_list:
            for alias in component.get('aliases', []):
                a_comp = deepcopy(component)
                a_comp['name'] = alias
                a_comp['alias-for'] = component['name']
                del a_comp['aliases']
                aliased_components.append(a_comp)
        component_list.extend(aliased_components)

        service_list = self._get_config_value(version, 'services')
        services = {}
        for service in service_list:
            services[service['name']] = service

        self._validate_names(services, component_list)

        components = {}
        components_by_mnemonic = {}
        for comp in component_list:
            components[comp['name']] = comp
            if 'alias-for' not in comp:
                components_by_mnemonic[comp['mnemonic']] = comp

        self._validate_services(services, components)

        for c_name, component in components.iteritems():
            self._check_endpoint_roles(component)
            self._check_port_range(component)
            self._check_port_attributes(component)
            self._check_supported_resource_allocations(component)
            self._check_config_set(component)
            self._check_relationship_vars(component)
            self._validate_consumers(component, services)

        LOG.info('%s()' % KenLog.fcn())
        return self._valid

    #
    # Check for duplicate names and mnemonics
    #
    def _validate_names(self, services, components):

        component_names = set()
        mnemonics = {}

        for service_name, service in services.iteritems():
            if service['mnemonic'] not in mnemonics:
                mnemonics[service['mnemonic']] = []
            mnemonics[service['mnemonic']].append("%s(service)" % service['name'])

        for comp in components:
            if comp['name'] in component_names:
                msg = ("service-component '%s' is defined more than once." %
                       (comp['name']))
                self.add_error(msg)
                self._valid = False
            else:
                component_names.add(comp['name'])

                # Don't inclued aliases in the mnemonic check
                if 'alias-for' not in comp:
                    if comp['mnemonic'] not in mnemonics:
                        mnemonics[comp['mnemonic']] = []
                    mnemonics[comp['mnemonic']].append("%s(component)" % comp['name'])

        for mnemonic, comp_list in mnemonics.iteritems():
            if len(comp_list) > 1:
                msg = ("menmonic '%s' is defined multiple times: %s" %
                       (mnemonic, str(comp_list).strip('[]')))
                self.add_error(msg)
                self._valid = False

    #
    # Make sure that each component is part of a service
    #
    def _validate_services(self, services, components):

        for comp_name, comp in components.iteritems():
            if 'service' in comp:
                if comp['service'] not in services:
                    msg = ("Unknown service '%s' in service component '%s'." %
                           (comp['service'], comp_name))
                    self.add_error(msg)
                    self._valid = False

        # Map using components element in service - deprecated
        for service_name, service in services.iteritems():
            service_comp = []
            for resource_type, data in service.get('components', {}).iteritems():
                for name in data:
                    if 'service' not in components[name]:
                        components[name]['service'] = service['name']
                        service_comp.append(name)
            if service_comp:
                msg = ("Service '%s' is using a deprecated 'components' defintion."
                       "Each of the following components should instead include "
                       "a \"service: %s\" statement" %
                       (service_name, str(service_comp).strip('[]')))
                self.add_warning(msg)

        # Make sure all components have a service
        for comp_name, comp in components.iteritems():
            if 'service' not in comp:
                comp['service'] = 'foundation'
                msg = ("Component '%s' is not defined as being part of a service "
                       "and so it has been added to the 'foundation' service" %
                       (comp_name))
                self.add_warning(msg)

        # Add a list of components to each service
        for comp_name, comp in components.iteritems():
            service_name = comp['service']
            if service_name not in services:
                continue
            if 'component-list' not in services[service_name]:
                services[service_name]['component-list'] = []
            services[service_name]['component-list'].append(comp_name)

    def _check_relationship_vars(self, component):
        for consumes_service in component.get('consumes-services', []):
            for rltnshp_var in consumes_service.get('relationship-vars', []):
                var_name = rltnshp_var.get('name', '')
                if not self._is_valid_ansible_var(var_name):
                    service_name = consumes_service.get('service-name',
                                                        '*undefined*')
                    self.add_error(
                        "Invalid relationship variable name '%s', "
                        "mnemonic:%s, service-name:%s" %
                        (var_name, component['mnemonic'], service_name))

    #
    # Check that the lists of multi-consumenrs and single-consumers are valid
    #
    def _validate_consumers(self, component, services):

        for service_name in component.get('multi-consumers', {}).get('allowed', []):
            if service_name not in services:
                msg = ("Unknown service '%s' in multi-consumers allowed list for "
                       "component '%s'" %
                       (service_name, component['name']))
                self.add_error(msg)
                self._valid = False

        for service_name in component.get('multi-consumers', {}).get('blocked', []):
            if service_name not in services:
                msg = ("Unknown service '%s' in multi-consumers blocked list for "
                       "component '%s'" %
                       (service_name, component['name']))
                self.add_error(msg)
                self._valid = False

    #
    # Check that no endpoints share a role
    #
    def _check_endpoint_roles(self, component):

        roles = set()
        for endpoint in component.get('endpoints', []):
            for role in endpoint.get('roles', []):
                if role in roles:
                    msg = ("Component %s has the same role defined for more "
                           "than one endpoint: %s" %
                           (component['name'], role))
                    self.add_error(msg)
                    self._valid = False
                else:
                    roles.add(role)

    #
    # Check that any endpoint specifying a port range isn't a vip
    #
    def _check_port_range(self, component):

        for endpoint in component.get('endpoints', []):
            if endpoint.get('has-vip') and ':' in str(endpoint['port']):
                msg = ("Component %s has an invalid port value '%s' - Can't "
                       "have a port range when has-vip is true" %
                       (component['name'], endpoint['port']))
                self.add_error(msg)
                self._valid = False

    #
    # Check additional port attributes
    #   - vip-port can only be specified for a vip
    #   - vip-tls-port can on;y be specified for a vip
    #   - tls-port can onlt be specified for a non vip
    #   - tls-port can only be specifed if tls-terminator is False
    #
    def _check_port_attributes(self, component):

        for endpoint in component.get('endpoints', []):
            if not endpoint.get('has-vip', False):
                if 'vip-port' in endpoint:
                    msg = ("Component %s port '%s' - Can't set vip-port "
                           "when has-vip is false." %
                           (component['name'], endpoint['port']))
                    self.add_error(msg)
                    self._valid = False

                if 'vip-tls-port' in endpoint:
                    msg = ("Component %s port '%s' - Can't set vip-tls-port "
                           "when has-vip is false." %
                           (component['name'], endpoint['port']))
                    self.add_error(msg)
                    self._valid = False

                if 'vip-options' in endpoint:
                    msg = ("Component %s port '%s' - Can't set vip-options "
                           "when has-vip is false." %
                           (component['name'], endpoint['port']))
                    self.add_error(msg)
                    self._valid = False

            if 'tls-port' in endpoint:
                # We haven't added processing for the combination of "tls-port"
                # and 'has-vip' yet.
                if endpoint.get('has-vip', False):
                    msg = ("Component %s port '%s' - Can't set tls-port "
                           "when has-vip is true." %
                           (component['name'], endpoint['port']))
                    self.add_error(msg)
                    self._valid = False

                # We haven't added processing for the combination of "tls-port"
                # and a tls terminator yet.
                if endpoint.get('tls-terminator', True):
                    msg = ("Component %s port '%s' - Can't set tls-port "
                           "when tls-terminator is true." %
                           (component['name'], endpoint['port']))
                    self.add_error(msg)
                    self._valid = False

    #
    # Check supprorted resource allocations
    #
    def _check_supported_resource_allocations(self, component):
        supported_allocations = component.get('supported-resource-allocations', {})
        if supported_allocations:
            if (supported_allocations.get('cpu', False) and
                    'cpu-roles' not in supported_allocations):
                msg = ("Component %s supports cpu allocations but does not "
                       "define a list of cpu roles" %
                       (component['name']))
                self.add_error(msg)
                self._valid = False

    def _is_valid_ansible_var(self, var_name):
        valid_var = False
        if var_name:
            if re.match('[A-Za-z_]+$', var_name[0:1]) is not None:
                valid_var = re.match('[\w]+$', var_name[1:]) is not None
        return valid_var

    def _check_config_set(self, component):
        for config_set in component.get('config-set', []):
            for ansible_var in config_set.get('ansible-vars', []):
                var_name = ansible_var.get('name', '')
                if not self._is_valid_ansible_var(var_name):
                    self.add_error(
                        "Invalid config-set variable name '%s'" % var_name)

    @property
    def instructions(self):
        return self._instructions

    def get_dependencies(self):
        return ['services-2.0']
