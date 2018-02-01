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


LOG = logging.getLogger(__name__)


class ServiceValidator(ValidatorPlugin):
    def __init__(self, instructions, config_files):
        super(ServiceValidator, self).__init__(
            2.0, instructions, config_files,
            'services-2.0')
        LOG.info('%s()' % KenLog.fcn())

        self._valid = True

    def validate(self):
        LOG.info('%s()' % KenLog.fcn())
        version = float(self.version())

        input = self._create_content(version, "services")
        self._valid = self.validate_schema(input, "service")
        if not self._valid:
            return self._valid

        service_list = self._get_config_value(version, 'services')
        self._validate_names(service_list)
        self._validate_relationship_vars(service_list)

        LOG.info('%s()' % KenLog.fcn())
        return self._valid

    #
    # Check for duplicate names and mnemonics
    #
    def _validate_names(self, services):

        service_names = set()
        mnemonics = {}

        for service in services:
            if service['name'] in service_names:
                msg = ("service '%s' is defined more than once." %
                       (service['name']))
                self.add_error(msg)
                self._valid = False
            else:
                service_names.add(service['name'])

                if service['mnemonic'] not in mnemonics:
                    mnemonics[service['mnemonic']] = []
                mnemonics[service['mnemonic']].append("%s" % service['name'])

        for mnemonic, service_list in mnemonics.iteritems():
            if len(service_list) > 1:
                msg = ("menmonic '%s' is defined for more that one service: %s" %
                       (mnemonic, str(service_list).strip('[]')))
                self.add_error(msg)
                self._valid = False

    def _is_valid_ansible_var(self, var_name):
        valid_var = False
        if var_name:
            if re.match('[A-Za-z_]+$', var_name[0:1]) is not None:
                valid_var = re.match('[\w]+$', var_name[1:]) is not None
        return valid_var

    def _validate_relationship_vars(self, services):
        for service in services:
            for consumes in service.get('consumes-services', []):
                for rltnshp_var in consumes.get('relationship-vars', []):
                    for vars in rltnshp_var.get('vars', {}).values():
                        for var in vars:
                            var_name = var.get('name', '')
                            if not self._is_valid_ansible_var(var_name):
                                self.add_error(
                                    "Invalid ansible variable name '%s', "
                                    "service-name:%s, "
                                    "relationship-vars-name:%s" %
                                    (var_name,
                                     service.get('name', '*undefined*'),
                                     rltnshp_var.get('name', '*undefined*')))

    @property
    def instructions(self):
        return self._instructions

    def get_dependencies(self):
        return []
