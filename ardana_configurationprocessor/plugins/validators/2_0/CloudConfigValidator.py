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

from ardana_configurationprocessor.cp.model.ValidatorPlugin \
    import ValidatorPlugin
from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog


LOG = logging.getLogger(__name__)


class CloudConfigValidator(ValidatorPlugin):
    def __init__(self, instructions, config_files):
        super(CloudConfigValidator, self).__init__(
            2.0, instructions, config_files,
            'cloudconfig-2.0')
        LOG.info('%s()' % KenLog.fcn())
        self._is_built = False
        self._path = instructions['cloud_input_path']

    def validate(self):
        LOG.info('%s()' % KenLog.fcn())
        version = float(self.version())

        cloud_data = self.validate_parsing()
        services = self._get_dict_from_config_value(version, 'services')

        audit_settings = {'audit-dir': '/var/audit',
                          'default': 'disabled',
                          'enabled-services': [],
                          'disabled-services': []}
        audit_settings.update(cloud_data['cloud'].get('audit-settings', {}))

        self._validate_audit(audit_settings, services)

    def _validate_audit(self, audit_settings, services):

        def _validate_service(name, context):
            if name not in services:
                msg = ("Unknown service '%s' in %s" %
                       (name, context))
                self.add_warning(msg)

        if audit_settings['default'] not in ['enabled', 'disabled']:
            msg = ("Value of audit-settings.default must be 'enabled' "
                   "or 'disabled'")
            self.add_error(msg)

        if not audit_settings['audit-dir']:
            msg = ("Value of audit-settings.audit-dir can not be empty")
            self.add_error(msg)

        for service_list in ['enabled-services', 'disabled-services']:
            for name in audit_settings[service_list]:
                _validate_service(name, 'audit-settings.%s' % service_list)

    @property
    def instructions(self):
        return self._instructions

    def get_dependencies(self):
        return []
