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

from ardana_configurationprocessor.cp.model.ValidatorPlugin \
    import ValidatorPlugin
from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog


LOG = logging.getLogger(__name__)


class NicDeviceFamiliesValidator(ValidatorPlugin):
    def __init__(self, instructions, config_files):
        super(NicDeviceFamiliesValidator, self).__init__(
            2.0, instructions, config_files,
            'nic-device-families-2.0')
        self._valid = False
        LOG.info('%s()' % KenLog.fcn())

    def validate(self):
        LOG.info('%s()' % KenLog.fcn())

        version = float(self.version())

        input = self._create_content(version, "nic-device-families")
        # Nic device families are optional
        if not input:
            return True

        self._valid = self.validate_schema(input, "nic_device_family")
        if self._valid:
            nic_dev_families = input['nic-device-families']
            self._validate_names(nic_dev_families)

        LOG.info('%s()' % KenLog.fcn())
        return self._valid

    def _validate_names(self, nic_device_families):
        #
        # Check each family is only defined once
        #
        names = set()
        for dev_family in nic_device_families:
            if dev_family['name'] in names:
                msg = ("NIC Device Family %s is defined more than once" %
                       (dev_family['name']))
                self.add_error(msg)
                self._valid = False
            else:
                names.add(dev_family['name'])

    @property
    def instructions(self):
        return self._instructions

    def get_dependencies(self):
        return []
