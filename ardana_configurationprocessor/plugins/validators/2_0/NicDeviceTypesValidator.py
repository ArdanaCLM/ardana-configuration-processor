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


class NicDeviceTypesValidator(ValidatorPlugin):
    def __init__(self, instructions, config_files):
        super(NicDeviceTypesValidator, self).__init__(
            2.0, instructions, config_files,
            'nic-device-types-2.0')
        self._valid = False
        LOG.info('%s()' % KenLog.fcn())

    def validate(self):
        LOG.info('%s()' % KenLog.fcn())

        version = float(self.version())

        input = self._create_content(version, "nic-device-types")
        # Nic device types are optional
        if not input:
            return True

        self._valid = self.validate_schema(input, "nic_device_type")
        if self._valid:
            nic_dev_types = input['nic-device-types']
            self._validate_names(nic_dev_types)
            self._validate_device_ids(nic_dev_types)
            self._validate_families(nic_dev_types)

        LOG.info('%s()' % KenLog.fcn())
        return self._valid

    def _validate_names(self, nic_device_types):
        #
        # Check each device type is only defined once
        #
        names = set()
        for dev_type in nic_device_types:
            if dev_type['name'] in names:
                msg = ("NIC Device Type %s is defined more than once" %
                       (dev_type['name']))
                self.add_error(msg)
                self._valid = False
            else:
                names.add(dev_type['name'])

    def _validate_device_ids(self, nic_device_types):
        #
        # Check each device_id is only defined once
        #
        device_ids = {}
        for dev_type in nic_device_types:
            if dev_type['device-id'] not in device_ids:
                device_ids[dev_type['device-id']] = []
            device_ids[dev_type['device-id']].append(dev_type['name'])

        for id, dev_types in device_ids.iteritems():
            if len(dev_types) > 1:
                msg = ("NIC Device ID '%s' is defined for more than "
                       "one device type: %s" %
                       (id, str(dev_types).strip('[]')))
                self.add_error(msg)
                self._valid = False

    def _validate_families(self, nic_device_types):

        version = float(self.version())
        families = self._get_dict_from_config_value(version, 'nic-device-families')
        if not families:
            families = []

        for dev_type in nic_device_types:
            if dev_type['family'] not in families:
                msg = ("NIC Device Type '%s': family '%s' is not defined." %
                       (dev_type['name'], dev_type['family']))
                self.add_error(msg)
                self._valid = False

    @property
    def instructions(self):
        return self._instructions

    def get_dependencies(self):
        return ['nic-device-families-2.0']
