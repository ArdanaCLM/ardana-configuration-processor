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


class RingSpecificationsValidator(ValidatorPlugin):
    def __init__(self, instructions, config_files):
        super(RingSpecificationsValidator, self).__init__(
            2.0, instructions, config_files,
            'ring-specifications-2.0')
        LOG.info('%s()' % KenLog.fcn())
        self._valid = True

    def validate(self):
        LOG.info('%s()' % KenLog.fcn())

        version = float(self.version())

        input = self._create_content(version, 'ring-specifications')
        if input:
            if len(input['ring-specifications']) > 1:
                msg = 'Multiple ring-specifications are not supported. ' \
                      'Use configuration-data instead.'
                self.add_error(msg)
                self._valid = False
            input2 = self._create_content(version, 'control-planes')
            if len(input2['control-planes']) > 1:
                msg = 'Do not use ring-specifications with multiple control-planes, ' \
                      'use configuration-data instead.'
                self.add_error(msg)
                self._valid = False
            return self._valid and self.validate_schema(input, 'ring_specifications')
        else:
            return self._valid

    @property
    def instructions(self):
        return self._instructions

    def get_dependencies(self):
        return ['control-planes-2.0']
