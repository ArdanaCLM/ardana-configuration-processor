#
# (c) Copyright 2015 Hewlett Packard Enterprise Development LP
# (c) Copyright 2017 SUSE LLC
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


class PassThroughValidator(ValidatorPlugin):
    def __init__(self, instructions, config_files):
        super(PassThroughValidator, self).__init__(
            2.0, instructions, config_files,
            'pass-through-2.0')
        LOG.info('%s()' % KenLog.fcn())

    def validate(self):
        LOG.info('%s()' % KenLog.fcn())
        version = float(self.version())

        input = self._create_content(version, "pass-through")
        if input:
            return self.validate_schema(input, "pass_through")
        LOG.info('%s()' % KenLog.fcn())

    @property
    def instructions(self):
        return self._instructions

    def get_dependencies(self):
        return []
