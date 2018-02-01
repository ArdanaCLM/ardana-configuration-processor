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


class RegionsValidator(ValidatorPlugin):
    def __init__(self, instructions, config_files):
        super(RegionsValidator, self).__init__(
            2.0, instructions, config_files,
            'regions-2.0')
        LOG.info('%s()' % KenLog.fcn())
        self._valid = False

    def validate(self):
        LOG.info('%s()' % KenLog.fcn())
        version = float(self.version())

        input = self._create_content(version, "regions")
        if input:
            self._valid = self.validate_schema(input, "region")

        if self._valid:
            regions = input['regions']

            # Map each component to its service
            services = self._get_dict_from_config_value(version, 'services')

            self._check_names(regions)
            for region in regions:
                self._check_services(region, services)

        LOG.info('%s()' % KenLog.fcn())
        return self._valid

    #
    # Check region names are unique
    #
    def _check_names(self, regions):

        names = set()
        for r in regions:
            if r['name'] in names:
                msg = ("Duplicate region name '%s'" %
                       (r['name']))
                self.add_error(msg)
            else:
                names.add(r['name'])

    #
    # Check servcies are valid
    #
    def _check_services(self, region, services):

        for includes in region.get('includes', []):
            for service_name in includes.get('services', []):
                if service_name == 'all':
                    continue
                if service_name not in services:
                    msg = ("Region '%s': Invalid service name '%s'." %
                           (region['name'], service_name))
                    self.add_error(msg)
                    self._valid = False

    @property
    def instructions(self):
        return self._instructions

    def get_dependencies(self):
        return ['service-components-2.0']
