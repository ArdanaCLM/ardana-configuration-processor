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
import string

from ardana_configurationprocessor.cp.model.ValidatorPlugin \
    import ValidatorPlugin
from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog

LOG = logging.getLogger(__name__)


class MemoryModelValidator(ValidatorPlugin):
    def __init__(self, instructions, config_files):
        super(MemoryModelValidator, self).__init__(
            2.0, instructions, config_files,
            'memory-model-2.0')
        self._valid = False
        LOG.info('%s()' % KenLog.fcn())

    def validate(self):
        LOG.info('%s()' % KenLog.fcn())

        version = float(self.version())

        input = self._create_content(version, "memory-models")
        if not input:
            return True

        self._valid = self.validate_schema(input, "memory_model")
        if self._valid:
            memory_models = input['memory-models']
            self._validate_names(memory_models)
            for model in memory_models:
                self._validate_model(model)

        return self._valid

    def _validate_names(self, memory_models):

        #
        # Check each model is only defined once
        #
        names = set()
        for model in memory_models:
            if model['name'] in names:
                msg = ("memory model %s is defined more than once." %
                       (model['name']))
                self.add_error(msg)
                self._valid = False
            else:
                names.add(model['name'])

    #
    # Validate each memory model.
    #
    def _validate_model(self, memory_model):

        def _validate_size(size):
            num = str(size).strip("KMG")
            qual = str(size).lstrip(string.digits)
            if num.isdigit and qual in ['K', 'M', 'G']:
                return True
            else:
                return False

        numa_page_sizes = {}
        non_numa_page_sizes = []
        for page in memory_model.get('huge-pages', []):

            if page['count'] <= 0:
                msg = ("Page count '%s' in memory model '%s' "
                       "is not valid." %
                       (page['count'], memory_model['name']))
                self.add_error(msg)
                self._valid = False
                continue

            if not _validate_size(page['size']):
                msg = ("Page size '%s' in memory model '%s' "
                       "is not valid." %
                       (page['size'], memory_model['name']))
                self.add_error(msg)
                self._valid = False
                continue

            if 'numa-node' in page:

                if page['size'] not in numa_page_sizes:
                    numa_page_sizes[page['size']] = []

                if page['numa-node'] in numa_page_sizes[page['size']]:
                    msg = ("Numa node '%s' defined multiple times for "
                           "page size '%s' in memory model '%s'." %
                           (page['numa-node'], page['size'], memory_model['name']))
                    self.add_error(msg)
                    self._valid = False
                else:
                    numa_page_sizes[page['size']].append(page['numa-node'])

            else:
                if page['size'] in non_numa_page_sizes:
                    msg = ("Page size '%s' defined multiple times in "
                           "memory model '%s'." %
                           (page['size'], memory_model['name']))
                    self.add_error(msg)
                    self._valid = False
                else:
                    non_numa_page_sizes.append(page['size'])

        if 'vm-size' in memory_model:
            if not _validate_size(memory_model['vm-size']['ram']):
                msg = ("Ram '%s' in vm-size in memory model '%s' "
                       "is not valid" % (memory_model['vm-size']['ram'], memory_model['name']))
                self.add_error(msg)
                self._valid = False

        if 'default-huge-page-size' in memory_model:
            if memory_model['default-huge-page-size'] not in non_numa_page_sizes:
                msg = ("Default huge page size '%s' in memory model '%s' "
                       "does not match any of the non-numa page sizes." %
                       (memory_model['default-huge-page-size'], memory_model['name']))
                self.add_error(msg)
                self._valid = False

    @property
    def instructions(self):
        return self._instructions

    def get_dependencies(self):
        return []
