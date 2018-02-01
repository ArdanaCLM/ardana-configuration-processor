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

from copy import deepcopy

from ardana_configurationprocessor.cp.model.MigratorPlugin \
    import MigratorPlugin
from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog
from ardana_configurationprocessor.cp.lib.DataTransformer \
    import DataTransformer


LOG = logging.getLogger(__name__)


class SwiftRingsMigrator(MigratorPlugin):
    def __init__(self, instructions, models, controllers, config_files):
        super(SwiftRingsMigrator, self).__init__(
            2.0, instructions, models, controllers, config_files,
            'swift-rings-2.0')
        LOG.info('%s()' % KenLog.fcn())

    def migrate(self, model_name, model):
        LOG.info('%s()' % KenLog.fcn())
        print('Migrating the "%s" model with the "%s" migrator...' % (
            model_name, self._slug))

        if 'ring-specifications' in model['2.0']:
            self._migrate_ring_to_config(model)

        return model

    def _migrate_ring_to_config(self, model):
        if 'configuration-data' not in model['2.0']:
            model['2.0']['configuration-data'] = []

        #
        # Copying just the first ring-specification - there should only be
        # one if we are running this migrator
        #
        ring_copy = deepcopy(model['2.0']['ring-specifications'][0])
        ring_data = {'control_plane_rings': DataTransformer(ring_copy).all_output('-', '_')}
        cp_name = model['2.0']['control-planes'][0]['name']
        config_name = 'SWIFT-CONFIG-%s' % cp_name.upper()
        swift_ring = {'name': config_name,
                      'services': ['swift'],
                      'data': ring_data}

        model['2.0']['configuration-data'].append(swift_ring)
        if 'configuration-data' not in model['2.0']['control-planes'][0]:
            model['2.0']['control-planes'][0]['configuration-data'] = []
        model['2.0']['control-planes'][0]['configuration-data'].append(config_name)

        for config in self._config_files:
            if config['version'] == 2:
                config.pop('ring-specifications')
        model['2.0'].pop('ring-specifications')

    def applies_to(self):
        return ['CloudModel']

    def get_dependencies(self):
        return []
