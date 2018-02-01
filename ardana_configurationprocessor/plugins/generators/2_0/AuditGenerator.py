# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
# (c) Copyright 2017-2018 SUSE LLC
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import logging
import logging.config

from ardana_configurationprocessor.cp.model.CPLogging import \
    CPLogging as KenLog
from ardana_configurationprocessor.cp.model.GeneratorPlugin \
    import GeneratorPlugin
from ardana_configurationprocessor.cp.model.v2_0.CloudModel \
    import CloudModel


LOG = logging.getLogger(__name__)


class AuditGenerator(GeneratorPlugin):
    def __init__(self, instructions, models, controllers):
        super(AuditGenerator, self).__init__(
            2.0, instructions, models, controllers,
            'audit-generator-2.0')
        LOG.info('%s()' % KenLog.fcn())

    def generate(self):
        LOG.info('%s()' % KenLog.fcn())

        self._action = KenLog.fcn()
        cloud_internal = CloudModel.internal(self._models['CloudModel'])

        cloud_data = self._models['CloudDescription']['cloud']
        control_planes = CloudModel.get(cloud_internal, 'control-planes', {})

        audit_settings = {'audit-dir': '/var/audit',
                          'default': 'disabled',
                          'enabled-services': [],
                          'disabled-services': []}
        audit_settings.update(cloud_data.get('audit-settings', {}))

        for cp_name, cp in control_planes.iteritems():
            cp_services = cp.get('services', {})
            for service_name, service_data in cp_services.iteritems():
                service_data['audit-settings'] = {
                    'dir': audit_settings['audit-dir'],
                    'enabled': audit_settings['default'] == 'enabled'}

                if service_name in audit_settings['enabled-services']:
                    service_data['audit-settings']['enabled'] = True
                elif service_name in audit_settings['disabled-services']:
                    service_data['audit-settings']['enabled'] = False

    def get_dependencies(self):
        return ['encryption-key',
                'internal-model-2.0',
                'cloud-cplite-2.0']
