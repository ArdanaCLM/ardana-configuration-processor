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
import os
import re
import yaml

from ardana_configurationprocessor.cp.model.v2_0.ArdanaPaths \
    import ArdanaPaths
from ardana_configurationprocessor.cp.model.BuilderPlugin \
    import BuilderPlugin
from ardana_configurationprocessor.cp.model.BuilderPlugin \
    import ArtifactMode
from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog
from ardana_configurationprocessor.cp.model.Version \
    import Version


LOG = logging.getLogger(__name__)


class PrivateDataMetaDataBuilder(BuilderPlugin):
    def __init__(self, instructions, models, controllers):
        super(PrivateDataMetaDataBuilder, self).__init__(
            2.0, instructions, models, controllers,
            'private-data-meta-data-2.0')
        LOG.info('%s()' % KenLog.fcn())
        self.cloud_desc = self._models['CloudDescription']['cloud']
        self._file_path = ArdanaPaths.get_output_path(self._instructions, self.cloud_desc)
        self._version = self._instructions['model_version']
        self._version = Version.normalize(self._version)
        self._meta_data = {}

    def build(self):
        LOG.info('%s()' % KenLog.fcn())

        self._load_meta_data()
        self._write_metadata()

    def _load_meta_data(self):
        #
        # We look for instances of private_data_<control-plane>, excluding
        # private_data_old, private_data_old_<control-plane>,
        # private_data_encryption_validator and private_data_cloud
        #
        pattern = re.compile('^private_data_((?!old.*)(?!encryption.)(?!cloud.*))')
        cloud = self._models['persistent_state'].get('private_data_cloud', {})
        for key, value in self._models['persistent_state'].iteritems():
            if re.search(pattern, key):
                cp = key.split('_')[-1]
                pd_m = 'private_data_metadata_%s' % cp
                self._meta_data[pd_m] = {}
                for k, v in value.iteritems():
                    if (not k.endswith("__is_secure") and not k.endswith('__metadata') and
                            k != "encryption_key_checker"):
                        if k not in cloud:
                            if k not in self._meta_data[pd_m]:
                                self._meta_data[pd_m][k] = {'metadata':
                                                            value.get('%s__metadata' % k, None),
                                                            'version': self._version}
                            else:
                                self._meta_data[pd_m][k]['metadata'].append(
                                    value.get('%s__metadata' % k))
                        else:
                            name = 'private_data_metadata_cloud'
                            if name not in self._meta_data:
                                self._meta_data[name] = {}
                            if k not in self._meta_data[name]:
                                self._meta_data[name][k] = {'metadata':
                                                            value.get('%s__metadata' % k, None),
                                                            'version': self._version}
                            else:
                                self._meta_data[name][k]['metadata'].extend(value.get('%s__metadata'
                                                                                      % k))

    def _write_metadata(self):
        for key, value in self._meta_data.iteritems():
            filename = "%s.yml" % key
            metadata_file = '%s/info/%s' % (self._file_path, filename)
            if value != {}:
                if not os.path.exists(os.path.dirname(metadata_file)):
                    os.makedirs(os.path.dirname(metadata_file))
                self.add_artifact(metadata_file, ArtifactMode.CREATED)
                with open(metadata_file, 'w') as yaml_file:
                    yaml.dump(value, yaml_file,
                              allow_unicode=False, default_flow_style=False)

    def get_dependencies(self):
        return ['persistent-state-2.0']
