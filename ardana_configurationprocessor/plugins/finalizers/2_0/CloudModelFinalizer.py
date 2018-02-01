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
import os
import logging
import logging.config

import yaml

from ardana_configurationprocessor.cp.model.FinalizerPlugin \
    import FinalizerPlugin
from ardana_configurationprocessor.cp.model.BuilderPlugin \
    import ArtifactMode
from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog


LOG = logging.getLogger(__name__)


class CloudModelFinalizer(FinalizerPlugin):
    def __init__(self, instructions, models, controllers, config_files):
        super(CloudModelFinalizer, self).__init__(
            2.0, instructions, models, controllers, config_files,
            'cloud-model-2.0')
        LOG.info('%s()' % KenLog.fcn())

    def finalize(self):
        LOG.info('%s()' % KenLog.fcn())
        cloud_config = self._controllers['CloudConfig']
        path = cloud_config.get_output_path(self._models)
        path = os.path.join(path, 'internal')
        if not os.path.exists(path):
            os.makedirs(path)

        model = self._models['CloudModel']

        file_name = '%s/CloudModel.yaml' % path
        self.add_artifact(file_name, ArtifactMode.CREATED)
        with open(file_name, 'w') as fp:
            yaml.dump(model, fp, default_flow_style=False, indent=2)

        config = self._config_files

        file_name = '%s/ConfigFiles.yaml' % path
        self.add_artifact(file_name, ArtifactMode.CREATED)
        with open(file_name, 'w') as fp:
            yaml.dump(config, fp, default_flow_style=False, indent=2)

    def get_dependencies(self):
        return []
