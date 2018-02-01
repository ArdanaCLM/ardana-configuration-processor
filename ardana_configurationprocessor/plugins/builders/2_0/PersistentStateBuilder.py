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
from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog
from ardana_configurationprocessor.cp.model.BuilderPlugin \
    import ArtifactMode
from ardana_configurationprocessor.cp.model.Version \
    import Version


LOG = logging.getLogger(__name__)


class PersistentStateBuilder(BuilderPlugin):
    def __init__(self, instructions, models, controllers):
        super(PersistentStateBuilder, self).__init__(
            2.0, instructions, models, controllers,
            'persistent-state-2.0')
        LOG.info('%s()' % KenLog.fcn())
        self._controllers = controllers
        self._models = models
        cloud_config = self._controllers['CloudConfig']
        self._persistence_path = cloud_config.get_persistent_path(self._models)
        if not os.path.isdir(self._persistence_path):
            os.makedirs(self._persistence_path)
        self.cloud_desc = self._models['CloudDescription']['cloud']
        self._file_path = ArdanaPaths.get_output_path(self._instructions, self.cloud_desc)
        self._version = self._instructions['model_version']
        self._version = Version.normalize(self._version)
        self._password_change = {}

    def build(self):
        LOG.info('%s()' % KenLog.fcn())
        self._remove_cp_None()
        self._check_persistent_state_consistency()
        if len(self._errors) > 0:
            return len(self._errors) == 0
        self._update_old_private_data()
        self._load_password_change()
        self._remove_non_scoped_private_data()
        self._load_cloud_variable_names()
        self._write_password_change()
        self._write_persistent_state()

    def _remove_cp_None(self):
        pattern = re.compile('^private_data_.*None')
        keys = self._models['persistent_state'].keys()
        key_match = [k for k in keys if re.search(pattern, k)]
        for k in key_match:
            del self._models['persistent_state'][k]

    def _check_persistent_state_consistency(self):
        if ('private_data' in self._models['persistent_state'] and
                self._models['persistent_state']['private_data']):
            #
            # We are looking for instances of private_data_<control-plane>, i.e
            # excluding private_data_old, private_data_old_<control-plane>,
            # private_data_encryption_validator and private_data_cloud.
            # If we have more than one of these instances we raise an error
            #
            pattern = re.compile('^private_data_((?!old.*)(?!encryption.)(?!cloud.*))')
            keys = self._models['persistent_state'].keys()
            key_match = [k for k in keys if re.search(pattern, k)]
            if len(key_match) > 1:
                msg = 'Persistent state inconsistent.  Run is attempting to add an extra control ' \
                      + 'plane without first migrating persistent state to scoped ' \
                      + 'representation. Please rerun with old input model first.'
                self.add_error(msg)
                return

    def _load_cloud_variable_names(self):
        if 'private_data_cloud' in self._models['persistent_state']:
            self._models['persistent_state']['private_data_cloud_variables'] = {}
            for k, v in self._models['persistent_state']['private_data_cloud'].iteritems():
                self._models['persistent_state']['private_data_cloud_variables'][k] = True

    def _remove_non_scoped_private_data(self):
        keys = self._models['persistent_state'].keys()
        #
        # We are looking for instances of private_data_<control-plane> and
        # private_data_old_<control-plane> excluding private_data_old and
        # private_data.  We split the <control-plane> off the instance and
        # make a list of the unique values so obtained, i.e. private_data
        # and possibly private_data_old.  We then remove the yml files that
        # correspond to the entries in the list
        #
        pattern = re.compile('^private_data_(((?!old)(?!encryption.)(?!cloud.*))|old_.)')
        key_match = list({key.rsplit('_', 1)[0] for key in keys if re.search(pattern, key)})
        for name in key_match:
            file_path = '%s%s.yml' % (self._persistence_path, name)
            if os.path.isfile(file_path):
                self.add_artifact(file_path, ArtifactMode.DELETED)
                os.remove(file_path)

    def _write_persistent_state(self):
        if 'persistent_state' in self._models:
            for key, value in self._models['persistent_state'].iteritems():
                if key not in ['private_data', 'private_data_old', 'private_data_cloud']:
                    filename = "%s.yml" % key
                    persistence_file = os.path.join(self._persistence_path + filename)
                    if value != {}:
                        self.add_artifact(persistence_file, ArtifactMode.CREATED)
                        with open(persistence_file, 'w') as yaml_file:
                            yaml.dump(value, yaml_file,
                                      allow_unicode=False, default_flow_style=False)

    def _write_password_change(self):
        for key, value in self._password_change.iteritems():
            filename = "password_change_%s.yml" % key
            pw_file = '%s/info/%s' % (self._file_path, filename)
            if value != {}:
                if not os.path.exists(os.path.dirname(pw_file)):
                    os.makedirs(os.path.dirname(pw_file))
                self.add_artifact(pw_file, ArtifactMode.CREATED)
                with open(pw_file, 'w') as yaml_file:
                    yaml.dump(value, yaml_file,
                              allow_unicode=False, default_flow_style=False)

    def _load_password_change(self):
        for key, value in self._models['persistent_state'].iteritems():
            pattern = re.compile('^private_data_old_.')
            if re.search(pattern, key):
                cp = key.split('_')[-1]
                private = self._models['persistent_state']['private_data_%s' % cp]
                for k, v in value.iteritems():
                    if (not k.endswith("__is_secure") and not k.endswith('__metadata') and
                            k != "encryption_key_checker"):
                        if cp not in self._password_change:
                            self._password_change[cp] = {}
                        self._password_change[cp][k] = {'metadata':
                                                        private.get('%s__metadata' % k, None),
                                                        'version': self._version}

    def _update_old_private_data(self):
        if 'persistent_state' in self._models:
            if 'private_data_old' in self._models['persistent_state']:
                self._update_dict('private_data_old')
            for key in self._models['persistent_state'].keys():
                if key.startswith('private_data_old_working'):
                    self._update_dict(key)

    def _update_dict(self, key):
        if key == 'private_data_old' and self._models['persistent_state']['private_data_old']:
            #
            # We look for instances of private_data_<control-plane>, excluding
            # private_data_old, private_data_old_<control-plane>,
            # private_data_encryption_validator and private_data_cloud
            #
            pattern = re.compile('^private_data_((?!old.*)(?!encryption.)(?!cloud.*))')
            keys = self._models['persistent_state'].keys()
            key_match = [k for k in keys if re.search(pattern, k)]
            if 'encryption_key_checker' in self._models['persistent_state'][key]:
                del self._models['persistent_state'][key]['encryption_key_checker']
            for k, v in self._models['persistent_state'][key_match[0]].iteritems():
                if k.endswith('__metadata'):
                    cp = v[0].get('cp')
                    break
        elif key == 'private_data_old' and not self._models['persistent_state']['private_data_old']:
            del self._models['persistent_state']['private_data_old']
            return
        else:
            cp = key.split('_')[-1]
        pd_old = 'private_data_old_%s' % cp
        if pd_old not in self._models['persistent_state']:
            self._models['persistent_state'][pd_old] = {}
        self._models['persistent_state'][pd_old].update(
            self._models['persistent_state'][key])
        del self._models['persistent_state'][key]

    def get_dependencies(self):
        return []
