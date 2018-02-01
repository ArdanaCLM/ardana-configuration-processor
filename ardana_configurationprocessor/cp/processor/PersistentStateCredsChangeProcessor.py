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
import traceback
import os
import re
import yaml

from copy import deepcopy
from ..model.CPProcessor import CPProcessor
from ..model.CPLogging import CPLogging as KenLog
from ..model.v2_0.Vault import Vault


LOG = logging.getLogger(__name__)


class PersistentStateCredsChange(CPProcessor):
    def __init__(self, instructions, controllers, models):
        super(PersistentStateCredsChange, self).__init__(instructions,
                                                         "PersistentStateCredsChange")

        LOG.info('%s()' % KenLog.fcn())

        self._models = models
        self._controllers = controllers

        cloud_config = self._controllers['CloudConfig']
        self._persistence_path = cloud_config.get_persistent_path(self._models)
        self._user_creds_path = instructions.get("credential_change_path", None)
        self._msg_base = "#   PersistentStateCreds:     "

    def process(self):
        LOG.info('%s()' % KenLog.fcn())
        self._errors = []
        try:
            self._load_persistent_state()
            self._load_creds_change()
            self._check_creds_change()
            self._check_cloud_scoped_variables()
            self._clear_metadata()
        except Exception as e:
            msg = 'PersistentStateCredsChange encountered an exception: %s\n' % e
            self.log_and_add_error(KenLog.fcn(), msg +
                                   traceback.format_exc())
            self.add_error(e)

        return len(self._errors) == 0

    def _load_persistent_state(self):
        if not os.path.isdir(self._persistence_path):
            self._models['persistent_state'] = {}
            return
        if not os.listdir(self._persistence_path):
            self._models['persistent_state'] = {}
            return

        files = [f for f in os.listdir(self._persistence_path) if
                 os.stat("%s/%s" % (self._persistence_path, f)).st_size != 0 and
                 f.endswith('.yml') or f.endswith('.yaml')]
        persistent_dict = {}
        for f in files:
            try:
                file_dict = yaml.load(open("%s/%s" % (self._persistence_path, f)))
            except (TypeError, ValueError) as e:
                msg = "Persistent State file %s cannot be parsed: %s" % (f, e)
                msg = self._msg_base + msg
                self.add_warning(msg)
                file_dict = {}
            if isinstance(file_dict, dict):
                key = f.split('.')[0]
                persistent_dict[key] = file_dict
            else:
                msg = "Persistent State file %s was not parsed properly" % f
                msg = self._msg_base + msg
                self.add_warning(msg)
        self._models['persistent_state'] = persistent_dict

    def _clear_metadata(self):
        for k, v in self._models['persistent_state'].iteritems():
            keys = [key for key in v.keys()]
            for key in keys:
                if key.endswith('__metadata'):
                    del v[key]

    def _load_creds_change(self):
        if not self._user_creds_path:
            return
        if self._user_creds_path and not os.path.isdir(self._user_creds_path):
            msg = "User-supplied-credentials directory doesn't exist"
            msg = self._msg_base + msg
            self.add_warning(msg)
            return
        if not os.listdir(self._user_creds_path):
            return
        files = [f for f in os.listdir(self._user_creds_path) if
                 os.stat("%s/%s" % (self._user_creds_path, f)).st_size != 0 and
                 f.endswith('.yml') or f.endswith('.yaml')]
        user_dict = {}

        encrypt = Vault(self._instructions)

        try:
            for f in files:
                try:
                    file_dict = yaml.load(encrypt.decrypt_file("%s/%s" % (self._user_creds_path, f)))
                except (TypeError, ValueError) as e:
                    msg = "User-supplied creds file %s cannot be parsed: %s" % (f, e)
                    msg = self._msg_base + msg
                    file_dict = {}
                    self.add_error(msg)
                if isinstance(file_dict, dict):
                    for k, v in file_dict.iteritems():
                        v_copy = deepcopy(v)
                        del(v_copy['metadata'])
                        for meta in v['metadata']:
                            cp = None
                            try:
                                cp = meta['cp']
                            except KeyError:
                                msg = "User-supplied cred '%s' in file '%s' does not include " \
                                      "a control plane.  Please include the relevant control " \
                                      "plane in the metadata section 'cp: <control plane>.'" \
                                      % (k, f)
                                msg = self._msg_base + msg
                                self.add_error(msg)
                            if cp:
                                if cp not in user_dict:
                                    user_dict[cp] = {}
                                if k not in user_dict[cp]:
                                    user_dict[cp][k] = v_copy
                else:
                    msg = "User-supplied creds file %s was not parsed properly" % f
                    msg = self._msg_base + msg
                    self.add_error(msg)
        finally:
            encrypt.destroy_files(warning=self._warnings, msg_base=self._msg_base)

        if len(user_dict) > 0:
            self._models['user_creds_change'] = user_dict

    def _check_creds_change(self):
        if 'user_creds_change' in self._models:
            #
            # We look for instances that are of the form private_data_<control-plane>,
            # i.e. excluding private_data_old, private_data_old_<control-plane>,
            # private_data_encryption_validator and private_data_cloud_variables
            #
            pattern = re.compile('^private_data_((?!old.*)(?!encryption.)(?!cloud.))')
            control_planes = [k.split('_')[-1] for k in self._models['persistent_state'].keys()
                              if re.match(pattern, k)]
            if 'private_data' in self._models['persistent_state']:
                for k, v in self._models['persistent_state']['private_data'].iteritems():
                    if k.endswith('__metadata'):
                        cp = v[0].get('cp')
                        control_planes.append(cp)
                        break
            not_valid = [k for k in self._models['user_creds_change'].keys()
                         if k not in control_planes]
            if len(not_valid) > 0:
                for item in not_valid:
                    msg = "Control-plane %s specified in user-supplied password change file " \
                          "is not present in persistent-state" % item
                    msg = self._msg_base + msg
                    self.add_error(msg)

            for k, v in self._models.get('user_creds_change').iteritems():
                if k not in not_valid:
                    for private in ['private_data_%s' % k, 'private_data']:
                        if self._models['persistent_state'].get(private, {}) != {}:
                            for key in v.keys():
                                if key not in self._models['persistent_state'][private]:
                                    msg = "User-supplied password name '%s' is not valid in " \
                                          "control-plane '%s'" % (key, k)
                                    msg = self._msg_base + msg
                                    self.add_error(msg)

    def _check_cloud_scoped_variables(self):
        if ('private_data_cloud_variables' in self._models['persistent_state'] and
                'user_creds_change' in self._models):
            #
            # We look for instances that are of the form private_data_<control-plane>,
            # i.e. excluding private_data_old, private_data_old_<control-plane>,
            # private_data_encryption_validator and private_data_cloud_variables
            #
            pattern = re.compile('^private_data_((?!old.*)(?!encryption.)(?!cloud.))')
            cloud_variables = self._models['persistent_state']['private_data_cloud_variables']
            for k, v in cloud_variables.iteritems():
                change_set = set()
                for change, value in self._models['user_creds_change'].iteritems():
                    for key, val in value.iteritems():
                        if key == k:
                            change_set.add(change)
                if len(change_set) > 0:
                    persist_set = set()
                    for persist, value in self._models['persistent_state'].iteritems():
                        if re.match(pattern, persist):
                            for key, val in value.iteritems():
                                if key == k:
                                    persist_set.add(persist.split('_')[-1])
                    if change_set != persist_set:
                        msg = "User is attempting to change variable '%s' with a scope of " \
                              "'cloud' but hasn't specified the exact set of control " \
                              "planes on which the variable is used - %s" % \
                              (k, ', '.join(list(persist_set)))
                        msg = self._msg_base + msg
                        self.add_error(msg)

    @property
    def models(self):
        return self._models

    @models.setter
    def models(self, models):
        self._models = models

    @property
    def controllers(self):
        return self._controllers

    @controllers.setter
    def controllers(self, controllers):
        self._controllers = controllers
