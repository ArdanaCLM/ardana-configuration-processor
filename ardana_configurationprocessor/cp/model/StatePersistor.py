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

from copy import deepcopy


class StatePersistor():
    def __init__(self, models, controllers,
                 persistence_file='general.yml',
                 persistence_path=None):

        self._key = persistence_file.split('.')[0]
        self._models = models
        if self._key in self._models['persistent_state']:
            self._data_dict = self._models['persistent_state'][self._key]
        else:
            self._data_dict = {}
            self._models['persistent_state'][self._key] = self._data_dict

    def persist_info(self, info_dict):
        self._data_dict.update(deepcopy(info_dict))

    def delete_info(self, keys):
        for key in keys:
            if key in self._data_dict:
                del self._data_dict[key]

    def recall_info(self, lookup_array=None):
        if not self._data_dict:
            return dict()

        if not lookup_array:
            return self._data_dict

        current_dict = self._data_dict
        for key in lookup_array:
            current_dict = current_dict.get(key, None)

        return current_dict
