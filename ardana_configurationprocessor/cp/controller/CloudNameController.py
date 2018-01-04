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
from ..model.JsonConfigFile import JsonConfigFile
from ..model.YamlConfigFile import YamlConfigFile


class CloudNameController(object):
    def __init__(self):
        pass

    @staticmethod
    def normalize_nickname(name, nickname):
        return nickname.replace(name, '').replace(' ', '_')

    @staticmethod
    def get_cloud_names(file_name):
        if file_name.endswith('.json'):
            cf = JsonConfigFile('cloudConfig', file_name)
            cf.load()

        elif file_name.endswith('.yml') or file_name.endswith('.yaml'):
            cf = YamlConfigFile('cloudConfig', file_name)
            cf.load()

        else:
            return '', ''

        element = cf.contents
        if not element:
            return '', ''

        name = element['cloud']['name']
        nickname = element['cloud']['nickname']

        nickname = CloudNameController.normalize_nickname(name, nickname)

        return name, nickname
