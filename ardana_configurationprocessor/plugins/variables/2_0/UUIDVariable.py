#
# (c) Copyright 2015 Hewlett Packard Enterprise Development LP
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
import uuid

from ardana_configurationprocessor.cp.model.VariablePlugin \
    import VariablePlugin


class UUIDVariable(VariablePlugin):
    def __init__(self, instructions, models, controllers):
        super(UUIDVariable, self).__init__(
            2.0, instructions, models, controllers,
            'uuid-2.0')

    def calculate(self, payload=None):
        if not payload:
            payload = dict()

        return str(uuid.uuid4())

    def is_immutable(self):
        return True

    @property
    def instructions(self):
        return self._instructions

    @property
    def models(self):
        return self._models

    @property
    def controllers(self):
        return self._controllers

    def get_dependencies(self):
        return []
