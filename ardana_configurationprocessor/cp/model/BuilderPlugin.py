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
import six
import logging

from abc import ABCMeta
from abc import abstractmethod

from .CPLogging import CPLogging as KenLog
from .PluginBase import PluginBase


LOG = logging.getLogger(__name__)


class ArtifactMode(object):
    CREATED = 0
    MODIFIED = 1
    DELETED = 2
    COPIED = 3
    ENCRYPTED = 4


@six.add_metaclass(ABCMeta)
class BuilderPlugin(PluginBase):
    def __init__(self, version, instructions, models, controllers, slug):
        super(BuilderPlugin, self).__init__(version, instructions, slug)

        LOG.info('%s()' % KenLog.fcn())

        self._models = models
        self._controllers = controllers
        self._artifacts = []

    @abstractmethod
    def build(self):
        """ Take the model and construct some output according to the
        instructions
        :return: True if the building succeeded, False if it failed.  Note
        that if it fails, the plugin should throw an exception.
        """
        pass

    def get_artifacts(self):
        """ The builder is responsible for keeping track of the artifacts
        that it generates.  This would include paths to created or modified
        files. Created files should be prepended with (+), removed files
        should be prepended with (-), and modified files should be prepended
        with (*).
        :return: The list of artifacts
        """
        return self._artifacts

    def add_artifact(self, artifact, mode):
        a = '(?) '
        if mode == ArtifactMode.CREATED:
            a = '(+) '

        if mode == ArtifactMode.MODIFIED:
            a = '(*) '

        if mode == ArtifactMode.DELETED:
            a = '(-) '

        if mode == ArtifactMode.COPIED:
            a = '(>) '

        if mode == ArtifactMode.ENCRYPTED:
            a = '(x) '

        a += artifact

        self._artifacts.append(a)

    @property
    def models(self):
        return self._models

    @property
    def controllers(self):
        return self._controllers

    def check_dependency_success(self):
        for dependency in self.get_dependencies():
            if not self._instructions['builder_success'][dependency]:
                return False
        return True
