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
import logging
import timeit
import traceback

from ..model.CPProcessor import CPProcessor
from ..model.CPLogging import CPLogging as KenLog


LOG = logging.getLogger(__name__)


class BuilderProcessor(CPProcessor):
    def __init__(self, instructions, models, controllers):
        super(BuilderProcessor, self).__init__(instructions, "Builder")

        LOG.info('%s()' % KenLog.fcn())

        self._models = models
        self._controllers = controllers
        self._instructions['builder_success'] = {}

    def process(self):
        LOG.info('%s()' % KenLog.fcn())

        if not self._run_builders():
            return False

        return True

    def _run_builders(self):
        LOG.info('%s()' % KenLog.fcn())

        return_value = True

        invoke_args = (self._instructions, self._models,
                       self._controllers)

        order = self.get_plugin_order('builder', 'builders', invoke_args)
        for builder in order:
            mgr = self.load_plugin('builder', builder, invoke_args)
            if not mgr:
                continue

            if not mgr.driver.is_compatible_with_cloud(invoke_args):
                continue

            self._instructions['builder_success'][builder] = True

            self.start_plugin(builder)

            if mgr.driver.check_dependency_success():
                try:
                    duration = timeit.timeit(mgr.driver.build, number=1)
                except Exception as e:
                    msg = 'Builder %s encountered an exception: %s\n' % (
                        builder, e)
                    self.log_and_add_error(KenLog.fcn(), msg +
                                           traceback.format_exc())

                self.process_warnings(mgr, builder)

                if not self.process_errors(mgr, builder):
                    self._instructions['builder_success'][builder] = False
                    continue

                self.process_artifacts(mgr, builder)

                self.complete_plugin(builder, duration)
            else:
                msg = 'Builder %s skipped since a dependent builder failed' % builder
                self.log_and_print_message(KenLog.fcn(), msg)
                self._instructions['builder_success'][builder] = False

        return return_value

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
