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


class ExplainerProcessor(CPProcessor):
    def __init__(self, instructions, models, controllers):
        super(ExplainerProcessor, self).__init__(instructions, "Explainer")

        LOG.info('%s()' % KenLog.fcn())

        self._models = models
        self._controllers = controllers

    def process(self):
        LOG.info('%s()' % KenLog.fcn())

        if not self._run_explainers():
            return False

        return True

    def _run_explainers(self):
        LOG.info('%s()' % KenLog.fcn())

        return_value = True

        invoke_args = (self._instructions, self._models,
                       self._controllers)

        order = self.get_plugin_order('explainer', 'explainers', invoke_args)
        for explainer in order:
            mgr = self.load_plugin('explainer', explainer, invoke_args)
            if not mgr:
                continue

            if not mgr.driver.is_compatible_with_cloud(invoke_args):
                continue

            self.start_plugin(explainer)

            try:
                duration = timeit.timeit(mgr.driver.explain, number=1)
            except Exception as e:
                msg = 'Explainer %s encountered an exception: %s\n' % (
                    explainer, e)
                self.log_and_add_error(KenLog.fcn(), msg +
                                       traceback.format_exc())

            self.process_warnings(mgr, explainer)

            if not self.process_errors(mgr, explainer):
                continue

            self.complete_plugin(explainer, duration)

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
