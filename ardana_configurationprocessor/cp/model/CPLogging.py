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
import collections
import os
import six
import sys
import json
import logging
import platform
from abc import ABCMeta

LOG = logging.getLogger(__name__)


@six.add_metaclass(ABCMeta)
class CPLogging(object):
    def __init__(self, instructions):
        self._instructions = instructions
        self._setup_logging()

    def merge_dicts(self, d1, d2):
        """
        Modifies d1 in-place to contain values from d2.  If any value
        in d1 is a dictionary (or dict-like), *and* the corresponding
        value in d2 is also a dictionary, then merge them in-place.
        """
        for k, v2 in d2.items():
            v1 = d1.get(k)  # returns None if v1 has no value for this key
            if (isinstance(v1, collections.Mapping) and
                    isinstance(v2, collections.Mapping)):
                self.merge_dicts(v1, v2)
            else:
                d1[k] = v2

    def _find_logging_config(self, logging_conf_filename):
        """ try first 'site_config_path" configuration and then
        fallback to the config provided from the python module"""
        path = self._instructions.get('site_config_path', '.')
        path_fallback = os.path.abspath(os.path.join(
            os.path.realpath(__file__), '..', '..', '..', 'data', 'Config'))
        for p in [path, path_fallback]:
            logging_config = os.path.join(p, logging_conf_filename)
            if os.path.exists(logging_config):
                return logging_config
        return None

    def _setup_logging(self):
        logging_config = self._find_logging_config('logging.json')
        logging_config_win = self._find_logging_config('logging-win.json')
        try:
            with open(logging_config, 'rt') as f:
                config = json.load(f)
            if platform.system() == 'Windows' and logging_config_win:
                with open(logging_config_win, 'rt') as f:
                    self.merge_dicts(config, json.load(f))
            log_dir = self._instructions['log_dir']

            for h, elem_h in six.iteritems(config['handlers']):
                if 'filename' in elem_h:

                    filename = elem_h['filename']
                    filename = filename.replace('@LOG_DIR@', log_dir)
                    elem_h['filename'] = filename

                    dirname = os.path.dirname(filename)
                    if not os.path.exists(dirname):
                        try:
                            os.makedirs(dirname)
                        except Exception as e:
                            print('Error: Could not create "%s" (%s)' %
                                  (dirname, e))

            logging.config.dictConfig(config)
        except IOError:
            pass

    @staticmethod
    def fcn():
        return sys._getframe(1).f_code.co_name
