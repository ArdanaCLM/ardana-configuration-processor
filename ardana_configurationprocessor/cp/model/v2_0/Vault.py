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

import os
import sh
import tempfile
import logging
import logging.config

from ardana_configurationprocessor.cp.model.CPSecurity \
    import CPSecurity
from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog


LOG = logging.getLogger(__name__)


class Vault(object):
    def __init__(self, instructions):
        LOG.info('%s()' % KenLog.fcn())

        self._instructions = instructions
        self.prefix = 'ans'
        self.suffix = '.pw'
        self._temp_files = []
        self._pw_file = self._create_temp_file()
        self._create_password_file()
        self._temp_files.append(self._pw_file[1])

    def decrypt_file(self, file_name):
        pw_file_name = self._pw_file
        pw_file_arg = '--vault-password-file=%s' % pw_file_name

        try:
            temp_file = self._create_temp_file(file_name)
            sh.ansible_vault.decrypt(temp_file, pw_file_arg)
            return open(temp_file)
        except Exception:
            return open(file_name)

    def _create_password_file(self):
        pw_file_name = self._pw_file
        if 'encryption_key' in self._instructions:
            with open(pw_file_name, 'w') as fp:
                fp.write(CPSecurity.decode_key(self._instructions[
                    'encryption_key']))

    def _create_temp_file(self, file_name=None):
        temp_file = tempfile.mkstemp(prefix=self.prefix, suffix=self.suffix,
                                     text=True)
        fd = os.fdopen(temp_file[0], 'w')
        if file_name is not None:
            with open(file_name) as fd2:
                fd.write(fd2.read())
        fd.close()
        self._temp_files.append(temp_file[1])
        return temp_file[1]

    def destroy_files(self, warning=None, msg_base=''):
        for f in self._temp_files:
            try:
                if os.path.exists(f):
                    with open(f, 'w') as fp:
                        fp.write('*' * 128)
                    os.remove(f)
            except IOError as e:
                if warning is not None:
                    msg = "Error trying to remove tempfile %s: %s" % (f, str(e))
                    msg = msg_base + msg
                    self._add_warning(warning, msg)

    def _add_warning(self, warnings, warning):
        if warning not in warnings:
            warnings.append(warning)
