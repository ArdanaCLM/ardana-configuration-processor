#
# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
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
import logging
import logging.config

from Crypto.PublicKey import RSA, DSA

from ardana_configurationprocessor.cp.model.VariablePlugin \
    import VariablePlugin
from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog


LOG = logging.getLogger(__name__)


class RandomSshKeyVariable(VariablePlugin):
    def __init__(self, instructions, models, controllers):
        super(RandomSshKeyVariable, self).__init__(
            2.0, instructions, models, controllers,
            'random-sshkey-2.0')
        LOG.info('%s()' % KenLog.fcn())

    def calculate(self, payload=None):
        LOG.info('%s()' % KenLog.fcn())

        if not payload:
            payload = dict()

        if 'algorithm' not in payload:
            payload['algorithm'] = 'RSA'

        elif payload['algorithm'] not in ('RSA', 'DSA',):
            self.add_error('algorithm must be one of RSA or DSA')
            return None

        if 'length' not in payload:
            payload['length'] = 2048

        if 'comment' not in payload:
            payload['comment'] = None

        if 'passphrase' not in payload:
            payload['passphrase'] = None

        return self._calculate(payload)

    def is_immutable(self):
        return True

    def _calculate(self, payload):
        LOG.info('%s()' % KenLog.fcn())

        algorithm = payload['algorithm']
        length = payload['length']
        passphrase = payload['passphrase']
        comment = payload['comment']

        if algorithm == 'RSA':
            key = RSA.generate(length)

        elif algorithm == 'DSA':
            key = DSA.generate(length)

        value = {
            'private': key.exportKey('PEM', passphrase=passphrase),
            'public': key.publickey().exportKey('OpenSSH'),
        }

        if comment is not None:
            value['public'] += " " + comment

        return value

    @property
    def instructions(self):
        return self._instructions

    @property
    def models(self):
        return self._models

    @property
    def controllers(self):
        return self._controllers
