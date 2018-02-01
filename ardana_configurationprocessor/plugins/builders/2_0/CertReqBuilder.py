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
import os
import logging
import logging.config

from ardana_configurationprocessor.cp.model.v2_0.ArdanaPaths \
    import ArdanaPaths
from ardana_configurationprocessor.cp.model.v2_0.CloudModel \
    import CloudModel

from ardana_configurationprocessor.cp.model.BuilderPlugin \
    import BuilderPlugin
from ardana_configurationprocessor.cp.model.BuilderPlugin \
    import ArtifactMode
from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog


LOG = logging.getLogger(__name__)


class CertReqBuilder(BuilderPlugin):
    def __init__(self, instructions, models, controllers):
        super(CertReqBuilder, self).__init__(
            2.0, instructions, models, controllers,
            'cert-req-2.0')
        LOG.info('%s()' % KenLog.fcn())

        self.cloud_desc = self._models['CloudDescription']['cloud']
        self._file_path = ArdanaPaths.get_output_path(self._instructions, self.cloud_desc)

        self._cloud_model = self._models['CloudModel']
        self._cloud_version = CloudModel.version(self._cloud_model, self._version)
        self._cloud_internal = CloudModel.internal(self._cloud_model)

        ArdanaPaths.make_path(self._file_path)

    def build(self):
        LOG.info('%s()' % KenLog.fcn())

        control_planes = CloudModel.get(self._cloud_internal, 'control-planes')

        for cp_name, cp in control_planes.iteritems():

            cert_data = cp['lb-cert-data']
            for lb_provider, certs in cert_data.iteritems():
                for cert_name, cert_details in certs.iteritems():
                    self._write_cert_req_info(cert_name, cert_details)

    def _write_cert_req_info(self, cert_name, cert_details):

            filename = "%s/info/cert_reqs/%s" % (
                self._file_path, cert_name)
            if not os.path.exists(os.path.dirname(filename)):
                os.makedirs(os.path.dirname(filename))
            self.add_artifact(filename, ArtifactMode.CREATED)

            with open(filename, 'w') as f:
                f.write("[req]\n")
                f.write("distinguished_name = req_distinguished_name\n")
                f.write("req_extensions = v3_req\n")
                f.write("prompt = no\n")
                f.write("\n")
                f.write("[ req_distinguished_name ]\n")
                f.write("CN = \"ardana-vip\"\n")
                f.write("\n")
                f.write("[ v3_req ]\n")
                f.write("basicConstraints = CA:FALSE\n")
                f.write("keyUsage = nonRepudiation, digitalSignature, keyEncipherment\n")
                f.write("subjectAltName = @alt_names\n")
                f.write("\n")
                f.write("[ alt_names ]\n")

                dns_index = 1
                ip_index = 1

                for name in sorted(cert_details['names']):
                    f.write("DNS.%s = \"%s\"\n" % (dns_index, name))
                    dns_index += 1

                for addr in cert_details['vips']:
                    f.write("DNS.%s = \"%s\"\n" % (dns_index, addr))
                    dns_index += 1
                    f.write("IP.%s = \"%s\"\n" % (ip_index, addr))
                    ip_index += 1

    def get_dependencies(self):
        return ['persistent-state-2.0']
