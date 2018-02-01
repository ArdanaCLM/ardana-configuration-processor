#
# (c) Copyright 2015, 2016 Hewlett Packard Enterprise Development LP
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
from operator \
    import itemgetter

import logging
import logging.config

from ardana_configurationprocessor.cp.model.v2_0.ArdanaPaths \
    import ArdanaPaths
from ardana_configurationprocessor.cp.model.v2_0.CloudDescription \
    import CloudDescription
from ardana_configurationprocessor.cp.model.v2_0.CloudModel \
    import CloudModel

from ardana_configurationprocessor.cp.model.BuilderPlugin \
    import BuilderPlugin
from ardana_configurationprocessor.cp.model.BuilderPlugin \
    import ArtifactMode
from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog

from netaddr import IPAddress

LOG = logging.getLogger(__name__)


class HostsFileBuilder(BuilderPlugin):
    def __init__(self, instructions, models, controllers):
        super(HostsFileBuilder, self).__init__(
            2.0, instructions, models, controllers,
            'hosts-file-2.0')
        LOG.info('%s()' % KenLog.fcn())

        self.cloud_desc = self._models['CloudDescription']['cloud']
        self._file_path = ArdanaPaths.get_output_path(self._instructions, self.cloud_desc)
        self._file_path = os.path.join(self._file_path, 'net')

        self._cloud_model = self._models['CloudModel']
        self._cloud_version = CloudModel.version(self._cloud_model, self._version)
        self._cloud_internal = CloudModel.internal(self._cloud_model)

        ArdanaPaths.make_path(self._file_path)

    def build(self):
        LOG.info('%s()' % KenLog.fcn())

        file_name = os.path.join(self._file_path, 'hosts.hf')
        self.add_artifact(file_name, ArtifactMode.CREATED)

        allocated_addresses = CloudModel.get(self._cloud_internal, 'address_allocations')
        host_aliases = CloudModel.get(self._cloud_internal, 'host_aliases')
        host_names = CloudModel.get(self._cloud_internal, 'host_names')
        cloud_name = CloudDescription.get_cloud_name(self.cloud_desc)

        with open(file_name, 'w') as fp:
            fp.write("# Cloud: %s\n" % (cloud_name))
            fp.write("\n")
            fp.write("# Localhost Information\n")
            fp.write("127.0.0.1      localhost\n")
            fp.write("\n")
            fp.write("# The following lines are desirable for IPv6 capable hosts\n")
            fp.write("::1     localhost ip6-localhost ip6-loopback\n")
            fp.write("fe00::0 ip6-localnet\n")
            fp.write("ff00::0 ip6-mcastprefix\n")
            fp.write("ff02::1 ip6-allnodes\n")
            fp.write("ff02::2 ip6-allrouters\n")
            fp.write("\n")

            for group_name, group in allocated_addresses.iteritems():
                fp.write("#\n")
                fp.write("# Network Group: %s\n" % (group_name))
                fp.write("#\n")
                for network_name, network in group.iteritems():
                    fp.write("# Network: %s\n" % (network_name))
                    ips = []
                    for addr in network:
                        aliases = host_aliases.get(group_name,
                                                   {}).get(network_name,
                                                           {}).get(addr, [])
                        hostnames = host_names.get(group_name, {}).get(network_name, {})

                        # Need to find out if there is a hostname in the list of aliases,
                        # and if there are alaias for that hostname
                        hostname = ""
                        has_alias = False
                        for name in aliases:
                            if name in hostnames:
                                hostname = name
                            else:
                                has_alias = True

                        ip_version = IPAddress(addr).version
                        for name in aliases:

                            # If we have a hostname and one or more aliases then
                            # we want to have these as aliases in the hosts file
                            # so that any fqdn lookup will get the hostname not
                            # the alias
                            if hostname and has_alias:
                                if hostname == name:
                                    continue
                                else:
                                    name_string = "%s %s" % (hostname, name)
                            else:
                                name_string = name

                            if ip_version == 4:
                                # Expand the address to a string with leading
                                # spaces in each quad so that it sorts by
                                # version
                                ips.append(["%3s.%3s.%3s.%3s" % tuple(addr.split(".")), name_string])
                            else:
                                ips.append([addr, name_string])
                    for ip in sorted(ips, key=itemgetter(0)):
                        # Also add lowercase hostnames for eventlet-0.20.0, which treats /etc/hosts
                        # as case-sensitive
                        fp.write("%-16s %s %s\n" % (ip[0].replace(" ", ""), ip[1], ip[1].lower()))

    def get_dependencies(self):
        return ['persistent-state-2.0']
