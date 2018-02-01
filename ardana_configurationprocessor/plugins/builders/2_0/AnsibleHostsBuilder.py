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

from copy import deepcopy

from ardana_configurationprocessor.cp.model.v2_0.ArdanaPaths \
    import ArdanaPaths
from ardana_configurationprocessor.cp.model.v2_0.CloudDescription \
    import CloudDescription
from ardana_configurationprocessor.cp.model.v2_0.CloudModel \
    import CloudModel
from ardana_configurationprocessor.cp.model.v2_0 \
    import ServerState

from ardana_configurationprocessor.cp.model.BuilderPlugin \
    import BuilderPlugin
from ardana_configurationprocessor.cp.model.BuilderPlugin \
    import ArtifactMode
from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog


LOG = logging.getLogger(__name__)


class AnsibleHostsBuilder(BuilderPlugin):
    def __init__(self, instructions, models, controllers):
        super(AnsibleHostsBuilder, self).__init__(
            2.0, instructions, models, controllers,
            'ansible-hosts-2.0')
        LOG.info('%s()' % KenLog.fcn())
        self.cloud_desc = self._models['CloudDescription']['cloud']
        self._file_path = ArdanaPaths.get_output_path(self._instructions, self.cloud_desc)
        self._file_path = os.path.join(self._file_path, 'ansible')

        self._cloud_model = self._models['CloudModel']
        self._cloud_version = CloudModel.version(self._cloud_model, self._version)
        self._cloud_internal = CloudModel.internal(self._cloud_model)

        ArdanaPaths.make_path(self._file_path)

    def build(self):
        LOG.info('%s()' % KenLog.fcn())

        cloud_name = CloudDescription.get_cloud_name(self.cloud_desc)
        control_planes = deepcopy(CloudModel.get(self._cloud_internal, 'control-planes'))
        components = CloudModel.get(self._cloud_internal, 'components')
        server_groups = CloudModel.get(self._cloud_internal, 'server-groups')
        servers = CloudModel.get(self._cloud_internal, 'servers')

        for cp_name, cp in control_planes.iteritems():
            for cluster in cp['clusters']:
                if cluster.get('use-localhost', False):
                    local_name = "%s-%s-local" % (cp_name, cluster.get('cluster-prefix'))
                    cluster['servers'].append({'hostname': local_name,
                                               'ardana_ansible_host': local_name,
                                               'addr': "127.0.0.1"})

        filename = "%s/hosts/localhost" % (self._file_path)
        self.add_artifact(filename, ArtifactMode.CREATED)
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))

        with open(filename, 'w') as f:
            f.write("localhost\n")

        filename = "%s/hosts/verb_hosts" % (self._file_path)
        self.add_artifact(filename, ArtifactMode.CREATED)
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))

        with open(filename, 'w') as f:
            f.write("[localhost]\n")
            f.write("localhost\n")
            f.write("\n")

            f.write("[resources:children]\n")
            for cp_name in sorted(control_planes):
                cp = control_planes[cp_name]
                for cluster in cp['clusters']:
                    for server in cluster['servers']:
                        if (server['hostname'] != "%s-%s-local" %
                                (cp_name, cluster.get('cluster-prefix'))):
                            f.write("%s\n" % server['ardana_ansible_host'])
                for resource_group_name, resource_group in cp.get('resources', {}).iteritems():
                    for server in resource_group['servers']:
                        f.write("%s\n" % server['ardana_ansible_host'])
            f.write("\n")

            f.write("[ardana-hypervisors:children]\n")
            for cp_name in sorted(control_planes):
                cp = control_planes[cp_name]
                for cluster in cp['clusters']:
                    for server in cluster['servers']:
                        if server.get('vm-factory', False):
                            f.write("%s\n" % server['hostname'])
                for resource_group_name, resource_group in cp.get('resources', {}).iteritems():
                    for server in resource_group['servers']:
                        if server.get('vm-factory', False):
                            f.write("%s\n" % server['hostname'])
            f.write("\n")

            # Build a host group for vms on a vmfactory
            for cp_name in sorted(control_planes):
                cp = control_planes[cp_name]
                for cluster in cp['clusters']:
                    for server in cluster['servers']:
                        if server.get('vm-factory', False):
                            f.write("[%s-vms:children]\n" % server['ardana_ansible_host'])
                            for my_vm in server.get('vms'):
                                f.write("%s\n" % my_vm['ardana_ansible_host'])
                            f.write("\n")
                            f.write("[%s-all:children]\n" % server['ardana_ansible_host'])
                            f.write("%s\n" % server['ardana_ansible_host'])
                            f.write("%s-vms\n" % server['ardana_ansible_host'])
                            f.write("\n")

                for resource_group_name, resource_group in cp.get('resources', {}).iteritems():
                    for server in resource_group['servers']:
                        if server.get('vm-factory', False):
                            f.write("[%s-vms:children]\n" % server['ardana_ansible_host'])
                            for my_vm in server.get('vms'):
                                f.write("%s\n" % my_vm['ardana_ansible_host'])
                            f.write("\n")
                            f.write("[%s-all:children]\n" % server['ardana_ansible_host'])
                            f.write("%s\n" % server['ardana_ansible_host'])
                            f.write("%s-vms\n" % server['ardana_ansible_host'])
                            f.write("\n")

            # Build a list of all control_planes
            f.write("[%s:children]\n" % (cloud_name))
            for cp_name in sorted(control_planes):
                f.write("%s-%s\n" % (cloud_name, cp_name))
            f.write("\n")

            # List all clusters and resource in a control plane
            for cp_name in sorted(control_planes):
                cp = control_planes[cp_name]
                f.write("[%s-%s:children]\n" % (cloud_name, cp_name))
                for cluster in cp['clusters']:
                    f.write("%s-%s-%s\n" % (cloud_name, cp_name, cluster['name']))
                for resource_group_name in cp.get('resources', []):
                    f.write("%s-%s-%s\n" % (cloud_name, cp_name, resource_group_name))
                f.write("\n")

            # List all members of each clusters in a cp
            for cp_name in sorted(control_planes):
                cp = control_planes[cp_name]
                for cluster in cp['clusters']:
                    f.write("[%s-%s-%s:children]\n" % (cloud_name, cp_name, cluster['name']))
                    for server in sorted(cluster['servers'],
                                         key=lambda s: s['ardana_ansible_host']):
                        f.write("%s\n" % server['ardana_ansible_host'])
                    f.write("\n")

                    for server in sorted(cluster['servers'],
                                         key=lambda s: s['ardana_ansible_host']):
                        f.write("[%s]\n" % server['ardana_ansible_host'])
                        f.write("%s ansible_ssh_host=%s" % (server['ardana_ansible_host'], server['addr']))
                        if server.get('ansible_options'):
                            f.write(" %s" % server['ansible_options'])
                        f.write("\n\n")

                for resource_group_name, resource_group in cp.get('resources', {}).iteritems():
                    f.write("[%s-%s-%s:children]\n" % (cloud_name, cp_name, resource_group_name))
                    for server in sorted(resource_group['servers'],
                                         key=lambda s: s['ardana_ansible_host']):
                        f.write("%s\n" % server['ardana_ansible_host'])
                    f.write("\n")

                    for server in sorted(resource_group['servers'],
                                         key=lambda s: s['ardana_ansible_host']):
                        f.write("[%s]\n" % server['ardana_ansible_host'])
                        f.write("%s ansible_ssh_host=%s" % (server['ardana_ansible_host'], server['addr']))
                        if server.get('ansible_options'):
                            f.write(" %s" % server['ansible_options'])
                        f.write("\n\n")

            # Build list of hosts by component accross all cps
            component_list = {}
            for cp_name, cp in control_planes.iteritems():
                for component_name, component_data in cp['components'].iteritems():
                    if component_name not in components:
                        print "Warning: No data for %s when building host_vars" % component_name
                        continue

                    component_mnemonic = components[component_name]['mnemonic']

                    if component_mnemonic not in component_list:
                        component_list[component_mnemonic] = {}

                    if cp_name not in component_list[component_mnemonic]:
                        component_list[component_mnemonic][cp_name] = {}

                    for cluster in cp['clusters']:
                        if (component_name in cluster['service-components']):

                            if cluster['name'] not in component_list[component_mnemonic][cp_name]:
                                component_list[component_mnemonic][cp_name][cluster['name']] = []
                            host_list = component_list[component_mnemonic][cp_name][cluster['name']]

                            for server in cluster['servers']:
                                host_list.append(server['ardana_ansible_host'])

                    if 'resources' in cp:
                        for r_name, resources in cp['resources'].iteritems():
                            if (component_name in resources['service-components']):

                                if r_name not in component_list[component_mnemonic][cp_name]:
                                    component_list[component_mnemonic][cp_name][r_name] = []
                                host_list = component_list[component_mnemonic][cp_name][r_name]

                                for server in resources['servers']:
                                    host_list.append(server['ardana_ansible_host'])

            # Build a list of the first host of each component in each control plane
            first_member_list = {}
            for name in sorted(component_list):

                if name not in first_member_list:
                    first_member_list[name] = []

                for cp_name, clusters in component_list[name].iteritems():
                    hosts = []
                    for cluster_name, cluster_hosts in clusters.iteritems():
                        hosts.extend(cluster_hosts)
                    if len(hosts) > 0:
                        first_member_list[name].append(sorted(hosts)[0])

            # Add in any deleted components
            for cp_name, cp in control_planes.iteritems():
                for cluster in cp['clusters']:
                    for server in cluster['servers']:
                        self._add_deleted_components(component_list, components,
                                                     server, cp_name, cluster['name'])

                for r_name, resources in cp.get('resources', {}).iteritems():
                    for server in resources.get('servers', []):
                        self._add_deleted_components(component_list, components,
                                                     server, cp_name, r_name)

            for component_name in sorted(component_list):
                component_data = component_list[component_name]

                # Check there is at least one host
                host_count = 0
                for cp_name, cp_data in component_data.iteritems():
                    for cluster_name, hosts in cp_data.iteritems():
                        host_count += len(hosts)
                if host_count == 0:
                    continue

                f.write("[%s:children]\n" % (component_name))
                for cp_name in sorted(component_data):
                    f.write("%s-%s\n" % (component_name, cp_name))
                f.write("\n")

                for cp_name in sorted(component_data):
                    f.write("[%s-%s:children]\n" % (component_name, cp_name))
                    cluster_data = component_data[cp_name]
                    for cluster in sorted(cluster_data):
                        f.write("%s-%s-%s\n" % (component_name, cp_name, cluster))
                    f.write("\n")

                    for cluster in sorted(cluster_data):
                        f.write("[%s-%s-%s:children]\n" % (component_name, cp_name, cluster))
                        hosts = cluster_data[cluster]
                        for host in sorted(hosts):
                            f.write("%s\n" % host)
                        f.write("\n")

                if component_name in first_member_list:
                    f.write("[%s--first-member:children]\n" % (component_name))
                    for host in sorted(first_member_list[component_name]):
                        f.write("%s\n" % host)
                    f.write("\n")

            # Build list of server groups
            for sg_name, sg in server_groups.iteritems():
                f.write("[%s:children]\n" % (sg_name))
                for child in sg.get('server-groups', []):
                    f.write("%s\n" % child)
                for server in sg.get('servers', []):
                    if server['state'] == ServerState.ALLOCATED:
                        f.write("%s\n" % server['ardana_ansible_host'])
                f.write("\n")

            # Build a list of host aliases
            for server in servers:
                if server['state'] != ServerState.ALLOCATED:
                    continue
                if server['hostname'] != server['ardana_ansible_host']:
                    f.write("[%s:children]\n" % server['hostname'])
                    f.write("%s\n\n" % server['ardana_ansible_host'])
                for iface, iface_data in server['interfaces'].iteritems():
                    for net_name, net in iface_data.get('networks', {}).iteritems():
                        if 'addr' in net:
                            if (net['hostname'] != server['ardana_ansible_host'] and
                                    net['hostname'] != server['hostname']):
                                f.write("[%s:children]\n" % net['hostname'])
                                f.write("%s\n\n" % server['ardana_ansible_host'])

    def _add_deleted_components(self, deleted_components, components, server, cp_name, group_name):

        previous_config = server.get('previous_config', {})
        for previous_component in previous_config.get('components', []):
            if previous_component in server.get('components', []):
                continue

            print "Component %s deleted from server %s" % (previous_component, server['name'])

            if previous_component not in components:
                print "Warning: No data for %s when building host_vars" % previous_component
                continue

            component_mnemonic = components[previous_component]['mnemonic'] + "-DELETED"

            if component_mnemonic not in deleted_components:
                deleted_components[component_mnemonic] = {}

            if cp_name not in deleted_components[component_mnemonic]:
                deleted_components[component_mnemonic][cp_name] = {}

            if group_name not in deleted_components[component_mnemonic][cp_name]:
                deleted_components[component_mnemonic][cp_name][group_name] = []
            deleted_components[component_mnemonic][cp_name][group_name].append(server['ardana_ansible_host'])

    def get_dependencies(self):
        return ['persistent-state-2.0']
