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

from ardana_configurationprocessor.cp.model.v2_0.CloudModel \
    import CloudModel
from ardana_configurationprocessor.cp.model.v2_0.ServerGroup \
    import ServerGroup

from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog
from ardana_configurationprocessor.cp.model.GeneratorPlugin \
    import GeneratorPlugin

from ardana_configurationprocessor.cp.model.v2_0 \
    import AllocationPolicy
from ardana_configurationprocessor.cp.model.v2_0 \
    import ServerState

from ardana_configurationprocessor.cp.model.StatePersistor \
    import StatePersistor

from ardana_configurationprocessor.cp.model.v2_0.ArdanaPaths \
    import ArdanaPaths


from copy import deepcopy
from netaddr import IPNetwork, IPAddress, IPRange, IPSet

LOG = logging.getLogger(__name__)


class CloudCpLiteGenerator(GeneratorPlugin):

    def __init__(self, instructions, models, controllers):
        super(CloudCpLiteGenerator, self).__init__(
            2.0, instructions, models, controllers,
            'cloud-cplite-2.0')

        LOG.info('%s()' % KenLog.fcn())

        self._address_state_persistor = StatePersistor(
            self._models, self._controllers, 'ip_addresses.yml')

        self._server_allocation_state_persistor = StatePersistor(
            self._models, self._controllers, 'server_allocations.yml')

        self.cloud_desc = self._models['CloudDescription']['cloud']
        self._file_path = ArdanaPaths.get_output_path(self._instructions, self.cloud_desc)
        ArdanaPaths.make_path(self._file_path)

        self.explaination = ""
        self.explain_level = 0
        self.explain_prefix = ""
        self.explain_uline = "=-"

    def explain_block(self, block_name, level=0):
        self.explaination += '\n' + " " * (level - 1) * 2 + block_name + '\n'
        if level < len(self.explain_uline):
            uline = self.explain_uline[level]
            self.explaination += " " * (level - 1) * 2 + uline * len(block_name) + '\n'
        self.explain_level = level
        self.explain_prefix = " " * level * 2

    def explain(self, message):
        self.explaination += self.explain_prefix + message + "\n"

    def write_explanation(self):
        filename = "%s/info/explain.txt" % (self._file_path)
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))

        with open(filename, 'w') as fp:
            fp.write(self.explaination)

    def generate(self):
        LOG.info('%s()' % KenLog.fcn())
        self._generate_cp_lite()

    def _generate_cp_lite(self):
        LOG.info('%s()' % KenLog.fcn())
        cloud_data = self._models['CloudDescription']['cloud']
        cloud_version = CloudModel.version(self._models['CloudModel'], self._version)
        cloud_internal = CloudModel.internal(self._models['CloudModel'])

        remove_deleted_servers = self._instructions['remove_deleted_servers']
        free_unused_addresses = self._instructions['free_unused_addresses']

        # Components
        components = CloudModel.get(cloud_internal, 'components')

        network_addresses = {}
        bm_servers = []

        # Servers
        if 'servers' in cloud_version:
            bm_servers.extend(cloud_version['servers'])

        # Build a list of server addresses so we can
        # reserve them
        server_addresses = {}
        for s in bm_servers:
            server_addresses[s['ip-addr']] = s['id']

        # Control Planes
        control_planes = CloudModel.get(cloud_internal, 'control-planes')

        # Network Groups
        network_groups = CloudModel.get(cloud_internal, 'network-groups')

        # Networks
        networks = CloudModel.get(cloud_internal, 'networks')
        for net in networks.values():

            network_addresses[net['name']] = {'allocated': [], 'sets': None}
            if 'cidr' in net:
                net_ip_set, net_vips = self.process_network(net)
                network_addresses[net['name']]['sets'] = net_ip_set
                network_addresses[net['name']]['vips'] = net_vips
                self.generate_addresses(network_addresses[net['name']],
                                        server_addresses)

        # Server Groups
        server_groups = CloudModel.get(cloud_internal, 'server-groups')
        default_server_group = CloudModel.get(cloud_internal, 'default-server-group')

        # Servers
        servers = CloudModel.get(cloud_internal, 'servers')

        ####################################
        #
        # End of reading input data
        #
        ###################################

        # Get the persisted server data.  Take a copy so we don't update
        # the persisted state by accident
        persisted_allocations = \
            deepcopy(self._server_allocation_state_persistor.recall_info())

        # Keep track of previously allocated servers by cp, cluster, and member_id
        server_allocations = {}
        server_ids = []

        for server in servers:
            server_ids.append(server['id'])

            # If this server was allocated in a previous run keep it as the
            # same member_id in the same cluster.
            # If the server has been deleted at some stage then it can return
            # provided the cluster limit isn't exceeded
            if server['id'] not in persisted_allocations:
                server['state'] = ServerState.AVAILABLE
            else:
                alloc = persisted_allocations[server['id']]
                if 'cp_name' not in alloc:
                    server['state'] = ServerState.AVAILABLE
                elif alloc['state'] == ServerState.DELETED and remove_deleted_servers:
                    server['state'] = ServerState.AVAILABLE
                    self._server_allocation_state_persistor.delete_info([server['id']])
                else:
                    server['state'] = alloc['state']
                    server['previous_config'] = alloc.get('previous_config', {})
                    # Track where it is / was used
                    cp_name = alloc['cp_name']
                    if alloc['type'] == 'cluster':
                        group_name = alloc['cluster_name']
                    else:
                        group_name = alloc['resource_name']
                    member_id = alloc['member_id']

                    if cp_name not in server_allocations:
                        server_allocations[cp_name] = {}
                    if group_name not in server_allocations[cp_name]:
                        server_allocations[cp_name][group_name] = \
                            {'member_ids': set(),
                             ServerState.ALLOCATED: [],
                             ServerState.DELETED: []}

                    alloc['server'] = server
                    server_allocations[cp_name][group_name][alloc['state']].append(alloc)
                    server_allocations[cp_name][group_name]['member_ids'].add(member_id)

        # Check if we have any persisted allocations for a group that no longer
        # exists in the model.

        # Build a map of the type for each group so we can report it any error message
        persisted_group_type = {}
        for id, data in persisted_allocations.iteritems():
            group_type = data.get('type')
            if group_type == 'cluster':
                persisted_group_type[data['cluster_name']] = group_type
            elif group_type == 'resource':
                persisted_group_type[data['resource_name']] = group_type

        for cp_name, cp in control_planes.iteritems():
            current_groups = set()
            for cluster in cp['clusters']:
                current_groups.add(cluster['name'])
            for r in cp.get('resources', []):
                current_groups.add(r['name'])

            for group_name in server_allocations.get(cp_name, []):
                if group_name not in current_groups:
                    msg = ("Cluster deleted from input model\n"
                           "Persisted server allocations found for %s "
                           "'%s' that no longer exists in control plane %s. " %
                           (persisted_group_type.get(group_name, ''), group_name, cp_name))
                    for alloc_data in server_allocations[cp_name][group_name]['allocated']:
                        msg += ("\n         member:%s server:%s (%s)" %
                                (alloc_data['member_id'],
                                 alloc_data['server']['id'], alloc_data['server']['addr']))
                    msg += ("\n    If these servers are no longer used they must be "
                            "removed from the input model.")
                    self.add_error(msg)

        # Mark any servers which are in persisted state but not the list of servers
        # as deleted.  Keep the information about where they were used in the state
        # for now, and show the member id is used unless we've been given the
        # remove_deleted_servers option on the command line
        deleted_msg = ""
        for id, info in persisted_allocations.iteritems():
            if id not in server_ids:
                if remove_deleted_servers:
                    self._server_allocation_state_persistor.delete_info([id])
                else:
                    # Still track that we had a server in a particular slot so
                    # we don't reallocate that identity
                    if 'cp_name' in info:
                        cp_name = info['cp_name']
                        if info['type'] == 'cluster':
                            group_name = info['cluster_name']
                        else:
                            group_name = info['resource_name']
                        member_id = info['member_id']

                        # Recored that the member_id is still associated with
                        # a server we have persisted data for, so it doesn't
                        # get reused.
                        if cp_name not in server_allocations:
                            server_allocations[cp_name] = {}
                        if group_name not in server_allocations[cp_name]:
                            server_allocations[cp_name][group_name] = \
                                {'member_ids': set(),
                                 ServerState.ALLOCATED: [],
                                 ServerState.DELETED: []}
                        server_allocations[cp_name][group_name]['member_ids'].add(member_id)
                        deleted_msg += ("\n         %s (control plane:%s cluster:%s member:%s)" %
                                        (id, cp_name, group_name, member_id))

                        info['state'] = ServerState.DELETED
                        if 'previous_config' in info:
                            del info['previous_config']
                        self._server_allocation_state_persistor.persist_info({id: info})

        if deleted_msg:
            msg = ("Servers deleted from input model\n"
                   "The following server allocations are persisted but not used: "
                   "%s\n"
                   "    To free these allocations rerun the config processor playbook with "
                   "'-e remove_deleted_servers=True'.  If running the config processor direct "
                   "from the command line use '--remove_deleted_servers'" % deleted_msg)
            self.add_warning(msg)

        # Intialise the list of zone types.  This is where we keep track of zones for
        # those services that declare they are interested (nova, cinder, swift, etc)
        for cp_name, cp in control_planes.iteritems():
            cp['zone-types'] = {}

        # Walk through the Control Planes Allocating servers
        for cp_name in sorted(control_planes):
            self.explain_block("Allocate Servers for control plane %s" % cp_name)
            cp = control_planes[cp_name]

            hostname_data = cloud_data.get('hostname-data',
                                           {'host-prefix': cloud_data['name'],
                                            'member-prefix': '-m'})
            cp['hostname-data'] = hostname_data
            cp_allocations = server_allocations.get(cp_name, {})

            for cluster in cp['clusters']:
                self.explain_block("cluster: %s" % cluster['name'], level=1)

                # List of zones comes from the CP or the cluster
                failure_zones = cluster.get('failure-zones',
                                            cp.get('failure-zones', []))

                # Get the list of groups that are our failure zones
                failure_zone_groups = []
                for zone_name in failure_zones:
                    failure_zone_groups.append(server_groups[zone_name])

                # Update the list of per service zones in this control plane
                self._update_cp_zones(cp, failure_zones,
                                      cluster['service-components'],
                                      components)

                # Get the allocation policy
                policy = cluster.get('allocation-policy',
                                     AllocationPolicy.STRICT)

                cluster['servers'] = []
                allocations = cp_allocations.get(cluster['name'], {})
                allocated_zones = set()

                # Restore the existing Allocations
                for alloc in allocations.get(ServerState.ALLOCATED, []):
                    server = alloc['server']
                    zone = ServerGroup.get_zone(failure_zone_groups,
                                                server['id'])
                    if zone:
                        allocated_zones.add(zone)
                    elif failure_zones:
                        msg = ("Allocated server %s in cluster %s:%s is not "
                               "in the specified failure zones: %s" %
                               (server['id'], cp_name, cluster['name'],
                                failure_zones))
                        self.add_warning(msg)

                    self.explain("Persisted allocation for server '%s' (%s)" %
                                 (server['id'], zone))
                    self._add_server_to_cluster(server,
                                                alloc['member_id'], zone,
                                                cp, cluster, hostname_data)

                # Check if we're over the maximum size
                if ('max-count' in cluster and
                        len(cluster['servers']) > cluster['max-count']):
                    msg = ("Due to existing allocations %s:%s contains %s servers "
                           "which is now more that the max value specified of %s." %
                           (cp['name'], cluster['name'], len(cluster['servers']),
                            cluster['max-count']))
                    self.add_warning(msg)

                # Restore any servers that were deleted but are now back with us
                for alloc in allocations.get(ServerState.DELETED, []):
                    if ('max-count' in cluster and
                            len(cluster['servers']) >= cluster['max-count']):
                        msg = ("Cannot restore server %s as member %s of %s:%s as it "
                               "would exceed the max count of %d" %
                               (alloc['server']['id'], alloc['member_id'],
                                cp_name, cluster['name'], cluster['max-count']))
                        self.add_warning(msg)
                        continue
                    else:
                        server = alloc['server']
                        zone = ServerGroup.get_zone(failure_zone_groups,
                                                    server['id'])

                        if not zone and failure_zones:
                            msg = ("Previously deleted server %s in cluster %s:%s "
                                   "can not be restored as it is not "
                                   "in the specified failure zones: %s" %
                                   (server['id'], cp_name, cluster['name'],
                                    failure_zones))
                            self.add_warning(msg)
                        else:
                            if zone:
                                allocated_zones.add(zone)

                            self.explain("Persisted allocation for previously "
                                         "deleted server '%s' (%s)" % (server['id'], zone))
                            self._add_server_to_cluster(alloc['server'],
                                                        alloc['member_id'], zone,
                                                        cp, cluster, hostname_data)
                            msg = ("Previously deleted server restored\n"
                                   "Server '%s' has been restored to cluster %s:%s" %
                                   (alloc['server']['id'], cp_name, cluster['name']))
                            self.add_warning(msg)

                # Build a list of all the failure zones to allocate from
                search_zones = set(failure_zones)

                # If using the strict allocation policy excluding
                # any zones we already have servers from
                if policy == AllocationPolicy.STRICT:
                    for zone in allocated_zones:
                        search_zones.remove(zone)

                    # If the list of search zones is empty then we may already have
                    # servers from each zone so reset the list
                    if not search_zones:
                        search_zones = set(failure_zones)

                # Allocate any servers required to bring us up to the required
                # count
                member_id = 0
                while True:
                    if ('max-count' in cluster and
                            len(cluster['servers']) >= cluster['max-count']):
                        break

                    # Don't use member IDs that belong to current or deleted servers
                    member_id += 1
                    while member_id in allocations.get('member_ids', set()):
                        member_id += 1

                    # Build the list of zones to search
                    from_zones = []
                    for zone_name in search_zones:
                        from_zones.append(server_groups[zone_name])

                    # Find a free server for the required role
                    self.explain("Searching for server with role %s in zones: %s" %
                                 (cluster['server-role'], search_zones))
                    s, zone_name = ServerGroup.get_server(from_zones,
                                                          state=ServerState.AVAILABLE,
                                                          roles=cluster['server-role'],
                                                          default=default_server_group)

                    if s:
                        self.explain("Allocated server '%s' (%s)" %
                                     (s['id'], zone_name))
                        self._add_server_to_cluster(s, member_id, zone_name,
                                                    cp, cluster, hostname_data)

                        if policy == AllocationPolicy.STRICT:
                            # Remove the zone this server came from the search list
                            if zone_name:
                                search_zones.remove(zone_name)

                            # If the list is now empty then reset it
                            if not search_zones:
                                search_zones = set(failure_zones)

                    else:
                        if ('min-count' in cluster and
                                len(cluster['servers']) < cluster['min-count']):
                            msg = ("Couldn't allocate %d servers with role %s for "
                                   "cluster %s in %s" %
                                   (cluster['min-count'], cluster['server-role'],
                                    cluster['name'], cp_name))
                            if search_zones:
                                msg += " from zones %s" % (search_zones)
                            self.add_error(msg)
                        break

                # Save the state of all allocated servers
                state = {}
                for s in cluster['servers']:
                    s_config = deepcopy(s)
                    if 'previous_config' in s_config:
                        del s_config['previous_config']
                    state[s['id']] = {'state': s['state'],
                                      'type': 'cluster',
                                      'vm-factory': s.get('vm-factory', False),
                                      'hypervisor-id': s.get('hypervisor-id', None),
                                      'cp_name': cp['name'],
                                      'cluster_name': cluster['name'],
                                      'member_id': s['member_id'],
                                      'previous_config': s_config}
                self._server_allocation_state_persistor.persist_info(state)

            #
            # Now do the same thing for resource nodes
            #
            if 'resources' in cp:

                # Convert the list to a dict so we can reference it by name
                resource_nodes = {}
                for r in cp['resources']:
                    resource_nodes[r['name']] = r
                cp['resources'] = resource_nodes

                for r_name, resources in cp['resources'].iteritems():
                    self.explain_block("resource: %s" % r_name, level=1)

                    # List of zones comes from the CP or the resource group
                    failure_zones = resources.get('failure-zones',
                                                  cp.get('failure-zones', []))

                    # Get the list of groups that are our failure zones
                    failure_zone_groups = []
                    for zone_name in failure_zones:
                        failure_zone_groups.append(server_groups[zone_name])

                    # Get the allocation policy.  Default policy for a
                    # resource group is any  - this is one of the few
                    # differences between a cluster and a reosurce group
                    policy = resources.get('allocation-policy',
                                           AllocationPolicy.ANY)

                    # Update the list of per service zones in this control plane
                    self._update_cp_zones(cp, failure_zones,
                                          resources['service-components'],
                                          components)

                    resources['servers'] = []
                    allocations = cp_allocations.get(r_name, {})
                    allocated_zones = set()

                    # Restore the existing Allocations
                    for alloc in allocations.get(ServerState.ALLOCATED, []):
                        server = alloc['server']
                        zone = ServerGroup.get_zone(failure_zone_groups,
                                                    server['id'])
                        if zone:
                            allocated_zones.add(zone)
                        elif failure_zones:
                            msg = ("Allocated server %s in resource group %s:%s is not "
                                   "in the specified failure zones: %s" %
                                   (server['id'], cp_name, r_name,
                                    failure_zones))
                            self.add_warning(msg)

                        self.explain("Persisted allocation for server '%s' (%s)" %
                                     (server['id'], zone))
                        self._add_server_to_resources(alloc['server'],
                                                      alloc['member_id'], zone,
                                                      cp, resources, hostname_data)

                    # Check if we're over the maximum size
                    if ('max-count' in resources and
                            len(resources['servers']) > resources['max-count']):
                        msg = ("Due to existing allocations %s:%s contains %s servers "
                               "which is now more that the max value specified of %s." %
                               (cp['name'], r_name, len(resources['servers']),
                                resources['max-count']))
                        self.add_warning(msg)

                    # Restore any servers that were deleted but are now back with us
                    for alloc in allocations.get(ServerState.DELETED, []):
                        if ('max-count' in resources and
                                len(resources['servers']) >= resources['max-count']):
                            msg = ("Cannot restore server %s to %s:%s as it "
                                   "would exceed the max count of %d" %
                                   (alloc['server']['id'], cp_name, r_name,
                                    resources['max-count']))
                            self.add_warning(msg)
                            continue
                        else:
                            server = alloc['server']
                            zone = ServerGroup.get_zone(failure_zone_groups,
                                                        server['id'])
                            if not zone and failure_zones:
                                msg = ("Previously deleted server %s in resource group %s:%s "
                                       "can not be restored as it is not "
                                       "in the specified failure zones: %s" %
                                       (server['id'], cp_name, r_name,
                                        failure_zones))
                                self.add_error(msg)
                            else:
                                if zone:
                                    allocated_zones.add(zone)

                                self.explain("Persisted allocation for previously "
                                             "deleted server '%s' (%s)" % (server['id'], zone))

                                self._add_server_to_resources(alloc['server'],
                                                              alloc['member_id'],
                                                              zone,
                                                              cp, resources, hostname_data)

                                msg = ("Previously deleted server restored\n"
                                       "Server '%s' has been restored to resource group %s:%s" %
                                       (alloc['server']['id'], cp_name, r_name))
                                self.add_warning(msg)

                    # Build a list of all the failure zones to allocate from,
                    search_zones = set(failure_zones)

                    # If using the strict allocation policy excluding
                    # any zones we already have servers from
                    if policy == AllocationPolicy.STRICT:
                        for zone in allocated_zones:
                            search_zones.remove(zone)

                        # If the list of search zones is empty then we may already have
                        # servers from each zone so reset the list
                        if not search_zones:
                            search_zones = set(failure_zones)

                    # Allocate any servers required to bring us up to the required
                    # count
                    member_id = 0
                    while True:
                        if ('max-count' in resources and
                                len(resources['servers']) >= resources['max-count']):
                            break

                        # Don't use member IDs that belong to current or deleted servers
                        member_id += 1
                        while member_id in allocations.get('member_ids', set()):
                            member_id += 1

                        # Build the list of zones to search
                        from_zones = []
                        for zone_name in search_zones:
                            from_zones.append(server_groups[zone_name])

                        # Find a free server for the required role
                        s = None
                        self.explain("Searching for server with role %s in zones: %s" %
                                     (resources['server-role'], search_zones))
                        s, zone_name = ServerGroup.get_server(from_zones,
                                                              state=ServerState.AVAILABLE,
                                                              roles=resources['server-role'],
                                                              default=default_server_group)

                        if s:
                            self.explain("Allocated server '%s' (%s)" %
                                         (s['id'], zone_name))
                            self._add_server_to_resources(s, member_id, zone_name,
                                                          cp, resources, hostname_data)

                            if policy == AllocationPolicy.STRICT:
                                # Remove the zone this server came from the search list
                                if zone_name:
                                    search_zones.remove(zone_name)

                                # If the list is now empty then reset it
                                if not search_zones:
                                    search_zones = set(failure_zones)

                        else:
                            if ('min-count' in resources and
                                    len(resources['servers']) < resources['min-count']):
                                msg = ("Couldn't allocate %d servers with role %s for "
                                       "resource group %s in %s" %
                                       (resources['min-count'], resources['server-role'],
                                        r_name, cp_name))
                                if search_zones:
                                    msg += " from zones %s" % (search_zones)
                                self.add_error(msg)
                            break

                    # Save the state of all allocated servers
                    state = {}
                    for s in resources['servers']:
                        s_config = deepcopy(s)
                        if 'previous_config' in s_config:
                            del s_config['previous_config']
                        state[s['id']] = {'state': s['state'],
                                          'type': 'resource',
                                          'vm-factory': s.get('vm-factory', False),
                                          'hypervisor-id': s.get('hypervisor-id', None),
                                          'cp_name': cp['name'],
                                          'resource_name': r_name,
                                          'member_id': s['member_id'],
                                          'previous_config': s_config}
                    self._server_allocation_state_persistor.persist_info(state)

        # Now check that we've allocated all required vm-factories
        # and that we haven't applied any components that cannot run on a vm
        # to vms
        vmf_required = set()
        for server in servers:
            if server['state'] == ServerState.ALLOCATED and server.get('hypervisor-id', None):
                vmf_required.add(server['hypervisor-id'])
                for comp_name in server.get('components', []):
                    if not components[comp_name].get('can-run-on-a-vm', True):
                        msg = ("vm '%s' with server-role '%s' has been assigned to "
                               "control-plane '%s' with a component '%s' that cannot "
                               "run on a vm" %
                               (server['id'], server['role'], server['control-plane-name'],
                                comp_name))
                        self.add_error(msg)

        vmf_allocated = set()
        for server in servers:
            if server['state'] == ServerState.ALLOCATED and server.get('vm-factory', False):
                vmf_allocated.add(server['id'])
        if vmf_required != vmf_allocated:
            vmf_unallocated = list(vmf_required - vmf_allocated)
            for vmf in vmf_unallocated:
                for server in servers:
                    if server['id'] == vmf:
                        msg = ("Server '%s' in server-group '%s' with role '%s' which is a "
                               "host-node for vms that have been allocated has not itself been "
                               "allocated.  Please increase the max-count for the cluster or "
                               "resource pool with its role and server-group." %
                               (vmf, server['server_group'], server['role']))
                        self.add_error(msg)
                        break

        # Remove the parent relationships in server_groups
        # now we're done processign because it causes a
        # circular reference
        for group_name, group in server_groups.iteritems():
            ServerGroup.clear_parent(group)

        # Resolve the networks for each server
        self.explain_block("Resolve Networks for Servers")
        for cp_name, cp in control_planes.iteritems():
            cp_prefix = cp.get('control-plane-prefix', cp['name'])
            hostname_prefix = "%s-%s" % (hostname_data['host-prefix'], cp_prefix)
            for cluster in cp['clusters']:
                for s in cluster['servers']:
                    self.resolve_server_networks(s, components, network_groups, network_addresses,
                                                 cluster, hostname_prefix, cp)
                    s['ardana_ansible_host'] = s['name']

            if 'resources' in cp:
                for r_name, resources in cp['resources'].iteritems():
                    for s in resources['servers']:
                        self.resolve_server_networks(s, components, network_groups, network_addresses,
                                                     resources, hostname_prefix, cp)
                        s['ardana_ansible_host'] = s['name']

        # Set up the dimensions for each server.  Note that if a server was allocated
        # to a now deleted cluster then an error will have already been logged, so skip
        # those here by checking for the cluster-name key
        for server in servers:
            if server['state'] == ServerState.ALLOCATED and 'cluster-name' in server:
                server['dimensions'] = {'hostname': server['hostname'],
                                        'cluster': server['cluster-name'],
                                        'control_plane': server['control-plane-name'],
                                        'cloud_name': cloud_data['name']}

        # Populate the service views
        service_view = {'by_region': {},
                        'by_service': {},
                        'by_rack': {}}

        for cp_name in sorted(control_planes):
            cp = control_planes[cp_name]
            cp_service_view = service_view['by_region'][cp_name] = {}

            cp['components'] = {}

            for cluster in cp['clusters']:
                for component_name in cluster['service-components']:
                    if component_name not in cp['components']:
                        cp['components'][component_name] = {'hosts': [],
                                                            'clusters': []}
                for s in cluster['servers']:
                    for component_name in s['components']:
                        component = components.get(component_name, {})
                        component_parent = component['service']

                        # Add to list of components in this cp
                        cp['components'][component_name]['hosts'].append(s['hostname'])
                        if cluster['name'] not in cp['components'][component_name]['clusters']:
                            cp['components'][component_name]['clusters'].append(cluster['name'])

                        # Add to by region service view
                        if component_parent not in cp_service_view:
                            cp_service_view[component_parent] = {}
                        if component_name not in cp_service_view[component_parent]:
                            cp_service_view[component_parent][component_name] = []
                        cp_service_view[component_parent][component_name].append(s['hostname'])

                        # Add to by_service service view
                        if component_parent not in service_view['by_service']:
                            service_view['by_service'][component_parent] = {}
                        if cp_name not in service_view['by_service'][component_parent]:
                            service_view['by_service'][component_parent][cp_name] = {}
                        if component_name not in service_view['by_service'][component_parent][cp_name]:
                            service_view['by_service'][component_parent][cp_name][component_name] = []
                        service_view['by_service'][component_parent][cp_name][component_name].append(s['hostname'])

                        # Add to by_rack service view
                        if s['rack'] not in service_view['by_rack']:
                            service_view['by_rack'][s['rack']] = {}
                        if s['hostname'] not in service_view['by_rack'][s['rack']]:
                            s_view = service_view['by_rack'][s['rack']][s['hostname']] = {}
                        if component_parent not in s_view:
                            s_view[component_parent] = []
                        if component_name not in s_view[component_parent]:
                            s_view[component_parent].append(component_name)

            if 'resources' in cp:

                for r_name, resources in cp['resources'].iteritems():
                    for component_name in resources['service-components']:
                        if component_name not in cp['components']:
                            cp['components'][component_name] = {'hosts': [],
                                                                'clusters': []}
                    for s in resources['servers']:
                        for component_name in s['components']:
                            component = components.get(component_name, {})
                            component_parent = component['service']

                            cp['components'][component_name]['hosts'].append(s['hostname'])
                            if r_name not in cp['components'][component_name]['clusters']:
                                cp['components'][component_name]['clusters'].append(r_name)

                            # Add to by region service view
                            if component_parent not in cp_service_view:
                                cp_service_view[component_parent] = {}
                            if component_name not in cp_service_view[component_parent]:
                                cp_service_view[component_parent][component_name] = []
                            cp_service_view[component_parent][component_name].append(s['hostname'])

                            # Add to by_service service view
                            if component_parent not in service_view['by_service']:
                                service_view['by_service'][component_parent] = {}
                            if cp_name not in service_view['by_service'][component_parent]:
                                service_view['by_service'][component_parent][cp_name] = {}
                            if component_name not in service_view['by_service'][component_parent][cp_name]:
                                service_view['by_service'][component_parent][cp_name][component_name] = []
                            service_view['by_service'][component_parent][cp_name][component_name].append(s['hostname'])

                            # Add to by_rack service view
                            if s['rack'] not in service_view['by_rack']:
                                service_view['by_rack'][s['rack']] = {}
                            if s['hostname'] not in service_view['by_rack'][s['rack']]:
                                s_view = service_view['by_rack'][s['rack']][s['hostname']] = {}
                            if component_parent not in s_view:
                                s_view[component_parent] = []
                            if component_name not in s_view[component_parent]:
                                s_view[component_parent].append(component_name)

        #
        # Generate cluster list for services
        #
        for cp_name in sorted(control_planes):
            cp = control_planes[cp_name]
            for comp_name, comp_data in cp.get('components', {}).iteritems():
                comp_service = components[comp_name]['service']
                if 'clusters' not in cp['services'][comp_service]:
                    cp['services'][comp_service]['clusters'] = set()
                cp['services'][comp_service]['clusters'].update(set(comp_data.get('clusters', [])))

            # Convert back to a list
            for service_name, service_data in cp['services'].iteritems():
                service_data['clusters'] = list(service_data['clusters'])

        #
        # Add network routes and VIPs
        #

        for cp_name in sorted(control_planes):
            cp = control_planes[cp_name]

            # build a list of all servers in the control plane
            cp_servers = []
            for cluster in cp['clusters']:
                for s in cluster['servers']:
                    cp_servers.append(s)

            for r_name, resources in cp.get('resources', {}).iteritems():
                for s in resources['servers']:
                    cp_servers.append(s)

            # Find all of the networks, services and endpoints in this control plane
            cp_networks = set()
            cp_endpoints = {}
            cp_service_vips = {}

            for s in cp_servers:
                for iface_name, iface in s['interfaces'].iteritems():
                    for net_name, net in iface['networks'].iteritems():
                        cp_networks.add(net_name)
                        for component_name, ep in net['endpoints'].iteritems():
                            if component_name not in cp_endpoints:
                                cp_endpoints[component_name] = {'network-group': net['network-group'],
                                                                'host-tls': ep['use-tls'],
                                                                'hosts': [],
                                                                'has-vip': False}

                            if component_name in s.get('service-vips', {}):
                                if component_name not in cp_service_vips:
                                    cp_service_vips[component_name] = {}

                                if s['cluster-name'] not in cp_service_vips[component_name]:
                                    cp_service_vips[component_name][s['cluster-name']] = {'failure_zones': []}

                                cluster_ep = cp_service_vips[component_name][s['cluster-name']]
                                cluster_ep['vip'] = s['service-vips'][component_name]
                                if s['failure-zone'] not in cluster_ep['failure_zones']:
                                    cluster_ep['failure_zones'].append(s['failure-zone'])

                            cp_endpoints[component_name]['hosts'].append(
                                {'hostname': net['hostname'],
                                 'network': net['name'],
                                 'ip_address': net['addr'],
                                 'member_id': s['member_id'],
                                 'host_dimensions': s['dimensions'],
                                 'ardana_ansible_host': s['ardana_ansible_host']})
            cp['service-vips'] = cp_service_vips

            self.explain_block("Resolve Network Routes")
            cp_routes = {}
            # Add routes for each network used in this control plane
            for net_name in cp_networks:
                net = networks[net_name]
                if net_name not in cp_routes:
                    cp_routes[net_name] = []

                # Add routes to other networks in the same network group
                for other_net in network_groups[net['network-group']]['networks']:
                    if net_name != other_net['name'] and 'cidr' in other_net:
                        self.explain("Add route from %s to %s (same group)" % (net_name, other_net['name']))
                        route_data = {'cidr': other_net['cidr'],
                                      'net_name': other_net['name'],
                                      'implicit': True,
                                      'default': False}
                        cp_routes[net_name].append(route_data)

                # Add other routes required by this group
                for route in network_groups[net['network-group']].get('routes', []):
                    if route in network_groups:
                        # If this is a route to another group, add in all of the networks in that group
                        for other_net in network_groups[route].get('networks', []):
                            if 'cidr' not in other_net:
                                continue
                            self.explain("Add route from %s to %s (another group)" %
                                         (net_name, other_net['name']))
                            route_data = {'cidr': other_net['cidr'],
                                          'net_name': other_net['name'],
                                          'implicit': False,
                                          'default': False}
                            cp_routes[net_name].append(route_data)
                    elif route == 'default':
                        default_cidr = self.get_default_route_cidr(net['cidr'])
                        self.explain("Add route from %s to %s (default)" %
                                     (net_name, default_cidr))
                        route_data = {'cidr': default_cidr,
                                      'net_name': None,
                                      'implicit': False,
                                      'default': True}
                        cp_routes[net_name].append(route_data)
                    else:
                        msg = ("Invalid route '%s' in network group %s - "
                               "must be a network group name or 'default'." %
                               (route, net['network-group']))
                        self.add_error(msg)

            # Add the routes for each server
            self.explain_block("Resolve Network Routes for each server")
            for s in cp_servers:
                self.explain_block("server: %s" % s['name'], level=1)
                # Find the list of all networks we have an implcit route to
                implicit_routes = set()
                for iface_name, iface in s['interfaces'].iteritems():
                    for net_name, net in iface['networks'].iteritems():
                        implicit_routes.add(net_name)
                        for route_data in cp_routes.get(net['name'], []):
                            if route_data['implicit']:
                                implicit_routes.add(route_data['net_name'])

                for iface_name, iface in s['interfaces'].iteritems():
                    for net_name, net in iface['networks'].iteritems():
                        net['routes'] = []
                        for route_data in cp_routes.get(net['name'], []):
                            if not route_data['implicit'] and route_data['net_name'] in implicit_routes:
                                self.explain("Skip %s -> %s (%s) as covered by an implicit route" %
                                             (net_name, route_data['cidr'], route_data['net_name']))
                            else:
                                self.explain("Add %s -> %s (%s)" %
                                             (net_name, route_data['cidr'], route_data['net_name']))
                                net['routes'].append(route_data)

            # Find networks that have Load Balancers
            vip_networks = {}
            vips_by_role = {}
            self.explain_block("Define load balancers")
            for lb in cp['load-balancers']:
                self.explain_block("Load balancer: %s" % lb['name'], level=1)
                address = ''
                vip_net_group = lb.get('network-group', 'External')

                vip_provider = lb.get('provider', 'external')
                if vip_provider == 'external':
                    vip_net = "External"
                    for ext_ep in lb.get('vip-address', []):
                        if ext_ep['region'] == cp.get('region-name', '') or ext_ep['region'] == "*":
                            address = ext_ep.get('ip-address', '???')
                            cert_file = ext_ep.get('cert-file', '')
                    if not address:
                        continue
                elif vip_provider not in cp['components']:
                    continue
                else:
                    # Find the servers running the vip_provider
                    vip_nets = {}
                    for vip_server in cp['components'][vip_provider]['hosts']:
                        vip_net = self._get_network_in_netgroup_for_server(vip_net_group, vip_server, cp_servers)
                        if not vip_net:
                            msg = ("Server '%s' provides the '%s' service for load balancer '%s' "
                                   "but it is not connected to a network in network group '%s'" %
                                   (vip_server, vip_provider, lb['name'], vip_net_group))
                            self.add_error(msg)
                            continue
                        vip_nets[vip_net] = vip_server

                    if len(vip_nets) > 1:
                        msg = ("Load Balancer providers on different networks\n"
                               "The following servers provide the '%s' service for load balancer '%s' "
                               "in network group '%s' but are on different networks:\n" %
                               (vip_provider, lb['name'], vip_net_group))
                        for vip_net, vip_server in vip_nets.iteritems():
                            msg += "    %s:  network %s\n" % (vip_server, vip_net)
                        self.add_error(msg)
                        continue

                    elif len(vip_nets) == 1:
                        vip_net = vip_nets.keys()[0]

                        # If services on this LB share a vip allocate it now
                        if lb.get('shared-address', True):
                            vip_name = "%s-%s-vip-%s-%s" % (
                                hostname_data['host-prefix'],
                                cp.get('control-plane-prefix', cp['name']),
                                lb.get('name', 'lb'),
                                network_groups[vip_net_group].get(
                                    'hostname-suffix',
                                    network_groups[vip_net_group]['name']))

                            address = self.allocate_address(
                                network_addresses[vip_net],
                                "vip %s" % (lb['name']),
                                vip_name, vip_net,
                                self.get_addr_from_net_vips(network_addresses[vip_net],
                                                            lb.get('roles', [])))

                    cert_file = lb.get('cert-file', '')

                # See if cert_file is really a list of per service cert_files
                if cert_file:
                    if isinstance(cert_file, basestring):
                        cert_list = {'default': cert_file}
                    else:
                        cert_list = cert_file
                else:
                    cert_list = None

                #
                # Loop through all services in thie region, and find which need
                # to have a vip on this LB. A service might be excplictly on a
                # lb, or included as "default"
                #

                #
                # When not sharing VIPs between services we need to keep track of them
                #
                component_vips = {}

                for component_name, component_endpoint in cp_endpoints.iteritems():

                    lb_components = lb.get('components', []) + lb.get('tls-components', [])

                    if (component_name in lb_components or "default" in lb_components):
                        for component_ep in components.get(component_name, {}).get('endpoints', []):
                            if component_ep.get('has-vip'):

                                # Check Service allows this VIP role
                                vip_roles = [r for r in lb.get('roles', [])
                                             if r in (component_ep.get('roles', []) +
                                                      component_ep.get('optional-roles', []))]
                                if not vip_roles:
                                    continue

                                # So now we know that ths component should have a VIP on this LB
                                # for one or more of its roles.
                                if 'internal' in vip_roles:
                                    cp_endpoints[component_name]['has-vip'] = True

                                # Create an entry in vip_networks
                                # for this network if it doesn't already exist

                                if vip_net not in vip_networks:
                                    vip_networks[vip_net] = []

                                # Build an Alias for the VIP for this component
                                vip_alias = {}
                                for role in vip_roles:
                                    if role == 'internal':
                                        alias = "%s-%s-vip-%s-%s" % (
                                            hostname_data['host-prefix'],
                                            cp.get('control-plane-prefix', cp['name']),
                                            components[component_name]['mnemonic'],
                                            network_groups[vip_net_group].get(
                                                'hostname-suffix',
                                                network_groups[vip_net_group]['name']))
                                    else:
                                        alias = "%s-%s-vip-%s-%s-%s" % (
                                            hostname_data['host-prefix'],
                                            cp.get('control-plane-prefix', cp['name']),
                                            role,
                                            components[component_name]['mnemonic'],
                                            network_groups[vip_net_group].get(
                                                'hostname-suffix',
                                                network_groups[vip_net_group]['name']))

                                    vip_alias[role] = alias

                                # If we have a shared address create an alias
                                if lb.get('shared-address', True):
                                    for alias_role, alias in vip_alias.iteritems():
                                        self.add_hostname_alias(networks[vip_net], address, alias)

                                else:
                                    # See if we already have an address for this VIP
                                    if component_name in component_vips:
                                        address = component_vips[component_name]
                                    else:
                                        # Allocate an address for the vip for this component
                                        if 'internal' in vip_roles:
                                            vip_name = vip_alias['internal']
                                        elif 'public' in vip_roles:
                                            vip_name = vip_alias['public']
                                        else:
                                            vip_name = vip_alias[0]

                                        address = self.allocate_address(
                                            network_addresses[vip_net],
                                            "vip for %s" % component_name,
                                            vip_name, vip_net, vip_name,
                                            self.get_addr_from_net_vips(
                                                network_addresses[vip_net],
                                                vip_roles))
                                        component_vips[component_name] = address

                                    for alias_role, alias in vip_alias.iteritems():
                                        if vip_name != alias:
                                            self.add_hostname_alias(networks[vip_net], address, alias)

                                # Always use the service name / alias for clarity in haproxy config
                                if 'internal' in vip_roles:
                                    vip_hostname = vip_alias['internal']
                                elif 'admin' in vip_roles:
                                    vip_hostname = vip_alias['admin']
                                elif 'public' in vip_roles:
                                    vip_hostname = vip_alias['public']
                                else:
                                    vip_hostname = vip_alias.values()[0]

                                # Work out if the VIP is TLS or not.
                                # If the endpoint has the property "vip-tls-terminator" set to
                                # True (Default) the the load balancer should terminates TLS for
                                # VIP if its listed in tls-compontns.
                                # if 'vip-tls-terminator' is False then the load balancer works
                                # in pass through mode and we take teh TLS setting from the
                                # host endpoint.
                                if component_ep.get('vip-tls-terminator', True):
                                    if component_name in lb.get('components', []):
                                        vip_tls = False
                                    elif (component_name in lb.get('tls-components', []) or
                                            "default" in lb.get('tls-components', [])):
                                        vip_tls = True
                                    else:
                                        vip_tls = False
                                else:
                                    vip_tls = component_endpoint['host-tls']

                                # Create an entry for the vip for this component
                                vip_data = {
                                    'lb-name': lb['name'],
                                    'component-name': component_name,
                                    'provider': lb.get('provider', "External"),
                                    'vip-port': component_ep.get('vip-port',
                                                                 component_ep['port']),
                                    'host-port': component_ep['port'],
                                    'target': component_endpoint['network-group'],
                                    'hosts': component_endpoint['hosts'],
                                    'host-tls': component_endpoint['host-tls'],
                                    'roles': vip_roles,
                                    'advertise': False,
                                    'address': address,
                                    'network': vip_net,
                                    'network-group': vip_net_group,
                                    'aliases': {},
                                    'hostname': vip_hostname,
                                    'vip-tls': vip_tls,
                                    'vip-tls-terminator': component_ep.get('vip-tls-terminator', True)
                                }

                                if vip_tls and 'vip-tls-port' in component_ep:
                                    vip_data['vip-port'] = component_ep['vip-tls-port']

                                vip_data['aliases'] = vip_alias

                                if lb.get('external-name'):
                                    vip_data['external-name'] = lb['external-name']

                                if cert_list:
                                    cert = cert_list.get(component_name)
                                    if not cert:
                                        cert = cert_list.get('default')

                                    if cert:
                                        vip_data['cert-file'] = cert
                                    else:
                                        msg = ("Network group %s load balancer %s: "
                                               "cert-file supplied as a dict but no "
                                               "entry for 'default' or %s." %
                                               (vip_net_group, lb['name'], component_name))
                                        self.add_error(msg)

                                if 'vip-options' in component_ep:
                                    vip_data['vip-options'] = component_ep['vip-options']

                                if 'vip-check' in component_ep:
                                    vip_data['vip-check'] = component_ep['vip-check']

                                vip_data['vip-backup-mode'] = component_ep.get('vip-backup-mode',
                                                                               False)

                                # Record if the VIP is on this LB as part of the default set
                                if "default" in lb.get('components', []) + lb.get('tls-components', []):
                                    self.explain("Add %s for roles %s due to 'default'" % (component_name, vip_roles))
                                    vip_data['default'] = True
                                else:
                                    self.explain("Add %s for roles %s" % (component_name, vip_roles))
                                    vip_data['default'] = False

                                    # Keep track of the components added by name so we can remove
                                    # any entries for those components added to the list via a
                                    # "default" match for the same role.
                                    for role in vip_roles:
                                        if role not in vips_by_role:
                                            vips_by_role[role] = []
                                        vips_by_role[role].append(component_name)

                                # See if this endpoint should be advertised
                                if 'advertises-to-services' in \
                                        components[component_name]:
                                    vip_data['advertise'] = True

                                vip_networks[vip_net].append(vip_data)

            # Can't do any more if we have errors when building the load balancers
            if self._errors:
                return

            # Save the results in the cp
            cp['vip_networks'] = vip_networks

            # Now we have a full list of LBs on all networks build a list of
            # load-balancers by provider (e.g. ip-cluster) form this control plane.
            # Note that a CP load balancer will serve the VIPs for multiple load-balancers
            # in the input model (for example the public and internal LBs will be separate
            # in network groups but are provided by the same ip-cluster service
            #
            self.explain_block("Map load balancers to providers")
            cp['load-balancer-config'] = {}
            component_vips = {}
            for vip_net_name, vip_net in vip_networks.iteritems():
                self.explain_block("Network %s" % vip_net_name, level=1)
                for vip_data in vip_net:
                    vip_component_name = vip_data['component-name']

                    # If this VIP was added as a result of a "default" set on a
                    # Load balancer check to see if it has any explcit roles on another
                    # LB.  If it does remove those roles from this VIP.
                    if vip_data['default']:
                        default_roles = []
                        for role in vip_data['roles']:
                            if vip_component_name not in vips_by_role.get(role, []):
                                default_roles.append(role)
                        vip_data['roles'] = default_roles

                    # We might have removed all of the roles in the above
                    if not vip_data['roles']:
                        continue

                    if vip_data['provider'] not in cp['load-balancer-config']:
                        cp['load-balancer-config'][vip_data['provider']] = {}

                    if vip_component_name not in cp['load-balancer-config'][vip_data['provider']]:

                        cp['load-balancer-config'][vip_data['provider']][vip_component_name] = {
                            'hosts': vip_data['hosts'],
                            'host-tls': vip_data['host-tls'],
                            'networks': []
                        }

                    # NOTE: If the host is terminating TLS then stunnel will listen on
                    # the vip-port not the host-port.  Normally these are the same but
                    # they can be different if an service can't allow anything else to
                    # bind to the same port - for example vertica always binds to
                    # its port on 0.0.0.0 so haproxy and stunnel can't use the same port
                    if vip_data['host-tls']:
                        host_port = vip_data['vip-port']
                    else:
                        host_port = vip_data['host-port']

                    lb_networks = cp['load-balancer-config'][vip_data['provider']][vip_component_name]['networks']
                    self.explain("%s: %s %s roles: %s vip-port: %s host-port: %s" %
                                 (vip_data['address'], vip_data['provider'], vip_component_name,
                                  vip_data['roles'], vip_data['vip-port'], host_port))
                    lb_data = {
                        'lb-name': vip_data['lb-name'],
                        'component-name': vip_data['component-name'],
                        'hostname': vip_data['hostname'],
                        'ip-address': vip_data['address'],
                        'network': vip_data['network'],
                        'network-group': vip_data['network-group'],
                        'vip-port': vip_data['vip-port'],
                        'host-port': host_port,
                        'roles': vip_data['roles'],
                        'vip-tls': vip_data['vip-tls'] and vip_data['vip-tls-terminator'],
                        'vip-tls-terminator': vip_data['vip-tls-terminator'],
                        'aliases': vip_data['aliases']
                    }

                    # Copy accross any optional items.  Use deepcopy() beacuse the item may
                    # be one more than one VIP, and we dont't want reference tags in the
                    # output yaml
                    for item in ['external-name', 'cert-file', 'vip-options', 'vip-check', 'vip-backup-mode']:
                        if item in vip_data:
                            lb_data[item] = deepcopy(vip_data[item])

                    lb_networks.append(lb_data)

                    # Keep a map from component/role to the vip to make it
                    # easy to find them
                    if vip_component_name not in component_vips:
                        component_vips[vip_component_name] = {}

                    for role in vip_data['roles']:
                        component_vips[vip_component_name][role] = vip_data

            #
            # Build a list of all of the endpoints that are to be advertised
            #
            cp['advertises'] = {}
            for vip_net_name, vip_net in vip_networks.iteritems():
                for vip_data in vip_net:
                    vip_component_name = vip_data['component-name']

                    # Because of we add all services for a "default" rule and
                    # then remove any explicit roles on another LB we might end
                    # up with no roles
                    if not vip_data['roles']:
                        continue

                    if vip_data.get('advertise'):
                        if vip_component_name not in cp['advertises']:
                            cp['advertises'][vip_component_name] = {}

                        for r in vip_data['roles']:
                            if vip_data['vip-tls']:
                                protocol = 'https'
                            else:
                                protocol = 'http'

                            # Use IP address for URLs in keystone
                            url = "%s://%s:%s" % (
                                protocol,
                                vip_data.get('external-name', vip_data['address']),
                                vip_data['vip-port'])

                            data = {
                                'hostname': vip_data['hostname'],
                                'ip_address': vip_data['address'],
                                'port': vip_data['vip-port'],
                                'protocol': protocol,
                                'use_tls': vip_data['vip-tls'],
                                'url': url
                            }
                            cp['advertises'][vip_component_name][r] = data

            #
            # Build a list of endpoints for the control plane
            #
            #  access - what do clients call
            #  bind  - what does the sevice listen on
            #  tls_term - what does the tls terminator listen on
            #  tls_init - what does an tls initiator connect to
            endpoints = {}
            for component_name, endpoint in cp_endpoints.iteritems():
                for component_ep in components.get(component_name, {}).get('endpoints', []):
                    if component_name not in endpoints:
                        endpoints[component_name] = {}

                    for role in component_ep.get('roles', []) + component_ep.get('optional-roles', []):
                        if role not in endpoints[component_name]:
                            endpoints[component_name][role] = []
                        endpoint_data = {}

                        if component_ep.get('has-vip', False):
                            # Find the vip for this role
                            if role not in component_vips.get(component_name, {}):
                                if role not in component_ep.get('optional-roles', []):
                                    msg = ("Component %s needs a VIP for role %s "
                                           "but there is no load-balancer providing "
                                           "that role." % (component_name, role))
                                    self.add_error(msg)
                                continue

                            vip_data = component_vips[component_name][role]

                            # Components that need a TLS initiatior have to be accessed
                            # via localhost and have the TLS initiator configured
                            if vip_data['vip-tls'] and component_ep.get('tls-initiator', False):
                                endpoint_data['access'] = {
                                    'network': vip_data['network'],
                                    'address': self.get_localhost(vip_data['address']),
                                    'hostname': 'localhost',
                                    'port': vip_data['vip-port'],
                                    'use-tls': False}
                                endpoint_data['tls-init'] = {
                                    'address': vip_data['address'],
                                    'hostname': vip_data['aliases'][role],
                                    'port': vip_data['vip-port'],
                                    'use-tls': True}
                            else:
                                endpoint_data['access'] = {
                                    'network': vip_data['network'],
                                    'address': vip_data['address'],
                                    'hostname': vip_data['aliases'][role],
                                    'port': vip_data['vip-port'],
                                    'use-tls': vip_data['vip-tls']}

                            # If the service endpoint is TLS enabled and the service needs
                            # a TLS terminator the the service has to bind to localhost and
                            # the tls terminator has to be configured
                            if endpoint['host-tls'] and component_ep.get('tls-terminator', True):
                                endpoint_data['bind'] = {
                                    'address': self.get_localhost(vip_data['address']),
                                    'port': vip_data['host-port'],
                                    'tls': False}

                                # NOTE: Tell stunnel to use the vip-port
                                # because where this is different from the
                                # host-port it normally means that nothing
                                # apart from the service can use that port.
                                endpoint_data['tls-term'] = {
                                    'network_group': vip_data['target'],
                                    'port': vip_data['vip-port']}
                            else:
                                endpoint_data['bind'] = {
                                    'network_group': vip_data['target'],
                                    'port': vip_data['host-port'],
                                    'tls': (endpoint['host-tls'] and
                                            not component_ep.get('tls-terminator', True))}

                            # Check if the component wants to also have its members listed
                            if component_ep.get('list-members', False):
                                endpoint_data['access']['members'] = endpoint['hosts']
                                endpoint_data['access']['host-tls'] = endpoint['host-tls']

                        else:
                            # No VIP - so add list of members instead
                            endpoint_data['access'] = {
                                'members': endpoint['hosts'],
                                'port': component_ep['port'],
                                'use-tls': endpoint['host-tls']}

                            if endpoint['host-tls'] and 'tls-port' in component_ep:
                                endpoint_data['access']['port'] = component_ep['tls-port']

                            # If the service endpoint is TLS enabled and the service needs
                            # a TLS terminator the the service has to bind to localhost and
                            # the tls terminator has to be configured
                            if endpoint['host-tls']:
                                if component_ep.get('tls-terminator', True):
                                    endpoint_data['bind'] = {
                                        'address': self.get_localhost(endpoint['hosts'][0]['ip_address']),
                                        'port': component_ep['port'],
                                        'tls': False}

                                    endpoint_data['tls-term'] = {
                                        'network_group': endpoint['network-group'],
                                        'port': component_ep.get('tls-port', component_ep['port'])}

                                else:
                                    endpoint_data['bind'] = {
                                        'network_group': endpoint['network-group'],
                                        'port': component_ep.get('tls-port', component_ep['port']),
                                        'tls': True}
                            else:
                                endpoint_data['bind'] = {
                                    'network_group': endpoint['network-group'],
                                    'port': component_ep['port'],
                                    'tls': False}

                        endpoints[component_name][role].append(endpoint_data)

            cp['endpoints'] = endpoints

            # Add internal endpoints to services
            for component_name, component in cp['components'].iteritems():
                vip_data = component_vips.get(component_name, {}).get('internal', {})
                if vip_data:
                    component['endpoint'] = {'ip_address': vip_data['address'],
                                             'port': vip_data['vip-port']}
                    component['targets'] = vip_data['hosts']
                elif component_name in cp['endpoints']:
                    endpoint_data = cp['endpoints'][component_name]
                    if endpoint_data.get('internal', []):
                        # TODO-PHIL:   Not sure that taking the first entry when there are muliple
                        # internal endpoints is the right thing to do. We should probably validate
                        # elsewhere that a role is only used for one endpoint in a component.
                        endpoint_data = endpoint_data['internal'][0]['access']
                        component['endpoint'] = endpoint_data['port']
                        component['targets'] = endpoint_data['members']

            # Build a list of members by service
            cp['members'] = {}
            for component_name, r_endpoint in cp_endpoints.iteritems():
                for endpoint in components[component_name].get('endpoints', []):
                    if component_name not in cp['members']:
                        cp['members'][component_name] = {'hosts': r_endpoint['hosts'],
                                                         'ports': {}}
                        member_data = cp['members'][component_name]
                    for role in endpoint.get('roles', []) + endpoint.get('optional-roles', []):
                        if role not in member_data['ports']:
                            member_data['ports'][role] = []
                        member_data['ports'][role].append(endpoint['port'])

        # Build a list of allocated addresses
        allocated_addresses = {}
        persisted_unused = {}
        for group_name, group in network_groups.iteritems():
            allocated_addresses[group_name] = {}
            for network in group['networks']:
                allocated_addresses[group_name][network['name']] = {}
                for addr in network_addresses[network['name']]['allocated']:
                    if addr['allocated']:
                        allocated_addresses[group_name][network['name']][addr['addr']] = {'host': addr['host'],
                                                                                          'used-by': addr['used-by']}
                    elif addr['persisted']:
                        if network['name'] not in persisted_unused:
                            persisted_unused[network['name']] = []
                        persisted_unused[network['name']].append(addr)

        # Handle any persisted addresses that we are not using any more
        addr_msg = ""
        for net_name, addresses in persisted_unused.iteritems():
            for addr_data in addresses:
                if free_unused_addresses:
                    self._address_state_persistor.delete_info([addr_data['addr']])
                else:
                    addr_msg += ("\n         %s (%s - %s %s)" %
                                 (addr_data['addr'], net_name, addr_data['used-by'], addr_data['host']))

        if addr_msg:
            msg = ("Unused persisted address allocations\n"
                   "The following address allocations are persisted but not used: "
                   "%s\n"
                   "    To free these addresses rerun the config processor playbook with "
                   "'-e free_unused_addresses=True'.  If running the config processor direct "
                   "from the command line use '--free_unused_addresses'" % addr_msg)
            self.add_warning(msg)

        # Warn about any user defined VIPS that weren't allocated
        for net_name, addresses in network_addresses.iteritems():
            if addresses.get('vips', []):
                msg = ("The following VIPs on network '%s' have not been allocated: " % net_name)
                for vip in addresses['vips']:
                    msg += "%s (%s)" % (vip['address'], vip['roles'])
                self.add_warning(msg)

        CloudModel.put(cloud_internal, 'service_view', service_view)
        CloudModel.put(cloud_internal, 'address_allocations', allocated_addresses)
        CloudModel.put(cloud_internal, 'host_aliases', self.host_aliases)
        CloudModel.put(cloud_internal, 'host_names', self.host_names)

        self.write_explanation()

    #
    # Update the list of zone-types in a control plane based
    # on a list of components.  Component define which zone types any
    # server they are running on should be included in.  For example
    # nova-compute in its service definition will have:
    #
    #    zone-type: nova_availability_zones
    #
    # Building these per service makes it easier for a playbook to
    # see when it has to create zones in a particular control plane and
    # seperate zone creation from adding individual servers to a zone
    #
    @staticmethod
    def _update_cp_zones(cp, zones, component_list, components):
        for comp_name in component_list:
            zone_type = components[comp_name].get('zone-type')
            if zone_type:
                if zone_type not in cp['zone-types']:
                    cp['zone-types'][zone_type] = set()
                for zone in zones:
                    cp['zone-types'][zone_type].add(zone)

    #
    # Get a region for a server. This logic is somewhat flawed as a server could
    # host services from more than one region, but this value is used by swift
    # in group_vars/all to match servers to ring defintions. So for now we match:
    #    - If swift is on the server, the first region that includes swift
    #    - Otherwise the first region that contains any service on the server
    #
    # Swift is moving to using configuration-data for rings in 4.0, so we may be
    # able to remove this at some stage.
    #
    @staticmethod
    def _get_region(cp, services):

        # Phil: I hate hard coding swift here, but don't see any
        # obvious alternative.
        swift_comps = set(['swift'])

        match = swift_comps.intersection(services)
        if not match:
            match = set(services)

        result = None
        for region_name in sorted(cp.get('regions', {})):
            region_services = cp['regions'][region_name]
            if match.intersection(region_services):
                result = region_name
                break

        return result

    #
    # Add a server to a cluster
    #
    def _add_server_to_cluster(self, s, member_id, zone_name, cp, cluster, hostname_data):
        s['state'] = ServerState.ALLOCATED
        s['member_id'] = member_id
        s['failure-zone'] = zone_name
        s['components'] = cluster['service-components']
        s['services'] = cluster['services']
        s['region'] = self._get_region(cp, cluster['services'])
        s['control-plane-name'] = cp['name']
        s['cluster-name'] = cluster['name']

        self._get_region(cp, cluster['service-components'])
        name = "%s-%s-%s" % (hostname_data['host-prefix'],
                             cp.get('control-plane-prefix', cp['name']),
                             cluster.get('cluster-prefix', cluster['name']))
        s['name'] = name + "%s%d" % (hostname_data.get('member-prefix', ''),
                                     s['member_id'])
        cluster['servers'].append(s)

    #
    # Add a server to a resource group
    #
    def _add_server_to_resources(self, s, member_id, zone_name, cp, resources, hostname_data):
        s['state'] = ServerState.ALLOCATED
        s['member_id'] = member_id
        s['failure-zone'] = zone_name
        s['components'] = resources['service-components']
        s['services'] = resources['services']
        s['region'] = self._get_region(cp, resources['services'])
        s['control-plane-name'] = cp['name']
        s['cluster-name'] = resources['name']

        name = "%s-%s-%s%04d" % (hostname_data['host-prefix'],
                                 cp.get('control-plane-prefix', cp['name']),
                                 resources.get('resource-prefix', resources['name']),
                                 s['member_id'])
        s['name'] = name
        resources['servers'].append(s)

    #
    # Find network in network_group for a specific server in a list of servers
    #
    @staticmethod
    def _get_network_in_netgroup_for_server(net_group, server_name, servers):
        network = None
        for s in servers:
            if s.get('hostname') != server_name:
                continue
            for iface_name, iface in s.get('interfaces', {}).iteritems():
                for net_name, net_data in iface.get('networks', {}).iteritems():
                    if net_data['network-group'] == net_group:
                        network = net_name
                        break
        return network

    #
    # Generate addresses and load persisted address allocations
    #
    def generate_addresses(self, addresses, server_addresses):
        persisted_info = self._address_state_persistor.recall_info()
        for persisted_address, pi in persisted_info.iteritems():
            addr = IPAddress(persisted_address)
            if addr in addresses['sets']:
                address_info = {'addr': pi['addr'],
                                'free': bool(pi['free']),
                                'used-by': pi['used-by'],
                                'host': pi['host'],
                                'server-id': pi.get('server-id'),
                                'persisted': True,
                                'allocated': False}
                addresses['allocated'].append(address_info)
                addresses['sets'].remove(addr)
            else:
                # Address may be in addresses['vips']
                for net_vip in addresses.get('vips', []):
                    if persisted_address == net_vip.get('address', None):
                        address_info = {'addr': pi['addr'],
                                        'free': bool(pi['free']),
                                        'used-by': pi['used-by'],
                                        'host': pi['host'],
                                        'server-id': pi.get('server_id'),
                                        'persisted': True,
                                        'allocated': False}
                        addresses['allocated'].append(address_info)
                        break

        for server_address in server_addresses.viewkeys():
            addr = IPAddress(unicode(server_address))
            if addr in addresses['sets']:
                address_info = {'addr': server_address,
                                'free': False,
                                'used-by': "",
                                'host': "",
                                'server-id': server_addresses[server_address],
                                'persisted': False,
                                'allocated': False}
                addresses['allocated'].append(address_info)
                addresses['sets'].remove(addr)

    #
    # Allocate an address from a network or return a previously allocated
    # address
    #
    def allocate_address(self, addresses, used_by, host="", net_name="",
                         addr=None, server_id=None, match_prefix=None):

        """ Allocate an address from a list of addresses
        :param addresses:  A dict of allocated address structures ('allocated')
                           and available ip address sets ('sets')
        :param used_by: A string that records what the address is being used by
        :param host: The host name to be assocated with the address
        :param net_name:  The name of the network we're allocating from
        :param addr: A specific address to be allocated. Used when we're taking
                     an existing address from a server
        :param server_id: The ID of the server the address is allocated to
        :param match_prefix: BUG 477 - at the moment, the host field of a persisted
             VIP address contains the first server of the cluster the VIP will sit
             on. If that server is removed, the VIP is reallocated. This parameter
             controls the forward migration of persisted address records from
             that older strategy to one where the VIP 'hostname' is server-neutral.
        """

        result = None
        found_addr = None
        already_allocated = False
        for f in addresses['allocated']:

            if addr:
                if f['addr'] != addr:
                    continue
                elif f['free'] or f['host'] == host or (
                        f['server-id'] and f['server-id'] == server_id):
                    result = f
                    self.explain("Using address %s for %s %s on network %s" %
                                 (addr, used_by, host, net_name))
                    found_addr = addr
                    break
                else:
                    msg = ("Could not allocate address %s from network %s "
                           "for %s %s, already used by %s %s" %
                           (addr, net_name,
                            used_by, host, f['used-by'], f['host']))
                    self.add_error(msg)
                    already_allocated = True

            elif (f['used-by'] == used_by and
                  (f['host'] == host or
                   (match_prefix and
                    f['host'][:-4] == host and
                    f['host'][-4:].isdigit()))):
                result = f
                self.explain("Using persisted address %s for %s %s on network %s" %
                             (f['addr'], used_by, host, net_name))
                break

        # Didn't find one, so look for a free address
        if not result and not addr:
            # The first available address in addresses['sets'] should be our
            # 'free' address
            new_addr = None
            for ip in addresses['sets']:
                new_addr = ip
                addresses['sets'].remove(ip)
                break
            if new_addr:
                f = {'addr': str(new_addr),
                     'persisted': False}
                self.explain("Allocated address %s for %s %s on network %s" %
                             (f['addr'], used_by, host, net_name))
                result = f

        # Address is not in free address and hasn't already been allocated.
        # Check if the address is in the network vip address list
        if not result and addr and not already_allocated:
            for vip in addresses.get('vips', []):
                if vip.get('address', None) == addr:
                    f = {'addr': addr,
                         'persisted': False}
                    self.explain("Allocated user defined VIP %s for %s %s on network %s" %
                                 (addr, used_by, host, net_name))
                    result = f
                    found_addr = addr
                    break

        if result:
            # Always (re)persist the allocation, so that if we've changed the
            # set of data it gets updated
            addr = f['addr']
            f['free'] = False
            f['used-by'] = used_by
            f['host'] = host
            f['server-id'] = server_id
            f['allocated'] = True

            pi = {addr: f}
            self._address_state_persistor.persist_info(pi)
            if f not in addresses['allocated']:
                addresses['allocated'].append(f)
            if found_addr and not server_id:
                for vip in addresses.get('vips', []):
                    if addr == vip['address']:
                        addresses['vips'].remove(vip)
            return result['addr']
        else:
            msg = ("Could not allocate address from network %s "
                   "for %s %s" % (net_name, used_by, host))
            self.add_error(msg)

            return None

    # ---------------------------------------
    # Record host name aliases
    # ---------------------------------------
    host_aliases = {}

    def add_hostname_alias(self, net, address, name):

        if net['network-group'] not in self.host_aliases:
            self.host_aliases[net['network-group']] = {}

        if net['name'] not in self.host_aliases[net['network-group']]:
            self.host_aliases[net['network-group']][net['name']] = {}

        if address not in self.host_aliases[net['network-group']][net['name']]:
            self.host_aliases[net['network-group']][net['name']][address] = set()

        self.host_aliases[net['network-group']][net['name']][address].add(name)

    # ---------------------------------------
    # Record host name aliases
    # ---------------------------------------
    host_names = {}

    def add_hostname(self, net, address, name):

        if net['network-group'] not in self.host_names:
            self.host_names[net['network-group']] = {}

        if net['name'] not in self.host_names[net['network-group']]:
            self.host_names[net['network-group']][net['name']] = {}

        if address not in self.host_names[net['network-group']][net['name']]:
            self.host_names[net['network-group']][net['name']][name] = address

    # ----------------------------------------------
    # Check if we can take over an existing address
    # ----------------------------------------------
    def consume_address(self, addr, net):

        if IPAddress(addr) in net['sets']:
            return addr
        for allocated_address in net['allocated']:
            if allocated_address['addr'] == addr:
                return addr
        return None

    # ---------------------------------------
    # Resolve network config for a server.
    #
    # s                    The Server
    # components           All components in the input model
    # network_groups       All network_groups in the input model
    # network_addresses    Structure per network of addresses used and available
    # cluster              The Cluster or Resource group the server has been allocated to
    # hostname_prefix      The prefix to use for address names
    # cp                   The control plane the server has been allocated to
    #
    # Note:  The server structure passed in has a copy of the interface model with
    #        the specific network in scope for the server included.  As part of this
    #        method we reduce that down to the subest of networks that are actually
    #        required
    #
    # ---------------------------------------
    def resolve_server_networks(self, s, components, network_groups, network_addresses,
                                cluster, hostname_prefix, cp):

        # Find which networks we need for this server
        required_nets = set()
        related_nets = {}
        components_included = set()
        tags_found = set()

        self.explain_block("server: %s" % s['name'], level=1)

        for group_name, net_group in network_groups.iteritems():

            # Build a list of all components on ths network
            component_endpoints = (
                net_group.get('component-endpoints', []) +
                net_group.get('tls-component-endpoints', [])
            )
            for lb in cp['load-balancers']:
                if lb['network-group'] == group_name:
                    component_endpoints.append(lb['provider'])

            for component_name in s['components']:

                if component_name not in component_endpoints:
                    continue

                component = components.get(component_name, {})

                if (component_name in component_endpoints):
                    self.explain("add %s for component %s" % (group_name, component_name))
                    required_nets.add(group_name)
                    components_included.add(component_name)
                    self._add_auto_tags(component, group_name, cp['network-tags'])

        # Add in entries for default endpoints, network tags, or default route
        for group_name, net_group in network_groups.iteritems():

            component_endpoints = (
                net_group.get('component-endpoints', []) +
                net_group.get('tls-component-endpoints', [])
            )

            for component_name in s['components']:
                component = components.get(component_name, {})

                if ('default' in component_endpoints and
                        component_name not in components_included):
                    self.explain("add %s for %s (default)" % (group_name, component_name))
                    required_nets.add(group_name)
                    self._add_auto_tags(component, group_name, cp['network-tags'])

                # Add any networks that are required due to a service tag
                network_group_tags = cp['network-tags'].get(group_name, [])
                for tag in network_group_tags:
                    if tag.get('component', '') == component['name']:
                        # Add to the list of required networks
                        self.explain("add %s for tag %s (%s)" %
                                     (group_name, tag['name'], component['name']))
                        required_nets.add(group_name)

                        # Add to the list of related networks
                        if group_name not in related_nets:
                            related_nets[group_name] = []

                        related_nets[group_name].append(tag)

                        # Recored that we found the tag
                        tags_found.add(tag['name'])

        # Build a new list of networks limited to the ones needed on this server
        components_attached = set()
        server_network_groups = set()
        net_group_default_routes = []
        server_network_found = False

        # Keep track of which network device(s) we find for each cidr on this server
        server_cidrs = {}

        # Keep track of which network device(s) we find for each tagged vlan on this server
        server_tagged_vlans = {}

        # Keep track of which cidrs we find for each network_device on this server
        server_net_devices = {}

        for iface in s['interfaces']:
            iface_networks = {}
            iface_network_groups = []
            for net_name, net in iface['networks'].iteritems():
                if net['network-group'] in required_nets or net['forced'] or net['passthrough']:
                    iface_networks[net_name] = net
                    if not net['passthrough-only']:
                        server_network_groups.add(net['network-group'])
                    iface_network_groups.append(net['network-group'])

            iface['networks'] = iface_networks
            iface['network-groups'] = iface_network_groups

            pci_pt = iface['device'].get('pci-pt', False)
            sriov_only = iface['device'].get('sriov-only', False)

            hostname_networks = []
            for net_name, net in iface['networks'].iteritems():

                net['endpoints'] = {}
                net['service-tags'] = {}

                # Don't need to allocate an address or look for components on
                # passthrough-only networks
                if net['passthrough-only']:
                    continue

                # A network device is the combination of interface and vlanid.
                # Always treat untagged vlans as having an ID of 0 even if the vlanid
                # has been specified, since that's how they appear to the server.
                if net.get('tagged-vlan', True):
                    vlan_id = net['vlanid']
                else:
                    vlan_id = 0
                net_device = (iface['device']['name'], "vlanid: %s" % vlan_id)

                # Keep track of the cidrs and network devices so we can check
                # them later
                if 'cidr' in net:
                    cidr = IPNetwork(net['cidr'])
                    if cidr not in server_cidrs:
                        server_cidrs[cidr] = []
                    server_cidrs[cidr].append({'net-name': net_name,
                                               'net-device': net_device})

                    if net_device not in server_net_devices:
                        server_net_devices[net_device] = {}
                    if cidr not in server_net_devices[net_device]:
                        server_net_devices[net_device][cidr] = []
                    server_net_devices[net_device][cidr].append(net_name)

                # Keep track of tagged vlans on this server so we can check that they are
                # unique accross all of the interfaces of the server
                if net.get('tagged-vlan'):
                    vlanid = net['vlanid']
                    if vlanid not in server_tagged_vlans:
                        server_tagged_vlans[vlanid] = []
                    server_tagged_vlans[vlanid].append({'net-name': net_name,
                                                        'net-device': iface['device']['name']})

                # Allocate an address for this server
                if 'cidr' in net and not pci_pt and not sriov_only:
                    server_addr = self.consume_address(s['addr'], network_addresses[net['name']])
                    if server_addr:
                        server_network_found = True

                    net['addr'] = self.allocate_address(
                        network_addresses[net['name']],
                        used_by='server', host=s['name'],
                        net_name=net_name, addr=server_addr,
                        server_id=s['id'])
                    net_group = network_groups[net['network-group']]
                    net_suffix = net_group.get('hostname-suffix', net['network-group'])
                    net['hostname'] = "%s-%s" % (s['name'], net_suffix)
                    self.add_hostname_alias(net, net['addr'], net['hostname'])

                    # Is this the network that gives us the hostname ?
                    if net_group.get('hostname', False):
                        hostname_networks.append(net_name)
                        if s.get('hostname'):
                            self.add_hostname_alias(net, net['addr'], s['hostname'])
                        else:
                            s['hostname'] = net['hostname']
                        s['hostname_address'] = net['addr']
                        self.add_hostname(net, net['addr'], s['hostname'])

                    # Will this network give us a default route
                    if 'default' in net_group.get('routes', []):
                        net_group_default_routes.append(net_group['name'])

                net_group = network_groups[net['network-group']]
                net_group_endpoints = net_group.get('component-endpoints', [])
                net_group_tls_endpoints = net_group.get('tls-component-endpoints', [])

                # Add explicit endpoint attachments
                for component_name in s['components']:
                    component = components.get(component_name, {})
                    if (component_name in net_group_endpoints):
                        components_attached.add(component_name)
                        net['endpoints'][component_name] = {'use-tls': False}
                    if (component_name in net_group_tls_endpoints):
                        components_attached.add(component_name)
                        net['endpoints'][component_name] = {'use-tls': True}
                # Mark any networks added as a tag
                net['service-tags'] = related_nets.get(net['network-group'], {})

        # Check we found the network with the servers address
        if not server_network_found:
            msg = ("Server %s (%s) using interface model %s does not have a "
                   "connection to a network which contains its address." %
                   (s['name'], s['addr'], s['if-model']))
            self.add_error(msg)

        # Check we found a network to use as the hostname
        if s.get('hostname') is None:
            msg = ("Server %s (%s) using interface model %s does not have a "
                   "connection to a network group with \"hostname: true\"" %
                   (s['name'], s['addr'], s['if-model']))
            self.add_error(msg)
            # to prevent key errors in the rest of the generator
            s['hostname'] = s['name']

        # Check we only found one network to use as the hostname
        if len(hostname_networks) > 1:
            msg = ("Server %s (%s) using interface model %s is connected "
                   "to more than one network with \"hostname: true\": %s" %
                   (s['name'], s['addr'], s['if-model'],
                    str(hostname_networks).strip('[]')))
            self.add_error(msg)

        # Check we have only one one default route
        if len(net_group_default_routes) > 1:
            msg = ("Server %s (%s) using interface model %s has "
                   "more than one network group with a default route: %s"
                   % (s['name'], s['addr'], s['if-model'], net_group_default_routes))
            self.add_error(msg)

        # Check we don't have duplicate CIDRs on a network device, and that
        # we only have one network device for each CIDR.
        # server_net_devices is a dict with the form:
        #    net_device_1:
        #        cidr_1:   [List of networks]
        #        cidr_2:   [List of networks]
        #    net_device_2:
        #        cidr_3:   [List of networks]
        for net_device, cidrs in server_net_devices.iteritems():
            for cidr, networks in cidrs.iteritems():
                if len(networks) > 1:
                    msg = ("Server %s (%s) using interface model %s has CIDR %s "
                           "defined more than once for the same network device %s: %s "
                           % (s['name'], s['id'], s['if-model'],
                              str(cidr), net_device, str(networks).strip('[]')))
                    self.add_error(msg)

            # More than one CIDR on a network device is a valid network configuration, but
            # not currently supported by Ardana OpenStack
            if len(cidrs) > 1:
                msg = ("Server %s (%s) using interface model %s has more than one CIDR "
                       "defined for the same network device %s: "
                       % (s['name'], s['id'], s['if-model'], net_device))
                for cidr, networks in cidrs.iteritems():
                    msg += "%s(%s) " % (str(cidr), str(networks).strip('[]'))
                self.add_error(msg)

        # Ardana OpenStack does not support scoped addresses so check we only have
        # one network device for each cidr.  When we support scoped addresses
        # then those would need to be excluded from this check.
        for cidr, devices in server_cidrs.iteritems():

            # Might have the same device more than once, which is a different
            # error case
            unique_devs = set()
            for device in devices:
                unique_devs.add(device['net-device'])

            if len(unique_devs) > 1:
                msg = ("Server %s (%s) using interface model %s has CIDR %s "
                       "defined for more than one network device: "
                       % (s['name'], s['id'], s['if-model'], str(cidr)))
                for device in devices:
                    msg += "%s(%s) " % (device['net-device'], device['net-name'])
                self.add_error(msg)

        # Check we only have one device for each vlan id.  This is a valid
        # network configurtaion in general but not supported in Ardana OpenStack because
        # of the way we name devices and interface files.
        for vlanid, vlan_net_list in server_tagged_vlans.iteritems():
            if len(vlan_net_list) > 1:
                msg = ("Server %s (%s) using interface model %s is connected "
                       "to more than one network with vlanid %s which is not "
                       "supported: " %
                       (s['name'], s['id'], s['if-model'], vlanid))
                for vlan_net in vlan_net_list:
                    msg += "%s(%s) " % (vlan_net['net-device'], vlan_net['net-name'])
                self.add_error(msg)

        # Check we found all the required and related networks
        for net_group in required_nets:
            if net_group not in server_network_groups:
                # Don't error on networks that are in required due to a tag
                if net_group not in related_nets:
                    msg = ("Server %s (%s) using interface model %s does not have a "
                           "connection to a required network group: %s" %
                           (s['name'], s['addr'], s['if-model'], net_group))
                    self.add_error(msg)

        for net_group_name, tag_list in related_nets.iteritems():
            for tag_data in tag_list:
                if net_group_name not in server_network_groups:
                    msg = ("Server %s (%s) using interface model %s: %s is not "
                           "directly connected to a network group '%s' with the tag: %s " %
                           (s['name'], s['addr'], s['if-model'],
                            tag_data['component'], net_group_name, tag_data['name']))

                    if 'required' in tag_data['definition']:
                        self.add_error(msg)
                    else:
                        self.add_warning(msg)

        # Check we found all the tags:
        for component_name in s['components']:
            tags = components[component_name].get('network-tags', [])
            for tag in tags:
                if (tag.get('expected') and tag['name'] not in tags_found):
                    msg = ("Network tag \"%s\" was expected by %s: %s" %
                           (tag['name'], component_name, tag['expected']))
                    self.add_warning(msg)
                elif (tag.get('required') and tag['name'] not in tags_found):
                    msg = ("Network tag \"%s\" is required by %s: %s" %
                           (tag['name'], component_name, tag['required']))
                    self.add_error(msg)

        # Add default endpoint attachments
        for iface in s['interfaces']:

            for net_name, net in iface['networks'].iteritems():
                if net['passthrough-only']:
                    continue
                net_group = network_groups[net['network-group']]
                net_group_endpoints = net_group.get('component-endpoints', [])
                net_group_tls_endpoints = net_group.get('tls-component-endpoints', [])

                for component_name in s['components']:
                    component = components.get(component_name, {})
                    if ('default' in net_group_endpoints and
                            component_name not in components_attached):
                        net['endpoints'][component_name] = {'use-tls': False}
                    elif ('default' in net_group_tls_endpoints and
                            component_name not in components_attached):
                        net['endpoints'][component_name] = {'use-tls': True}

        # Add service ips if required
        for iface in s['interfaces']:
            for net_name, net in iface['networks'].iteritems():
                if net['passthrough-only']:
                    continue
                for component_name in s['components']:
                    if component_name not in net['endpoints']:
                        continue
                    component = components.get(component_name, {})
                    if (component.get('needs-ip', 'False') is True or
                            component.get('needs-cluster-ip', 'False') is True):
                        if 'service-ips' not in cluster:
                            cluster['service-ips'] = {}
                        if component_name not in cluster['service-ips']:
                            cluster['service-ips'][component_name] = {}
                        if net_name not in cluster['service-ips'][component_name]:
                            cluster['service-ips'][component_name][net_name] = \
                                {'hosts': []}
                        service_ip_data = cluster['service-ips'][component_name][net_name]

                        if (component.get('needs-ip', 'False') is True and
                                'cidr' in net):
                            addr = self.allocate_address(
                                network_addresses[net['name']],
                                used_by=component_name, host=s['name'], net_name=net_name)
                            net_group = network_groups[net['network-group']]
                            net_suffix = net_group.get('hostname-suffix', net['network-group'])
                            alias = "%s-%s-%s" % (s['name'], component['mnemonic'],
                                                  net_suffix)
                            self.add_hostname_alias(net, addr, alias)

                            if 'service-ips' in s:
                                s['service-ips'][component_name] = addr
                            else:
                                s['service-ips'] = {}
                                s['service-ips'][component_name] = addr

                            service_ip_data['hosts'].append(
                                {'hostname': alias,
                                 'name': s['name'],
                                 'ip_address': addr})

                        if (component.get('needs-cluster-ip', 'False') is True and
                                'cidr' in net):
                            if 'cluster-ip' not in service_ip_data:
                                addr = self.allocate_address(
                                    network_addresses[net['name']],
                                    used_by="%s-%s" % (component_name, '-cluster'),
                                    host="{}-{}".format(hostname_prefix, cluster['name']),
                                    net_name=net_name,
                                    match_prefix=True)
                                net_group = network_groups[net['network-group']]
                                net_suffix = net_group.get('hostname-suffix',
                                                           net['network-group'])
                                alias = "%s-%s-%s-%s" % (hostname_prefix,
                                                         cluster['name'],
                                                         component['mnemonic'],
                                                         net_suffix)
                                self.add_hostname_alias(net, addr, alias)
                                service_ip_data['cluster-ip'] = {'ip_address': addr,
                                                                 'hostname': alias}
                            else:
                                addr = service_ip_data['cluster-ip']['ip_address']

                            if 'service-vips' not in s:
                                s['service-vips'] = {}
                            s['service-vips'][component_name] = addr

        # Build a list of interfaces limited to the ones that need to be configured
        server_ifaces = {}
        for iface in s['interfaces']:
            if iface['networks']:
                server_ifaces[iface['name']] = iface

        s['interfaces'] = server_ifaces

    #
    # Add any auto assigned tags from a component to a network group
    #
    def _add_auto_tags(self, component, net_group, network_tags):

        for auto_tag in component.get('auto-network-tags', []):
            found = False
            for existing_tag in network_tags.get(net_group, []):
                if existing_tag['name'] == auto_tag['name']:
                    found = True
                    break

            if not found:
                tag_data = {
                    'name': auto_tag['name'],
                    'values': {},
                    'definition': auto_tag,
                    'component': component['name'],
                    'service': component['service']
                }
                if net_group not in network_tags:
                    network_tags[net_group] = []
                network_tags[net_group].append(tag_data)

    def get_default_route_cidr(self, cidr):
        if IPNetwork(cidr).version == 6:
            return '::/0'
        return '0.0.0.0/0'

    def get_localhost(self, address):
        if IPAddress(address).version == 6:
            return '::1'
        return '127.0.0.1'

    def process_network(self, net):
        ip_network = IPNetwork(unicode(net['cidr']))
        ip_version = ip_network.version
        address_list = net.get('addresses', None)
        if not address_list:
            # Find the first and last address of the cidr
            cidr_start = IPAddress(ip_network.first, ip_version) + 1
            cidr_end = IPAddress(ip_network.last, ip_version) - (ip_version == 4)
            ip_set = IPSet(IPRange(cidr_start, cidr_end))
        else:
            ip_set = IPSet()
            for address_entry in address_list:
                address = address_entry.split('-')
                if len(address) == 1:
                    ip_set.add(IPAddress(address[0].strip()))
                else:
                    ip_set.add(IPRange(address[0].strip(), address[1].strip()))
        gateway_ip = net.get('gateway-ip', None)
        if gateway_ip:
            ip_set.remove(IPAddress(unicode(gateway_ip)), ip_version)
        net_vips = net.get('vips', [])
        for vip in net_vips:
            vip_addr = vip.get('address', None)
            if vip_addr:
                ip_set.remove(IPAddress(unicode(vip_addr)), ip_version)
        return ip_set, net_vips

    def get_addr_from_net_vips(self, net, roles):

        net_vips = net.get('vips', [])
        vip_addr = None
        for net_vip in net_vips:
            # Search for a vip with a matching 'roles' list
            net_vip_roles = net_vip.get('roles', [])
            if set(roles) == set(net_vip_roles):
                vip_addr = net_vip.get('address', None)
                break
        if not vip_addr:
            # No vip with a matching 'roles' list, get first
            # vip found with an empty 'roles' list
            for net_vip in net_vips:
                net_vip_roles = net_vip.get('roles', None)
                if not net_vip_roles:
                    vip_addr = net_vip.get('address', None)
                    break
        return vip_addr

    def get_dependencies(self):
        return ['encryption-key',
                'internal-model-2.0',
                'network-generator-2.0',
                'configuration-data-generator-2.0',
                'network-tag-generator-2.0']
