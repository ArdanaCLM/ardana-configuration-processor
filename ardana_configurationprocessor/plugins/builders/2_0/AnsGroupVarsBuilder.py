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
import yaml

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
from ardana_configurationprocessor.cp.model.v2_0.ArdanaVariable \
    import ArdanaVariable
from ardana_configurationprocessor.cp.lib.DataTransformer \
    import DataTransformer


LOG = logging.getLogger(__name__)


class AnsGroupVarsBuilder(BuilderPlugin):
    def __init__(self, instructions, models, controllers):
        super(AnsGroupVarsBuilder, self).__init__(
            2.0, instructions, models, controllers,
            'ans-group-vars-2.0')
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
        control_planes = CloudModel.get(self._cloud_internal, 'control-planes')
        services = CloudModel.get(self._cloud_internal, 'services')
        components = CloudModel.get(self._cloud_internal, 'components')
        components_by_mnemonic = CloudModel.get(self._cloud_internal, 'components_by_mnemonic')
        pass_through = CloudModel.get(self._cloud_internal, 'pass_through')

        # Create the group vars for each Control Plane
        group_vars = {}
        for cp_name, cp in control_planes.iteritems():
            group_vars[cp_name] = self._build_ansible_group_vars(cloud_name, cp,
                                                                 services, components,
                                                                 components_by_mnemonic)
            #
            # Include disk details of all servers for Swift
            #
            group_vars[cp_name]['control_plane_servers'] = self._build_server_list(cp,
                                                                                   pass_through)

        # Add any global vars - hope to remove this at some stage
        global_vars = {}
        for cp_name, cp in control_planes.iteritems():
            for component_name, config_set in cp.get('config-sets', {}).iteritems():
                if 'global_vars' in config_set:
                    mnemonic = components[component_name]['mnemonic'].replace('-', '_')
                    if mnemonic not in global_vars:
                        global_vars[mnemonic] = {'vars': {}}
                    global_vars[mnemonic]['vars'].update(config_set['global_vars'])

            for component_name in cp['components']:
                if components[component_name].get('advertises_global', False):
                    mnemonic = components[component_name]['mnemonic'].replace('-', '_')
                    if mnemonic not in global_vars:
                        global_vars[mnemonic] = {}
                    global_vars[mnemonic]['advertises'] = group_vars[cp_name][mnemonic]['advertises']

        for cp_name, cp in control_planes.iteritems():
            for component, values in global_vars.iteritems():
                if component not in group_vars[cp_name]:
                    group_vars[cp_name][component] = values

        for cp_name, vars in group_vars.iteritems():
            self._write_cp_group_vars(cloud_name, cp_name, vars)

    def _build_server_list(self, cp, pass_through):
        servers = []
        for cluster in cp.get('clusters', []):
            for server in cluster['servers']:
                if server['state'] == ServerState.ALLOCATED:
                    server_info = self._expand_server(server, pass_through)
                    servers.append(server_info)

        for name, resource in cp.get('resources', {}).iteritems():
            for server in resource['servers']:
                if server['state'] == ServerState.ALLOCATED:
                    server_info = self._expand_server(server, pass_through)
                    servers.append(server_info)
        return servers

    def _expand_server(self, server, pass_through):
        disk_model_out = DataTransformer(server['disk-model']).all_output('-', '_')
        server_info = {'id': server['id'],
                       'name': server['ardana_ansible_host'],
                       'ardana_ansible_host': server['ardana_ansible_host'],
                       'server_group': server.get('server_group', None),
                       'failure_zone': server.get('failure-zone', None),
                       'server_group_list': server.get('server-group-list', []),
                       'control_plane': server.get('control-plane-name'),
                       'disk_model': disk_model_out,
                       'pass_through': pass_through['servers'].get(server['id'], {})}

        network_names = []
        for if_name, if_data in server['interfaces'].iteritems():
            for net_name, net_data in if_data['networks'].iteritems():
                if 'hostname' in net_data:
                    network_names.append(net_data['hostname'])
        server_info['network_names'] = network_names

        return server_info

    def _build_ansible_group_vars(self, cloud_name, cp, services, components, components_by_mnemonic):

        cp_group_vars = {}
        cp_prefix = "%s-%s" % (cloud_name, cp['name'])
        for cluster in cp['clusters']:

            host_prefix = "%s-%s-%s" % (cloud_name, cp['name'], cluster['name'])

            self._build_component_vars(cp_group_vars, cp,
                                       cluster['service-components'],
                                       cluster['servers'], components,
                                       components_by_mnemonic,
                                       services)

            group_vars = {}
            self._build_group_vars(group_vars, cp, cp_prefix, host_prefix,
                                   cluster['service-components'],
                                   cluster['servers'], components,
                                   components_by_mnemonic)

            self._build_service_ips(group_vars, cluster, components)

            group_vars['failure-zones'] = cluster.get('failure-zones',
                                                      cp.get('failure-zones', []))

            # Sort the service list to make it easier to compare accross changes
            group_vars['group']['services'] = \
                sorted(group_vars['group']['services'])

            # Add the Cluster config data
            group_vars['config_data'] = cluster.get('config-data', {})

            # Create group vars for the cluster
            filename = "%s/group_vars/%s-%s-%s" % (
                self._file_path, cloud_name, cp['name'], cluster['name'])
            if not os.path.exists(os.path.dirname(filename)):
                os.makedirs(os.path.dirname(filename))
            self.add_artifact(filename, ArtifactMode.CREATED)
            with open(filename, 'w') as fp:
                yaml.dump(group_vars, fp, default_flow_style=False, indent=4)

        self._build_service_vars(cp_group_vars, cp, services)

        # Add the failure zones for this control plane
        cp_group_vars['failure_zones'] = cp.get('failure-zones', [])

        # Add the list of zone types for this control plane
        cp_group_vars['zone_types'] = {}
        for type, zones in cp.get('zone-types', {}).iteritems():
            cp_group_vars['zone_types'][type] = []
            for zone in sorted(zones):
                cp_group_vars['zone_types'][type].append(zone)

        # Add the Load balancer definitions for this control plane
        if 'load-balancers' in cp:
            cp_group_vars['load_balancers'] = DataTransformer(cp['load-balancers']).all_output('-', '_')

        # Add the list of verb hosts for this control plane
        cp_group_vars['verb_hosts'] = {}
        for component_name in cp['components']:
            component = components[component_name]
            name = component['mnemonic'].replace('-', '_')
            cp_group_vars['verb_hosts'][name] = "%s-%s" % (component['mnemonic'],
                                                           cp['name'])

        for component_name in cp.get('deleted-components', []):
            component = components.get(component_name, {})
            if component:
                name = component['mnemonic'].replace('-', '_') + "_DELETED"
                cp_group_vars['verb_hosts'][name] = "%s-DELETED-%s" % (component['mnemonic'],
                                                                       cp['name'])

        # Add the list of network tag values for this control plane
        cp_group_vars['network_tag_values'] = self._build_network_tag_values(cp)

        # Add the list of network device types used by servers in this control plane
        cp_group_vars['network_device_types'] = self._build_nic_device_types(cp)

        # Add the CP level config data
        cp_group_vars['config_data'] = cp.get('config-data', {})

        if 'resources' in cp:
            for res_name, resources in cp['resources'].iteritems():

                group_vars = {}

                host_prefix = "%s-%s-%s" % (cloud_name, cp['name'], res_name)

                self._build_component_vars(group_vars, cp,
                                           resources['service-components'],
                                           resources['servers'], components,
                                           components_by_mnemonic, services)

                self._build_group_vars(group_vars, cp, cp_prefix, host_prefix,
                                       resources['service-components'],
                                       resources['servers'], components,
                                       components_by_mnemonic)

                self._build_service_ips(group_vars, resources, components)

                group_vars['failure-zones'] = resources.get('failure-zones',
                                                            cp.get('failure-zones', []))

                # Sort the service list to make it easier to compare accross changes
                group_vars['group']['services'] = \
                    sorted(group_vars['group']['services'])

                # Add the Resource Group config data
                group_vars['config_data'] = resources.get('config-data', {})

                filename = "%s/group_vars/%s-%s-%s" % (
                    self._file_path, cloud_name, cp['name'], res_name)
                if not os.path.exists(os.path.dirname(filename)):
                    os.makedirs(os.path.dirname(filename))
                self.add_artifact(filename, ArtifactMode.CREATED)

                with open(filename, 'w') as fp:
                    yaml.dump(group_vars, fp, default_flow_style=False, indent=4)

        return cp_group_vars

    def _write_cp_group_vars(self, cloud_name, cp_name, cp_group_vars):

        # Create the control plane group vars
        filename = "%s/group_vars/%s-%s" % (
            self._file_path, cloud_name, cp_name)
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))
        self.add_artifact(filename, ArtifactMode.CREATED)
        with open(filename, 'w') as fp:
            yaml.dump(cp_group_vars, fp, default_flow_style=False, indent=4)

    def _get_clusters_for_component(self, cp, component, services):
        if component in cp['components']:
            return cp['components'][component]['clusters']
        elif component in services:
            return services[component]['clusters']

    #
    # Build the set of Ansible Vars for a list of components, such
    #   - The endpoints it advertises
    #   - Any components it consumes
    #   - Any components it acts a a proxy for
    #   - Any components it contains
    #   - Any components which consume it
    #
    def _build_component_vars(self, group_vars, cp,
                              component_list, cluster_servers, components,
                              components_by_mnemonic, services):

        for component_name, component_vars in component_list.iteritems():
            if component_name in cp['components']:
                clusters = self._get_clusters_for_component(cp, component_name,
                                                            services)

                component = components[component_name]
                name = component['mnemonic'].replace('-', '_')
                group_vars[name] = {}
                component_group_vars = group_vars[name]

                # Add endpoints for this component
                if component_name in cp['advertises']:
                    vips = cp['advertises'].get(component_name, {})
                    advertises = {'vips': {}}
                    for keystone_data in ['keystone-service-name',
                                          'keystone-service-type']:
                        if keystone_data in component:
                            # NOTE(kuvaja): As Ansible does not allow '-'
                            # character in the variable names, we need to
                            # twiggle around a bit here.
                            advertises[keystone_data.replace('-', '_')] = \
                                component[keystone_data]

                    component_group_vars['advertises'] = advertises
                    component_service = component.get('service', 'foundation')
                    for role in ['admin', 'internal', 'public']:
                        if role in vips:
                            for region_name in sorted(cp.get('regions', {})):
                                region_services = cp['regions'][region_name]
                                if component_service not in region_services:
                                    continue
                                vip = {'host': vips[role]['hostname'],
                                       'ip_address': vips[role]['ip_address'],
                                       'port': vips[role]['port'],
                                       'protocol': vips[role]['protocol'],
                                       'url': vips[role]['url'],
                                       'region_name': region_name}
                                if role == 'internal':
                                    role_name = 'private'
                                else:
                                    role_name = role

                                if role_name not in advertises['vips']:
                                    advertises['vips'][role_name] = []
                                advertises['vips'][role_name].append(vip)

                # Add any advertised endpoints
                if component_name in cp.get('advertised', {}):
                    component_group_vars['advertised'] = cp['advertised'][component_name]

                # Add the details of all components we consume
                component_group_vars.update(cp['components'][component_name].get('consumes', {}))

                # Add members if advertised.  Note that CP1.0 does this
                # on a specific network, but we just have one internal
                # endpoint for each component
                if (component.get('advertise-member-list', False) or
                        'advertise-member-list-on' in component):

                    member_data = cp['members'][component_name]

                    # Build a dict of hosts so we can sort them by
                    # Ansible name (needs to match order in verb_hosts)
                    component_hosts = {}
                    for host_data in member_data['hosts']:
                        component_hosts[host_data['ardana_ansible_host']] = host_data

                    component_group_vars['members'] = {}
                    for role, ports in member_data['ports'].iteritems():

                        if role == 'internal':
                            role_name = 'private'
                        else:
                            role_name = role

                        component_group_vars['members'][role_name] = []
                        members = component_group_vars['members'][role_name]
                        for port in ports:
                            for x in sorted(component_hosts):
                                host_data = component_hosts[x]
                                members.append({'host': host_data['hostname'],
                                                'member_id': host_data['member_id'],
                                                'port': port,
                                                'ardana_ansible_host': host_data['ardana_ansible_host']})
                # Add details of any component we provide a proxy for
                lb_components = cp['load-balancer-config'].get(component_name, {})

                # Add details of any certs
                if lb_components:
                    component_group_vars['cert_data'] = cp['lb-cert-data'][component_name]

                # Add details for each component we provide an LB for
                for lb_component_name, lb_data in lb_components.iteritems():
                    if 'has_proxy' not in component_group_vars:
                        component_group_vars['has_proxy'] = {}
                    proxied_component = components[lb_component_name]['mnemonic'].replace('-', '_')
                    component_group_vars['has_proxy'][proxied_component] = {
                        'networks': [],
                        'servers': [],
                        'initiate_tls': lb_data['host-tls'],
                        'vars': {}}
                    for host_data in lb_data['hosts']:
                        component_group_vars['has_proxy'][proxied_component]['servers'].append(
                            host_data['hostname'])

                    for net_data in lb_data['networks']:

                        proxy_data = {'ports': [net_data['vip-port']],
                                      'server_ports': [net_data['host-port']],
                                      'vip': net_data['hostname'],
                                      'ip_address': net_data['ip-address'],
                                      'terminate_tls': net_data['vip-tls']}

                        if 'vip-options' in net_data:
                            proxy_data['vip_options'] = net_data['vip-options']

                        if 'vip-check' in net_data:
                            proxy_data['vip_check'] = net_data['vip-check']

                        if 'vip-backup-mode' in net_data:
                            proxy_data['vip_backup_mode'] = net_data['vip-backup-mode']

                        if 'cert-file' in net_data:
                            proxy_data['cert_file'] = net_data['cert-file']

                        # Don't tell the load balancer to initiate TLS when the
                        # service says it should be transparent
                        if net_data['vip-tls-terminator']:
                            if 'cert-file' in net_data:
                                proxy_data['cert_file'] = net_data['cert-file']
                        else:
                            component_group_vars['has_proxy'][proxied_component]['initiate_tls'] = False

                        component_group_vars['has_proxy'][proxied_component]['networks'].append(proxy_data)

                # Add details of contained services
                for contains_name, contains_data in component.get('contains', {}).iteritems():
                    rel_name = "%s_has_container" % contains_data['name']
                    component_group_vars[rel_name] = {'members': {},
                                                      'vips': {}
                                                      }
                    context = {'cp': cp['name'],
                               'component': component_name,
                               'contains': contains_name,
                               'clusters': clusters}
                    for var in contains_data.get('relationship-vars', []):
                        if 'vars' not in component_group_vars[rel_name]:
                            component_group_vars[rel_name]['vars'] = {}
                        payload = var['properties'] if 'properties' in var else {}
                        payload['context'] = context
                        value = ArdanaVariable.generate_value(
                            self._instructions, self._models,
                            self._controllers, var['name'], var['value'],
                            self._warnings, self._errors,
                            payload=payload)
                        old_value = ArdanaVariable.get_old_value(
                            self._instructions,
                            self._models,
                            self._controllers, var['name'], var['value'],
                            self._warnings, self._errors,
                            payload=payload)
                        component_group_vars[rel_name]['vars'][var['name']] = value
                        if old_value is not None:
                            if 'old_vars' not in component_group_vars[rel_name]:
                                component_group_vars[rel_name]['old_vars'] = {}
                            component_group_vars[rel_name]['old_vars'][var['name']] = old_value

                    vip_data = []
                    for net, vips in cp['vip_networks'].iteritems():
                        for vip in vips:
                            if vip['component-name'] == contains_name:
                                vip_data.append(vip)
                    for vip in vip_data:
                        for role in vip['roles']:
                            if role == 'internal':
                                role = 'private'
                            component_group_vars[rel_name]['members'][role] = []
                            component_group_vars[rel_name]['vips'][role] = []

                            for host_data in vip['hosts']:
                                component_group_vars[rel_name]['members'][role].append(
                                    {'host': host_data['hostname'],
                                     'port': vip['host-port']
                                     })

                            component_group_vars[rel_name]['vips'][role].append(
                                {'vip': vip['hostname'],
                                 'port': vip['host-port']
                                 })
                # Add Log info
                if 'produces-log-files' in component:
                    component_group_vars['produces_log_files'] = {'vars': {}}
                    component_log_info = component_group_vars['produces_log_files']

                    for log_info in component['produces-log-files']:
                        for var in log_info['relationship-vars']:
                            component_log_info['vars'][var['name']] = []
                            for val in var['value']:
                                for k, v in val.iteritems():
                                    component_log_info['vars'][var['name']].append({k: v})

                # Add data from the config set
                config_set = cp['config-sets'].get(component_name, {})
                component_group_vars['vars'] = config_set.get('vars', {})
                if 'old_vars' in config_set and config_set.get('old_vars') != {}:
                    component_group_vars['old_vars'] = config_set.get('old_vars')

                # Update with any values specific to this instance of the component
                if component_vars:
                    if 'vars' not in component_group_vars:
                        component_group_vars['vars'] = {}
                    component_group_vars['vars'].update(component_vars)

                # Add consumed-by data
                for consumer_info in cp['components'][component_name].get('consumed-by', []):
                    if consumer_info.get('vars', {}):
                        if 'consumed_by' not in component_group_vars:
                            component_group_vars['consumed_by'] = []
                        component_group_vars['consumed_by'].append(consumer_info)

                # Add provided-data data
                if 'provided-data' in cp['components'][component_name]:
                    component_group_vars['provided_data'] = cp['components'][component_name]['provided-data']

    #
    # Build the set of Ansible Vars for list of services, such as
    #   - Any components it consumes
    #
    def _build_service_vars(self, group_vars, cp, services):

        for service_name, service_data in cp.get('services', {}).iteritems():

            if service_name not in services:
                # Can happen for foundation components
                continue

            service = services.get(service_name)
            group_vars[service['mnemonic']] = {}

            group_vars[service['mnemonic']].update(service_data.get('consumes', {}))

            # Add Audit configuration
            group_vars[service['mnemonic']]['audit'] =\
                service_data.get('audit-settings', {})

            # Add region list
            group_vars[service['mnemonic']]['regions'] = []
            for region_name in sorted(cp.get('regions', {})):
                region_services = cp['regions'][region_name]
                if service_name in region_services:
                    group_vars[service['mnemonic']]['regions'].append(region_name)

    #
    # Add group vars that are not the values for each service or component
    #
    def _build_group_vars(self, group_vars, cp, cp_prefix, cluster_prefix,
                          component_list, cluster_servers, components,
                          components_by_mnemonic):

        if 'group' not in group_vars:
            group_vars['group'] = {}

        if 'services' not in group_vars['group']:
            group_vars['group']['services'] = []

        group_vars['group']['vars'] = {}

        for component_name in component_list:
            if component_name in components:
                component = components[component_name]
                group_vars['group']['services'].append(component['mnemonic'])
                group_vars['group']['services'].append(component_name)

    #
    # Add any per service IP data
    #
    def _build_service_ips(self, group_vars, group, components):

        if 'service-ips' in group:
            networks = CloudModel.get(self._cloud_internal, 'networks')
            if 'service_ips' not in group_vars:
                group_vars['service_ips'] = {}

            for name, net_data in group['service-ips'].iteritems():
                mnemonic = components[name]['mnemonic'].replace('-', '_')
                if mnemonic not in group_vars['service_ips']:
                    group_vars['service_ips'][mnemonic] = []
                for net_name, data in net_data.iteritems():
                    info = {'hosts': data.get('hosts', []),
                            'cluster_ip': data.get('cluster-ip', {}),
                            'cidr': networks[net_name].get('cidr')}
                    group_vars['service_ips'][mnemonic].append(info)

    #
    # Build a list of all network tag values within a control plane
    # Tag values are keys by service (to make it easy for a playbook to find the
    # list its interestd in and network group (as the same tag/value will be on
    # multiple hosts and we want to keep them unique within the list)
    #
    def _build_network_tag_values(self, cp):

        network_tag_values = {}
        for cluster in cp['clusters']:
            self._get_network_tag_values(cluster.get('servers', []),
                                         network_tag_values)

        if 'resources' in cp:
            for res_name, resources in cp['resources'].iteritems():
                self._get_network_tag_values(resources.get('servers', []),
                                             network_tag_values)

        return network_tag_values

    #
    # Update a list of all network tag values from a list of servers
    #
    @staticmethod
    def _get_network_tag_values(servers, tag_values):

        for server in servers:
            for if_name, if_data in server['interfaces'].iteritems():
                for net_name, net_data in if_data['networks'].iteritems():
                    for tag in net_data.get('service-tags', []):
                        if tag['service'] not in tag_values:
                            tag_values[tag['service']] = {}
                        if net_data['network-group'] not in tag_values[tag['service']]:
                            tag_values[tag['service']][net_data['network-group']] = {}
                        net_group_tag_values = tag_values[tag['service']][net_data['network-group']]
                        if tag['name'] not in net_group_tag_values:
                            net_group_tag_values[tag['name']] = tag['values']

    #
    # Build a list of all the device types used in this control plane
    #
    def _build_nic_device_types(self, cp):

        device_types = []
        device_type_names = set()
        servers = []

        for cluster in cp['clusters']:
            servers.extend(cluster.get('servers', []))

        if 'resources' in cp:
            for res_name, resources in cp['resources'].iteritems():
                servers.extend(resources.get('servers', []))

        for server in servers:
            if server.get('nic_map', {}):
                for device in server['nic_map']['physical-ports']:
                    if ('nic-device-type' in device and
                            device['nic-device-type']['name'] not in device_type_names):
                        dev_type = device['nic-device-type']
                        nic_type = {'name': dev_type['name'],
                                    'device_id': dev_type['device-id'],
                                    'vendor_id': dev_type['family_data']['vendor-id'],
                                    'family': dev_type['family']}
                        device_types.append(nic_type)
                        device_type_names.add(device['nic-device-type']['name'])

        return device_types

    def get_dependencies(self):
        return ['persistent-state-2.0']
