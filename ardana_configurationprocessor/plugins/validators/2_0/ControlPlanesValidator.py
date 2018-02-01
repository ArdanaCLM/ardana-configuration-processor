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
import logging.config

from ardana_configurationprocessor.cp.model.ValidatorPlugin \
    import ValidatorPlugin
from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog

from ardana_configurationprocessor.cp.model.v2_0 \
    import AllocationPolicy


LOG = logging.getLogger(__name__)


class ControlPlanesValidator(ValidatorPlugin):
    def __init__(self, instructions, config_files):
        super(ControlPlanesValidator, self).__init__(
            2.0, instructions, config_files,
            'control-planes-2.0')
        LOG.info('%s()' % KenLog.fcn())

    def validate(self):
        LOG.info('%s()' % KenLog.fcn())
        version = float(self.version())

        input = self._create_content(version, "control-planes")
        if input:
            valid = self.validate_schema(input, "control-plane")

        if valid:
            self._check_for_unique_cp_names(input['control-planes'])

            components = self._get_dict_from_config_value(version, 'service-components')

            components_by_mnemonic = {}
            for c_name, c_data in components.iteritems():
                components_by_mnemonic[c_data['mnemonic']] = c_data

            configuration_data = self._get_config_value(version, 'configuration-data')
            if not configuration_data:
                configuration_data = []

            regions = self._get_config_value(version, 'regions')
            if not regions:
                regions = []

            self._check_regions(regions, input['control-planes'])
            for cp in input['control-planes']:
                self._check_deprecations(cp)
                self._expand_components(cp)
                self._add_required_components(cp, components)
                self._check_and_expand_regions(cp, regions, components)
                self._check_for_unique_names(cp)
                self._check_allocation_policy(cp)
                self._check_components(cp, components)
                self._check_containers(cp, components, components_by_mnemonic)
                self._check_warnings(cp, components)
                self._check_configuration_data(cp, configuration_data, components)

            self._check_only_one_instance(input['control-planes'], components)
            self._check_uses_from(input['control-planes'], components)

        LOG.info('%s()' % KenLog.fcn())
        return valid

    #
    # Check for unique cp names
    #
    def _check_for_unique_cp_names(self, control_planes):
        cp_name = {}
        cp_prefix = {}
        for cp in control_planes:
            if cp['name'] not in cp_name:
                cp_name[cp['name']] = 0
            cp_name[cp['name']] += 1

            prefix = cp.get('control-plane-prefix', None)
            if prefix and prefix not in cp_prefix:
                cp_prefix[prefix] = 0
            if prefix:
                cp_prefix[prefix] += 1

        for name, number in cp_name.iteritems():
            if number > 1:
                msg = ("Control plane name '%s' is not unique" % name)
                self.add_error(msg)
                self._valid = False

        for name, number in cp_prefix.iteritems():
            if number > 1:
                msg = ("Control-plane-prefix '%s' is not unique" % name)
                self.add_error(msg)
                self._valid = False

    #
    # Check deprectaions
    #
    def _check_deprecations(self, cp):

        if 'member-groups' in cp:
            msg = ("%s: Use of 'member-groups' is deprecated, "
                   "Use 'clusters' instead." % (cp['name']))
            self.add_warning(msg)
            cp['clusters'] = cp['member-groups']
            del cp['member-groups']

        if 'resource-nodes' in cp:
            msg = ("Control Plane '%s': Use of 'resource-nodes' is deprecated, "
                   "Use 'resources' instead." % (cp['name']))
            self.add_warning(msg)
            cp['resources'] = cp['resource-nodes']
            del cp['resource-nodes']

    #
    # Check than names and prefices are unique within
    # a control plane
    #
    def _check_for_unique_names(self, cp):

        names = set()
        prefices = set()

        def _check_name(name):
            if name in names:
                msg = ("%s: Duplicate cluster/resource name '%s'" %
                       (cp['name'], name))
                self.add_error(msg)
            else:
                names.add(name)

        def _check_prefix(prefix):
            if prefix in prefices:
                msg = ("%s: Duplicate cluster/resource prefix: '%s' " %
                       (cp['name'], prefix))
                self.add_error(msg)
            else:
                prefices.add(prefix)

        for cluster in cp.get('clusters', []):
            _check_name(cluster['name'])
            if 'cluster-prefix' in cluster:
                _check_prefix(cluster['cluster-prefix'])

        for r in cp.get('resources', []):
            _check_name(r['name'])
            if 'resource-prefix' in r:
                _check_prefix(r['resource-prefix'])

    #
    # Check that allocation policies are valid
    #
    def _check_allocation_policy(self, cp):

        def _check_policy(policy, context):
            if policy not in AllocationPolicy.valid:
                msg = ("%s: Invalid allocation policy '%s' " %
                       (context, policy))
                self.add_error(msg)

        for cluster in cp.get('clusters', []):
            context = "%s:%s" % (cp['name'], cluster['name'])
            if 'allocation-policy' in cluster:
                _check_policy(cluster['allocation-policy'], context)

        for r in cp.get('resources', []):
            context = "%s:%s" % (cp['name'], r['name'])
            if 'allocation-policy' in r:
                _check_policy(r['allocation-policy'], context)

    #
    # Check that the components are valid
    #
    def _check_components(self, cp, components):

        def _check_component_exists(comp_name, context):
            if comp_name not in components:
                msg = ("%s: Undefined component '%s'" %
                       (context, comp_name))
                self.add_error(msg)

        context = "%s:%s" % (cp['name'], 'common-service-components')
        for comp_name in cp.get('common-service-components', []):
            _check_component_exists(comp_name, context)

        for cluster in cp['clusters']:
            context = "%s:%s" % (cp['name'], cluster['name'])
            for comp_name in cluster['service-components']:
                _check_component_exists(comp_name, context)

        for r in cp.get('resources', []):
            context = "%s:%s" % (cp['name'], r['name'])
            for comp_name in r['service-components']:
                _check_component_exists(comp_name, context)

    #
    # Check that all components are co-located with thier container
    #
    def _check_containers(self, cp, components, components_by_mnemonic):

        def _check_container(comp_name, list, context):
            if comp_name not in components:
                return
            component = components[comp_name]
            for container_data in component.get('has-container', []):
                container_name = container_data['service-name']
                if container_name in components_by_mnemonic:
                    container_name = components_by_mnemonic[container_name]['name']
                if container_name and container_name not in list:
                    msg = ("%s: '%s' needs to be co-hosted with '%s'" %
                           (context, comp_name, container_name))
                    self.add_error(msg)

        for cluster in cp['clusters']:
            context = "%s:%s" % (cp['name'], cluster['name'])
            for comp_name in cluster['service-components']:
                _check_container(comp_name, cluster['service-components'],
                                 context)

        for r in cp.get('resources', []):
            context = "%s:%s" % (cp['name'], r['name'])
            for comp_name in r['service-components']:
                _check_container(comp_name, r['service-components'],
                                 context)

    #
    # Check for any warnings a component has
    #
    def _check_warnings(self, cp, components):

        def _check_component_warnings(comp_name, context):
            if comp_name not in components:
                return
            for warning in components[comp_name].get('warnings', []):
                msg = ("%s: %s" %
                       (context, warning))
                self.add_warning(msg)

        context = "%s:%s" % (cp['name'], 'common-service-components')
        for comp_name in cp.get('common-service-components', []):
            _check_component_warnings(comp_name, context)

        for cluster in cp['clusters']:
            context = "%s:%s" % (cp['name'], cluster['name'])
            for comp_name in cluster['service-components']:
                _check_component_warnings(comp_name, context)

        for r in cp.get('resources', []):
            context = "%s:%s" % (cp['name'], r['name'])
            for comp_name in r['service-components']:
                _check_component_warnings(comp_name, context)

    #
    # Check configuration data exists, and at least one service is in scope
    #
    def _check_configuration_data(self, cp, configuration_data, components):

        def _check_config_data(name, service_list, context):

            if name in config_data:
                service_found = False
                config_service_list = config_data[name].get('services', [])
                if not config_service_list:
                    return
                for service in config_service_list:
                    if service in service_list:
                        service_found = True
                        break
                if not service_found:
                    msg = ("None of the services %s for configuration data '%s' "
                           "are in scope for the context '%s' so this "
                           "data will not be used."
                           % (config_service_list, name, context))
                    self.add_warning(msg)
            else:
                msg = ("%s: Configuration data '%s' is not defined."
                       % (context, name))
                self.add_error(msg)

        config_data = {}
        for c in configuration_data:
            config_data[c['name']] = c

        cp_service_list = set()
        common_service_list = set()
        for c in cp.get('common-service-components', {}):
            common_service_list.add(components.get(c, {}).get('service', 'foundation'))

        for cluster in cp['clusters']:
            context = "%s:%s" % (cp['name'], cluster['name'])
            service_list = set()
            for c in cluster.get('service-components', {}):
                service_list.add(components.get(c, {}).get('service', 'foundation'))
            service_list.update(common_service_list)
            cp_service_list.update(service_list)
            for name in cluster.get('configuration-data', []):
                _check_config_data(name, service_list, context)

        for r in cp.get('resources', []):
            context = "%s:%s" % (cp['name'], r['name'])
            service_list = set()
            for c in r.get('service-components', {}):
                service_list.add(components.get(c, {}).get('service', 'foundation'))
            service_list.update(common_service_list)
            cp_service_list.update(service_list)
            for name in r.get('configuration-data', []):
                _check_config_data(name, service_list, context)

        context = "%s" % (cp['name'])
        for name in cp.get('configuration-data', []):
            _check_config_data(name, cp_service_list, context)

    #
    # Converts component lists in clusters and control planes
    # into a consistent data structure by changing all entries to
    # dicts to make a consistent type (they can be either strings or
    # dicts in the input model)
    #
    # Logically in the CP this would be a migrator, but we need to do it here
    # to avoid all of the validation code having to include the same logic
    #
    def _expand_components(self, cp):

        # Common service components
        comps = {}
        for comp in cp.get('common-service-components', []):
            if isinstance(comp, dict):
                name = comp.keys()[0]
                comps[name] = comp[name]
            else:
                comps[comp] = {}
        cp['common-service-components'] = comps

        # Clusters
        for cluster in cp['clusters']:
            comps = {}
            for comp in cluster['service-components']:
                if isinstance(comp, dict):
                    name = comp.keys()[0]
                    comps[name] = comp[name]
                else:
                    comps[comp] = {}
            cluster['service-components'] = comps

        for r in cp.get('resources', []):
            comps = {}
            for comp in r['service-components']:
                if isinstance(comp, dict):
                    name = comp.keys()[0]
                    comps[name] = comp[name]
                else:
                    comps[comp] = {}
            r['service-components'] = comps

    #
    # Check that services which can only have a single instance in cloud
    # are only running on one cluster
    #
    def _check_only_one_instance(self, control_planes, components):
        service_clusters = {}
        for cp in control_planes:
            for cluster in cp['clusters']:
                for comp_name in list(set(cluster['service-components'].keys() +
                                          cp.get('common-service-components', {}).keys())):
                    if comp_name not in service_clusters:
                        service_clusters[comp_name] = []
                    service_clusters[comp_name].append((cp['name'], cluster['name']))

            for r in cp.get('resources', []):
                for comp_name in list(set(r['service-components'].keys() +
                                          cp.get('common-service-components', {}).keys())):
                    if comp_name not in service_clusters:
                        service_clusters[comp_name] = []
                    service_clusters[comp_name].append((cp['name'], r['name']))

        for comp_name, clusters in service_clusters.iteritems():
            if components.get(comp_name, {}).get('can-only-have-one-instance', False) \
                    and len(clusters) > 1:
                msg = ("Component '%s' which can only have one instance is specified on "
                       "more than one cluster in the input model: '%s'" %
                       (comp_name, ", ".join("(control-plane: %s, cluster: %s)" % tup
                                             for tup in clusters)))
                self.add_error(msg)

    #
    # Check consumes from other cps
    #
    def _check_uses_from(self, control_planes, components):

        for cp in control_planes:

            for uses in cp.get('uses', []):
                other_cp = filter(lambda x: x['name'] == uses['from'], control_planes)
                if not other_cp:
                    msg = ("Undefined Control plane '%s' in uses section of "
                           "control plane '%s'." %
                           (uses['from'], cp['name']))
                    self.add_error(msg)
                    self._valid = False
                    continue

                other_cp = other_cp[0]
                if cp['name'] == other_cp['name']:
                    msg = ("Control plane '%s' references itself in the uses section." %
                           (cp['name']))
                    self.add_error(msg)
                    self._valid = False
                    continue

                for comp in uses.get('service-components', []):
                    if comp in ['any', 'all']:
                        continue

                    if comp not in components:
                        msg = ("Undefined service component '%s' in uses section of "
                               "control plane '%s'." %
                               (comp, cp['name']))
                        self.add_error(msg)
                        self._valid = False
                        continue

                    if comp not in self._get_all_components(other_cp):
                        msg = ("Control plane %s uses '%s' from control plane '%s', but "
                               "'%s' is not part of that control plane." %
                               (cp['name'], comp, other_cp['name'], comp))
                        self.add_error(msg)
                        self._valid = False
                        continue

    #
    # Update a component list with any required dependencies
    #
    # Logically in the CP this would be a migrator, but we need to do it here
    # to avoid all of the validation code having to include the same logic
    #
    def _add_required_components(self, cp, components):

        def _add_required(component_list):
            for comp_name in component_list.keys():
                if comp_name not in components:
                    continue
                for requires in components[comp_name].get('requires', []):
                    required_comp = requires.get('name')
                    if (requires.get('scope') == 'host' and
                            required_comp not in component_list):
                        component_list[required_comp] = {}

        if 'common-service-components' in cp:
            _add_required(cp['common-service-components'])

        for cluster in cp['clusters']:
            _add_required(cluster['service-components'])

        for r in cp.get('resources', []):
            _add_required(r['service-components'])

    #
    # Check that we have a regions object when it is required (i.e. when there
    # is more than one control-plane), that we aren't mixing regions and
    # 'region-name'
    # Check all control-planes in regions are valid
    #
    def _check_regions(self, regions, control_planes):

        if len(control_planes) > 1 and not regions:
            msg = ("Detected more than one control plane and no regions object. "
                   "Please add a regions object to your input")
            self.add_error(msg)
            self._valid = False

        elif len(control_planes) == 1 and not regions:
            if not control_planes[0].get('region-name', None):
                msg = ("The input model specifies one control plane but no regions "
                       "object has been detected and there is no 'region-name' attribute "
                       "to the control plane.  Please add a regions object")
                self.add_error(msg)
                self._valid = False

        cp_names = set()
        for cp in control_planes:
            cp_names.add(cp['name'])
            if cp.get('region-name', None) and regions:
                msg = ("Have regions object but control plane '%s' is using "
                       "'region-name'.  Please remove the 'region-name'" % cp['name'])
                self.add_error(msg)
                self._valid = False

        for region in regions:
            for includes in region.get('includes', []):
                if includes['control-plane'] not in cp_names:
                    msg = ("Region '%s': Control Plane '%s' not defined. " %
                           (region['name'], includes['control-plane']))
                    self.add_error(msg)
                    self._valid = False

    #
    #
    # Validate that services listed for a region are in the control plane, and
    # add a list of regions/services in each control plane.
    #
    # Logically in the CP this would be a migrator, but we need to do it here
    # to enable validation
    #
    def _check_and_expand_regions(self, cp, regions, components):

        all_services = self._get_all_services(cp, components)

        if 'regions' not in cp:
            cp['regions'] = {}

        # Convert old style "region-name" into an entry in the regions list
        if 'region-name' in cp:
            region_def = {'name': cp['region-name'],
                          'includes': [{'control-plane': cp['name'],
                                        'services': ['all']}]}
            regions.append(region_def)

        # Buile a per-region list of serices for this CP
        for region in regions:
            for includes in region.get('includes', []):

                if includes['control-plane'] != cp['name']:
                    continue

                if region['name'] not in cp['regions']:
                    cp['regions'][region['name']] = []

                for service_name in includes.get('services', []):

                    if service_name == 'all':
                        cp['regions'][region['name']].extend(all_services)
                        continue

                    if service_name not in all_services:
                        msg = ("Region '%s': Service '%s' is not part of "
                               "control plane '%s'." %
                               (region['name'], service_name, cp['name']))
                        self.add_error(msg)
                        self._valid = False
                        continue
                    else:
                        cp['regions'][region['name']].append(service_name)

    #
    # return a list of all components in a control plane
    #
    def _get_all_components(self, cp):

        result = set()
        for comp in cp.get('common-service-components', []):
            result.add(comp)
        for cluster in cp.get('clusters', []):
            for comp in cluster['service-components']:
                result.add(comp)
        for r in cp.get('resources', []):
            for comp in r['service-components']:
                result.add(comp)

        return list(result)

    #
    # return a list of all servcies from a list of component names
    #
    def _get_all_services(self, cp, components):

        services = set()
        for comp in self._get_all_components(cp):
            # Can't assume all compoenents are valid yet
            if comp in components:
                services.add(components[comp].get('service', 'foundation'))

        return list(services)

    @property
    def instructions(self):
        return self._instructions

    def get_dependencies(self):
        return ['config-data-2.0',
                'service-components-2.0',
                'regions-2.0']
