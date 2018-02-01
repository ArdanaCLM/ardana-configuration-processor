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
import logging
import logging.config

from ardana_configurationprocessor.cp.model.v2_0.CloudModel \
    import CloudModel

from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog
from ardana_configurationprocessor.cp.model.GeneratorPlugin \
    import GeneratorPlugin


LOG = logging.getLogger(__name__)


class NetworkTagGenerator(GeneratorPlugin):

    def __init__(self, instructions, models, controllers):
        super(NetworkTagGenerator, self).__init__(
            2.0, instructions, models, controllers,
            'network-tag-generator-2.0')

        LOG.info('%s()' % KenLog.fcn())

        self.cloud_desc = self._models['CloudDescription']['cloud']

    def generate(self):
        LOG.info('%s()' % KenLog.fcn())

        cloud_internal = CloudModel.internal(self._models['CloudModel'])

        # Control Planes
        control_planes = CloudModel.get(cloud_internal, 'control-planes')

        # Network Groups
        network_groups = CloudModel.get(cloud_internal, 'network-groups')

        # components
        components = CloudModel.get(cloud_internal, 'components')

        # services
        services = CloudModel.get(cloud_internal, 'services')

        #
        # Find which tags have been deprecated or replaced
        #
        replaced_tags = {}
        deprecated_tags = {}
        for component_name, component in components.iteritems():
            for comp_tag in component.get('network-tags', []):
                for alias in comp_tag.get('aliases', []):
                    replaced_tags[alias] = comp_tag['name']
                if 'deprecated' in comp_tag:
                    deprecated_tags[comp_tag['name']] = comp_tag['deprecated']

        # In previous versions of Ardana OpenStack, any tags defined on a network group are
        # treated as applying to all control planes
        netgroup_tags = self._get_netgroup_tags(network_groups)

        # Process the tags for each cluster / resource group
        tag_found = {}
        for cp_name, cp in control_planes.iteritems():
            cp_components = set()
            for cluster in cp['clusters']:
                for comp_name in cluster['service-components']:
                    cp_components.add(comp_name)
            for r in cp.get('resources', []):
                for comp_name in r['service-components']:
                    cp_components.add(comp_name)

            cp['network-tags'] = self._process_network_tags(cp['config-data-network-tags'],
                                                            netgroup_tags,
                                                            cp_components, components,
                                                            services,
                                                            replaced_tags, deprecated_tags,
                                                            tag_found)

            self._validate_network_tags(cp_name,
                                        cp['network-tags'],
                                        cp['neutron-provider-nets'])

        for tag_name, found in tag_found.iteritems():
            if not found:
                msg = ("Tag '%s' is not defined by any service" % tag_name)
                self.add_warning(msg)

    #
    # Extract all of the tags from network groups and put it
    # in the same format as tags extracted from configuration
    # data (where tags may have come from more that one
    # configuration-data object).
    #
    # Output format is:
    #
    #   {<net_group>: [{'context': context_of_tag_definition,
    #                   'tags':    tag_data_from_netgroup}
    #                 ]
    #   }
    #
    def _get_netgroup_tags(self, network_groups):

        result = {}

        for net_group_name, net_group in network_groups.iteritems():
            context = "Network Group '%s'" % net_group_name
            if 'tags' not in net_group:
                continue
            result[net_group_name] = []

            # Need to keep track of the context we found the tag in
            # for error reporting later
            result[net_group_name].append({'context': context,
                                           'tags': net_group['tags']})

        return result

    #
    # Build a list of network tags for each network group
    # taking values from configuration-data and then network_groups.
    #
    # Validate that tags are in a valid format, and that each tag
    # is defined only once per network groups
    #
    # Input format in both cases is a list of tags defined on each
    # network group:
    #
    #
    #   {<net_group>: [{'context': context_of_tag_definition,
    #                   'tags':    tag_data_from_netgroup}
    #                 ]
    #   }
    #
    # Output Format is a dict where each tag is defined once
    #
    #  {<net_group>: {<tag_name>: {'context': context_of_tag_definition,
    #                              'values': tag_values},
    #                 <tag_name>: {'context': context_of_tag_definition,
    #                              'values': tag_values}
    #                }
    #  }
    #
    def _build_tag_list(self, config_data_tags, netgroup_tags):

        result = {}

        def _add_tags(context, net_group, tags):

            if net_group not in result:
                result[net_group] = {}

            for tag in tags:
                # A tag can be either a string or a dict with a single key
                # depending on whether it has attributes or not
                #
                #  neutron.networks.vxlan
                #
                #  neutron.networks.vxlan:
                #    tenant-vxlan-id-range: 1000:2000
                #
                if isinstance(tag, basestring):
                    tag_name = tag
                    tag_values = {}
                elif isinstance(tag, dict) and len(tag.keys()) == 1:
                    tag_name = tag.keys()[0]
                    tag_values = tag.values()[0]
                else:
                    msg = ("%s: network tag '%s' is an invalid format." %
                           (context, tag))
                    self.add_error(msg)
                    continue

                if tag_name in result[net_group]:
                    msg = ("network tag '%s' is defined more that once for network group '%s'\n"
                           "    %s\n"
                           "    %s\n" %
                           (tag_name, net_group,
                            result[net_group][tag_name]['context'],
                            context))
                    self.add_error(msg)
                else:
                    result[net_group][tag_name] = {'context': context, 'values': tag_values}

        for net_group_name, tag_list in config_data_tags.iteritems():
            for tag_data in tag_list:
                _add_tags(tag_data['context'], net_group_name, tag_data['tags'])

        for net_group_name, tag_list in netgroup_tags.iteritems():
            for tag_data in tag_list:
                _add_tags(tag_data['context'], net_group_name, tag_data['tags'])

        return result

    #
    # Handle any tag deprecation, updating the names as needed.
    #
    def _process_deprecated_tags(self, tags, replaced_tags, deprecated_tags):

        for netgroup_name, netgroup_tags in tags.iteritems():
            for tag_name in sorted(netgroup_tags):
                tag_data = netgroup_tags[tag_name]

                if tag_name in replaced_tags:
                    msg = ("Network tag name '%s' used in %s is deprecated and should be "
                           "replaced with '%s'.  Please update your input model." %
                           (tag_name, tag_data['context'], replaced_tags[tag_name]))
                    self.add_warning(msg)
                    netgroup_tags[replaced_tags[tag_name]] = tag_data
                    del netgroup_tags[tag_name]

                elif tag_name in deprecated_tags:
                    msg = ("Network tag '%s' used in %s is deprecated: %s "
                           "Please update your input model." %
                           (tag_name, tag_data['context'], deprecated_tags[tag_name]))
                    self.add_warning(msg)

    #
    # Process tags by combining tags from configuration data and
    # network groups, and expanding them to include data from the
    # related components (such as needs-bridge) and the schema
    # from the service
    #
    # Output Format is a dict providing an expanded list of
    # tags that apply to the control plane
    #
    #  {<net_group>: [{name:       tag name
    #                  values:     dict of values defined for the tag
    #                  component:  name of component that requires this tag
    #                  service:    name of the service the tage belong to
    #                  context:    where was the tag used in the input model
    #                  definition: tag definition from component
    #                  schema:     schema for tag values from the service
    #                 }]
    #
    def _process_network_tags(self, config_data_tags, netgroup_tags,
                              cp_components, components, services,
                              replaced_tags, deprecated_tags,
                              tag_found):

        # Build a combined list of tags
        tags = self._build_tag_list(config_data_tags, netgroup_tags)

        # Handle deprecated tags
        self._process_deprecated_tags(tags, replaced_tags, deprecated_tags)

        #
        # Expand any network group tags to include the definition
        # from the service component.
        #
        result = {}
        for netgroup_name in sorted(tags):
            netgroup_tags = tags[netgroup_name]
            tag_list = []
            for tag_name, tag_data in netgroup_tags.iteritems():

                if tag_name not in tag_found:
                    tag_found[tag_name] = False

                for component_name in cp_components:
                    component = components[component_name]
                    for comp_tag in component.get('network-tags', []):
                        if comp_tag['name'] == tag_name:
                            tag_data = {'name': tag_name,
                                        'values': tag_data.get('values', {}),
                                        'definition': comp_tag,
                                        'schema': {},
                                        'component': component_name,
                                        'service': components[component_name]['service'],
                                        'context': tag_data['context']}

                            # Get the schema from the service
                            tag_service = services.get(tag_data['service'], {})
                            for tag_schema in tag_service.get('network-tag-schema', []):
                                if tag_schema['name'] == tag_name:
                                    tag_found[tag_name] = True
                                    tag_data['schema'] = tag_schema['schema']
                                    tag_data['unique'] = tag_schema.get('unique', False)

                            tag_list.append(tag_data)

            if tag_list:
                result[netgroup_name] = tag_list

        return result

    #
    # Validate the set of tags for a control plane.
    #    cp_name                 Name of the control plane
    #    tags                    Dict of network tags indexed by network group
    #    neutron_provider_nets   List of physnets referenced in Neutron configuration data
    def _validate_network_tags(self, cp_name, tags, neutron_provider_nets):

        physnets = {}
        unique_tags = {}

        for net_group, tag_list in tags.iteritems():
            for tag in tag_list:
                if 'schema' in tag:
                    physnet_name = self._validate_tag_attributes(tag)
                    if physnet_name:
                        if physnet_name not in physnets:
                            physnets[physnet_name] = []
                        physnet_data = {'name': physnet_name,
                                        'net_group': net_group,
                                        'context': tag['context']}
                        physnets[physnet_name].append(physnet_data)

                if tag.get('unique', False):
                    if tag['name'] not in unique_tags:
                        unique_tags[tag['name']] = {}
                    unique_tags[tag['name']][net_group] = tag['context']

        self._validate_physnets(cp_name, physnets, neutron_provider_nets)
        self._validate_unique_tags(unique_tags)

    def _validate_tag_attributes(self, tag):

        physnet = None

        schema = tag.get('schema', {})

        for attr_name, attr in schema.iteritems():
            if not attr.get('optional', False):
                if attr_name not in tag['values']:
                    msg = ("%s: network tag '%s' is missing the required "
                           "attribute '%s'" %
                           (tag['context'], tag['name'], attr_name))
                    self.add_error(msg)
                    self._valid = False

        for tag_attr, tag_attr_value in tag['values'].iteritems():
            if tag_attr not in schema:
                msg = ("%s: network tag '%s' has an unrecognised attribute: '%s'" %
                       (tag['context'], tag['name'], tag_attr))
                self.add_warning(msg)
            else:
                schema_attr = schema[tag_attr]
                if schema_attr.get('type') == 'physnet':
                    physnet = tag_attr_value
                elif schema_attr.get('type') == 'range':
                    self._validate_range(tag, tag_attr_value, schema_attr)

        return physnet

    def _validate_range(self, tag, range, schema):
        range_pairs = range.split(',')
        valid_range_pairs = []
        range_min = schema.get('min')
        range_max = schema.get('max')
        for range_pair in range_pairs:
            start, end = range_pair.split(':')
            start, end = int(start), int(end)
            if not (start <= end):
                msg = ("%s: %s '%s' is an invalid range." %
                       (tag['context'], tag['name'], range_pair))
                self.add_error(msg)
                self._valid = False
            elif not (range_min <= start <= end <= range_max):
                msg = ("%s: %s '%s' "
                       "is an invalid range. Please specify ranges within "
                       "[%s:%s]" %
                       (tag['context'], tag['name'], range_pair, range_min, range_max))
                self.add_error(msg)
                self._valid = False
            else:
                valid_range_pairs.append(range_pair)

        if len(valid_range_pairs) > 1:
            self._check_range_overlap(tag, valid_range_pairs)

    def _check_range_overlap(self, tag, range_pairs):
        num_pairs = len(range_pairs)
        i = 0
        while i < num_pairs:
            start, end = range_pairs[i].split(':')
            start, end = int(start), int(end)
            j = i + 1
            while j < num_pairs:
                other_start, other_end = range_pairs[j].split(':')
                other_start, other_end = int(other_start), int(other_end)
                disjoint_before = other_start <= other_end < start <= end
                disjoint_after = start <= end < other_start <= other_end
                if not (disjoint_before or disjoint_after):
                    msg = ("%s: %s ID range '%s' overlaps with '%s'" %
                           (tag['context'], tag['name'], range_pairs[i], range_pairs[j]))
                    self.add_error(msg)
                    self._valid = False
                j += 1
            i += 1

    def _validate_physnets(self, cp_name, physnets, neutron_provider_nets):

        # Build a list of network groups in each phsynet
        # and physnets in each network group
        netgroup_physnets = {}
        physnet_netgroups = {}
        for physnet, tags in physnets.iteritems():
            physnet_netgroups[physnet] = {}
            for tag in tags:
                net_group = tag['net_group']
                physnet_netgroups[physnet][net_group] = tag['context']

                if net_group not in netgroup_physnets:
                    netgroup_physnets[net_group] = {}
                netgroup_physnets[net_group][physnet] = tag['context']

        # Check each network group only has one value of physnet
        for net_group, physnets in netgroup_physnets.iteritems():
            if len(physnets) > 1:
                msg = ("Multiple values of provider-physical-network defined for "
                       "network group '%s':\n" % net_group)
                for physnet, context in physnets.iteritems():
                    msg += "   '%s' defined by %s\n" % (physnet, context)
                self.add_error(msg)

        # Check each physnet is only applied to one network group
        for physnet, net_groups in physnet_netgroups.iteritems():
            if len(net_groups) > 1:
                msg = ("provider-physical-network '%s' is defined for "
                       "more than one network group':\n" % physnet)
                for net_group, context in net_groups.iteritems():
                    msg += "   '%s' defined by %s\n" % (net_group, context)
                self.add_error(msg)

        for neutron_net in neutron_provider_nets:
            if neutron_net['physnet'] not in physnet_netgroups:
                msg = ("'%s' used by %s is not defined by a network tag in control plane '%s'" %
                       (neutron_net['physnet'], neutron_net['context'], cp_name))
                self.add_error(msg)

    def _validate_unique_tags(self, unique_tags):
        for tag_name, used in unique_tags.iteritems():
            if len(used) > 1:
                msg = ("Network tag '%s' is defined on more than "
                       "network group in the following context:\n" %
                       (tag_name))
                for net_group, context in used.iteritems():
                    msg += "    %s: %s\n" % (net_group, context)
                self.add_error(msg)

    def get_dependencies(self):
        return ['encryption-key',
                'network-generator-2.0',
                'internal-model-2.0',
                'configuration-data-generator-2.0']
