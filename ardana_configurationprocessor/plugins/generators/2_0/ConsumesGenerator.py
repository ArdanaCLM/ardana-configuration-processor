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

from copy import deepcopy
from operator import itemgetter

from ardana_configurationprocessor.cp.model.CPLogging import \
    CPLogging as KenLog
from ardana_configurationprocessor.cp.model.GeneratorPlugin \
    import GeneratorPlugin
from ardana_configurationprocessor.cp.model.v2_0.CloudModel \
    import CloudModel
from ardana_configurationprocessor.cp.model.v2_0.ArdanaVariable \
    import ArdanaVariable


LOG = logging.getLogger(__name__)


class ConsumesGenerator(GeneratorPlugin):
    def __init__(self, instructions, models, controllers):
        super(ConsumesGenerator, self).__init__(
            2.0, instructions, models, controllers,
            'consumes-generator-2.0')
        LOG.info('%s()' % KenLog.fcn())

    def generate(self):
        LOG.info('%s()' % KenLog.fcn())

        self._action = KenLog.fcn()
        cloud_internal = CloudModel.internal(self._models['CloudModel'])

        components = CloudModel.get(cloud_internal, 'components', [])
        # If we have an error in an earlier generator we may not have
        # components in the internal model
        if not components:
            return

        components_by_mnemonic = CloudModel.get(cloud_internal, 'components_by_mnemonic')
        self.services = CloudModel.get(cloud_internal, 'services', [])
        control_planes = CloudModel.get(cloud_internal, 'control-planes')

        # Resolve the service level consumes for all control planes before we
        # do the component level consumes - as a component may need to find
        # the service relationship in a parent control plane
        #
        for cp_name, cp in control_planes.iteritems():
            for service_name, service_data in cp.get('services', []).iteritems():
                if service_name not in self.services:
                    continue
                service_data['consumes'] = self._get_consumes(self.services[service_name],
                                                              components,
                                                              components_by_mnemonic,
                                                              cp,
                                                              control_planes)

        # Resolve the component level consumes relationships.  If there is a
        # service level consumes relationship then any values from that override
        # any component level vaules (Normally if there is a service level relationship
        # then only that has relationship vars)
        #
        for cp_name, cp in control_planes.iteritems():
            for comp_name, comp_data in cp.get('components', []).iteritems():
                consumer = components[comp_name]
                comp_data['consumes'] = self._get_consumes(components[comp_name],
                                                           components,
                                                           components_by_mnemonic,
                                                           cp,
                                                           control_planes)

                # Add any values from a service level relationship
                consumer_service = consumer.get('service', 'foundation')
                for consumed_component in comp_data['consumes']:
                    service_consumes = self._get_service_consumes(consumer_service,
                                                                  consumed_component, cp)
                    if service_consumes:
                        self._update_no_overwrite(comp_data['consumes'][consumed_component],
                                                  deepcopy(service_consumes))

                # Process the config set for this component
                if 'config-sets' not in cp:
                    cp['config-sets'] = {}
                context = {'cp': cp['name'],
                           'consuming-cp': cp['name'],
                           'component': comp_name,
                           'clusters': self._get_clusters_for_component(cp, comp_name)}
                cp['config-sets'][comp_name] = self._process_config_set(components[comp_name],
                                                                        context)

        self._validate_multi_consumers(control_planes, components)

    def _update_no_overwrite(self, d, u):
        for k, v in u.iteritems():
            if k not in d or not d[k]:
                d[k] = v

    def _get_clusters_for_component(self, cp, component):
        if component in cp['components']:
            return cp['components'][component]['clusters']
        elif component in cp['services']:
            return cp['services'][component]['clusters']

    #
    # Build the set of component consumes relationships in the context of a
    # specific control plane
    #
    def _get_consumes(self, consumer, components, components_by_mnemonic, cp, control_planes):

        result = {}

        component_name = consumer['name']
        for consume in consumer.get('consumes-services', []):

            consumed_component_name = consume['service-name']
            if consumed_component_name not in components:
                consumed_component_name = components_by_mnemonic[consume['service-name']]['name']

            consumed_component = components[consumed_component_name]

            consume_name = "consumes_%s" % consumed_component['mnemonic'].replace('-', '_')
            result[consume_name] = {}
            consumes = result[consume_name]
            consumed_by = {'cp': cp['name'],
                           'component': component_name}

            consumes['vars'] = {}
            consumed_by['vars'] = {}

            scope = consume.get('scope', 'cloud')

            ep, service_vips, consumed_cp, regions = self._get_endpoint(consumed_component_name, cp, control_planes,
                                                                        components, scope)

            if service_vips:
                consumes['service_vips'] = deepcopy(service_vips)

            if 'relationship-vars' in consume:
                context = {'cp': consumed_cp,
                           'consuming-cp': cp['name'],
                           'component': component_name,
                           'consumes': consumed_component_name,
                           'clusters': self._get_clusters_for_component(cp, component_name)}
                schema = consumed_component.get('relationship-vars-schema', {})
                relationship = "%s consumes %s" % (component_name, consume['service-name'])
                vars, aliases, old_vars, old_aliases = self._process_vars(
                    consume['relationship-vars'], relationship, context, schema)
                consumed_by['vars'] = vars
                consumes['vars'] = deepcopy(vars)
                consumes['vars'].update(aliases)
                if old_vars is not None:
                    consumed_by['old_vars'] = old_vars
                    consumes['old_vars'] = deepcopy(old_vars)
                    consumes['old_vars'].update(old_aliases)

            consumes['name'] = consumed_component_name
            consumes['service'] = consumed_component['service']

            if ep:
                cons_cp = control_planes[consumed_cp]
                if 'consumed-by' not in cons_cp['components'][consumed_component_name]:
                    cons_cp['components'][consumed_component_name]['consumed-by'] = []
                cons_cp['components'][consumed_component_name]['consumed-by'].append(consumed_by)

                consumes['regions'] = regions

            else:
                del result[consume_name]

                # Some consumes relationships are optional.
                if consume.get('optional', False):
                    continue

                msg = ("%s: %s expects to consume %s, but %s "
                       "doesn't have an internal endpoint." %
                       (cp['name'], component_name, consumed_component_name,
                        consumed_component_name))
                self.add_error(msg)
                continue

            for role, role_data in ep.iteritems():

                # Never give a public or admin endpoint to a consumer
                if role in ['public', 'admin']:
                    continue

                # CP used 'private' as the name for  internal endpoints
                # in the playbooks so we have to stick with that
                if role == 'internal':
                    role_name = 'private'
                else:
                    role_name = role

                for data in role_data:
                    if 'address' in data.get('access', {}):

                        if ('consumes-vips' in consume and
                                role not in consume['consumes-vips']):
                            continue

                        if data['access']['use-tls']:
                            protocol = consumer.get('tls_protocol', 'https')
                        else:
                            protocol = consumer.get('nontls_protocol', 'http')
                        url = "%s://%s:%s" % (protocol,
                                              data['access']['hostname'],
                                              data['access']['port'])
                        if 'vips' not in consumes:
                            consumes['vips'] = {}
                        if role_name not in consumes['vips']:
                            consumes['vips'][role_name] = []

                        consumes['vips'][role_name].append({'ip_address': data['access']['address'],
                                                            'network': data['access']['network'],
                                                            'host': data['access']['hostname'],
                                                            'port': data['access']['port'],
                                                            'protocol': protocol,
                                                            'url': url,
                                                            'use_tls': data['access']['use-tls']})
                for data in role_data:
                    if 'members' in data.get('access', {}):

                        if ('consumes-members' in consume and
                                role not in consume['consumes-members']):
                            continue

                        if 'members' not in consumes:
                            consumes['members'] = {}
                        if 'role_name' not in consumes['members']:
                            consumes['members'][role_name] = []
                        for member in sorted(data['access']['members'], key=itemgetter('hostname')):
                            member_data = {'host': member['hostname'],
                                           'ardana_ansible_host': member['ardana_ansible_host'],
                                           'ip_address': member['ip_address'],
                                           'network': member['network'],
                                           'port': data['access']['port'],
                                           'use_tls': data['access']['use-tls']}
                            # A consumer can ask for the hostname if it needs to report metrics
                            # against the target (for example monasca host liveness check)
                            if consume.get('needs-host-dimensions', False):
                                member_data['host_dimensions'] = deepcopy(member['host_dimensions'])

                            consumes['members'][role_name].append(member_data)

        return result

    #
    # Find the endpoint of a service looking up through the
    # control planes
    #
    def _get_endpoint(self, component_name, cp, control_planes, components, scope):
        #
        # Get the endpoint for a component from the control plane
        # or its parent
        #
        ep = cp['endpoints'].get(component_name, {})
        service_vips = cp['service-vips'].get(component_name, {})
        consumed_cp = None
        regions = []

        if ep:
            consumed_cp = cp['name']
            for region_name, region_services in cp['regions'].iteritems():
                if components[component_name]['service'] in region_services:
                    regions.append(region_name)

        elif scope != 'control-plane':
            for uses in cp.get('uses', []):
                uses_from_cp = uses.get('service-components', [])
                if 'any' in uses_from_cp or 'all' in uses_from_cp or component_name in uses_from_cp:
                    ep, service_vips, consumed_cp, regions = self._get_endpoint(component_name,
                                                                                control_planes[uses['from']],
                                                                                control_planes, components, scope)

        return ep, service_vips, consumed_cp, regions

    #
    # Find data for a service level consumes of a compoent by looking up
    # through control planes
    #
    def _get_service_consumes(self, service_name, comp_name, cp):
        service_consumes = {}

        if service_name in cp['services']:
            if comp_name in cp['services'][service_name].get('consumes', {}):
                service_consumes = cp['services'][service_name]['consumes'][comp_name]

        if not service_consumes and 'parent-cp' in cp:
            service_consumes = self._get_service_consumes(service_name, comp_name,
                                                          cp['parent-cp'])

        return service_consumes

    #
    # Process config-set
    #
    def _process_config_set(self, component, context):

        result = {'vars': {}, 'old_vars': {}}

        for config in component.get('config-set', []):
            relationship = '%s.config-set' % component['name']
            vars, aliases, old_vars, old_aliases = self._process_vars(
                config.get('ansible-vars', []), relationship, context)
            result['vars'].update(vars)
            if old_vars:
                result['old_vars'].update(old_vars)

        # Add a list of any values which have to be global
        if 'global-vars' in component:
            result['global_vars'] = {}
            for global_var in component['global-vars']:
                result['global_vars'][global_var] = result['vars'][global_var]

        return result

    #
    # Expand a list of relationship vars.
    #
    def _process_vars(self, vars, relationship, context={}, schema={}):

        result = {}
        aliases = {}
        old_result = {}
        old_aliases = {}

        if isinstance(vars, list):
            # Got a list, each element of which is a expected to
            # be an Ardana OpenStack variable with name, value, and optionally properties
            for var in vars:
                if not isinstance(var, dict):
                    self.add_error("Non dict data type (%s) when processing relationship "
                                   "variables in %s: %s" % (type(var), relationship, var))
                    continue

                if 'name' not in var:
                    self.add_error("Missing name attribute when processing relationship "
                                   "variables in %s: %s" % (relationship, var))
                    continue

                if 'vars' in var:

                    if 'value' in var:
                        self.add_error("'vars' and 'value' are mutually exclusive "
                                       "in a relationship variable "
                                       "variables in %s: %s" % (relationship, var))
                        continue

                    # Service wants us to parse this var as a dict where each value
                    # is a list of relationship vars
                    if not isinstance(var['vars'], dict):
                        self.add_error("Non dict data type (%s) when processing relationship "
                                       "variables in %s: %s" % (type(var), relationship, var['name']))
                        continue

                    result[var['name']] = {}
                    # Find the schema entry
                    vars_schema = {}
                    for s in schema:
                        if s.get('name') == var['name']:
                            vars_schema = s.get('vars', {})
                            break
                    for k, v in var['vars'].iteritems():
                        var_res, var_aliases, old_var_res, old_var_aliases = \
                            self._process_vars(v, relationship, context, vars_schema)
                        result[var['name']][k] = var_res
                        if old_var_res is not None:
                            if var['name'] not in old_result:
                                old_result[var['name']] = {}
                            old_result[var['name']][k] = old_var_res

                        # Aliases are always added at the top level of the vars
                        aliases.update(var_aliases)
                        old_aliases.update(old_var_aliases)

                elif 'value' not in var:
                    self.add_error("Missing 'value' attribute when processing relationship "
                                   "variables in %s: %s" % (relationship, var))
                    continue

                else:
                    payload = var.get('properties', {})
                    # For the moment we treat all keys in a variable dict as if they
                    # are properties apart from name and value
                    for key, value in var.iteritems():
                        if key not in ['name', 'value', 'properties']:
                            payload[key] = value
                    payload['context'] = context
                    if 'scope' not in payload:
                        payload['scope'] = 'control-plane'
                    value = ArdanaVariable.generate_value(self._instructions,
                                                          self._models,
                                                          self._controllers,
                                                          var['name'], var['value'],
                                                          self._warnings,
                                                          self._errors,
                                                          payload=payload)
                    old_value = ArdanaVariable.get_old_value(self._instructions,
                                                             self._models,
                                                             self._controllers,
                                                             var['name'], var['value'],
                                                             self._warnings,
                                                             self._errors,
                                                             payload=payload)
                    result[var['name']] = value
                    if old_value is not None:
                        old_result[var['name']] = old_value
                    if 'alias' in var:
                        aliases[var['alias']] = value
                        if old_value is not None:
                            old_aliases[var['alias']] = old_value

        else:
            self.add_error("Unexpected data type (%s) when processing relationship "
                           "variables in %s" % (type(vars), relationship))

        # Check all values have been supplied and add any defaults
        for s in schema:

            if s['name'] in result:
                continue
            if 'default' in s:
                result[s['name']] = deepcopy(s['default'])
            else:
                msg = ("Missing relationship variable %s in %s"
                       % (s['name'], relationship))
                self.add_error(msg)

        return result, aliases, old_result if old_result != {} else None, old_aliases

    #
    # Validate the mutliple consumers of a component.   A component can optionally
    # define a list of services that are allowed to consume it from different control
    # planes via a "mulit-consumers" stanza which defines a default behaviour
    # and optional lists of services that are blocked  or allowed.
    #
    def _validate_multi_consumers(self, control_planes, components):

        for cp_name, cp in control_planes.iteritems():
            for comp_name, comp_data in cp.get('components', {}).iteritems():
                consumers = {}
                for consumer in comp_data.get('consumed-by', []):
                    if consumer['component'] not in consumers:
                        consumers[consumer['component']] = []
                    if consumer['cp'] not in consumers[consumer['component']]:
                        consumers[consumer['component']].append(consumer['cp'])

                for consuming_comp_name, consuming_cps in consumers.iteritems():
                    if len(consuming_cps) > 1:
                        comp_data = components[comp_name]

                        # not defining any rules means allow any
                        if 'multi-consumers' not in comp_data:
                            continue

                        rules = comp_data['multi-consumers']

                        # We might be consumed by a component or a service, and the
                        # list might be for a component or a service
                        if consuming_comp_name in components:
                            consuming_service = components[consuming_comp_name]['service']
                        else:
                            consuming_service = consuming_comp_name

                        if ((rules['default'] == 'block' and consuming_service not in rules.get('allowed', [])) or
                                (rules['default'] == 'allow' and consuming_service in rules.get('blocked', []))):
                            msg = ("Component '%s' in control plane '%s' is "
                                   "consumed by more than one instance of '%s' "
                                   "from the following control planes:  %s" %
                                   (comp_name, cp_name, consuming_comp_name,
                                    str(consuming_cps).strip('[]')))
                            self.add_error(msg)

    def get_dependencies(self):
        return ['encryption-key',
                'internal-model-2.0',
                'cloud-cplite-2.0']
