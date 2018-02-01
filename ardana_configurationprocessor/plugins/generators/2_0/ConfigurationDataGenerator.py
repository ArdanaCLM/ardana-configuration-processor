# (c) Copyright 2015-2016 Hewlett Packard Enterprise Development LP
# (c) Copyright 2017-2018 SUSE LLC
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import logging
import logging.config

from copy import deepcopy

from ardana_configurationprocessor.cp.model.CPLogging import \
    CPLogging as KenLog
from ardana_configurationprocessor.cp.model.GeneratorPlugin \
    import GeneratorPlugin
from ardana_configurationprocessor.cp.model.v2_0.CloudModel \
    import CloudModel


LOG = logging.getLogger(__name__)


class ConfigurationDataGenerator(GeneratorPlugin):
    def __init__(self, instructions, models, controllers):
        super(ConfigurationDataGenerator, self).__init__(
            2.0, instructions, models, controllers,
            'configuration-data-generator-2.0')
        LOG.info('%s()' % KenLog.fcn())

    def generate(self):
        LOG.info('%s()' % KenLog.fcn())

        self._action = KenLog.fcn()
        cloud_version = CloudModel.version(
            self._models['CloudModel'], self._version)
        cloud_internal = CloudModel.internal(self._models['CloudModel'])

        services = CloudModel.get(cloud_internal, 'services', [])

        config_data = {}
        for data in CloudModel.get(cloud_version, 'configuration-data', []):
            config_data[data['name']] = data

        control_planes = CloudModel.get(cloud_internal, 'control-planes')

        for cp_name, cp in control_planes.iteritems():

            #  Get any config data at the CP level
            cp_config_data = self._expand_config(cp.get('configuration-data', []),
                                                 config_data, services)

            # Extract all of the network tags defined in
            # configuration data for this control plane
            cp['config-data-network-tags'] = self._get_network_tags(cp['name'],
                                                                    cp.get('configuration-data', []),
                                                                    config_data)

            # Extract the list of physnets that have been defined
            # in neutron configuration data for this control plane
            # so they can be validated in the NetworkTagGenerator
            cp['neutron-provider-nets'] = self._get_provider_nets(cp['name'],
                                                                  cp.get('configuration-data', []),
                                                                  config_data)

            for cluster in cp['clusters']:
                cluster_config_data = self._expand_config(cluster.get('configuration-data', []),
                                                          config_data, services)
                context = "%s:%s" % (cp_name, cluster['name'])
                cluster['config-data'] = self._merge(cp_config_data, cluster_config_data, context)

                self._check_no_network_tags(context, cluster.get('configuration-data', []), config_data)

            for r in cp.get('resources', []):
                r_config_data = self._expand_config(r.get('configuration-data', []),
                                                    config_data, services)
                context = "%s:%s" % (cp_name, r['name'])
                r['config-data'] = self._merge(cp_config_data, r_config_data, context)

                self._check_no_network_tags(context, r.get('configuration-data', []), config_data)

    #
    # Expand a list of config data names into a dict
    # keyed by the service name of each item in
    # the list.
    #
    # Take a copy of the data so that we can merge
    # without affection other users of the same
    # original data
    #
    def _expand_config(self, config_list, config_data, services):

        result = {}

        for name in config_list:
            data = config_data[name]
            for service in data.get('services', []):

                if service not in services:
                    continue

                if 'data' not in data:
                    continue

                mnemonic = services[service]['mnemonic']

                if mnemonic not in result:
                    if isinstance(data['data'], list):
                        result[mnemonic] = []
                    else:
                        result[mnemonic] = {}

                result[mnemonic] = self._merge(result[mnemonic], data['data'], name)

        return result

    #
    # Do a deep merge of b into a
    #
    def _merge(self, a, b, context):

        # Take a copy so we don't update the original object which
        # might be merged with some other object in another context
        result = deepcopy(a)

        if isinstance(result, dict):
            if isinstance(b, dict):
                for key in b:
                    if key in result:
                        context = "%s.%s" % (context, key)
                        result[key] = self._merge(result[key], b[key], context)
                    else:
                        result[key] = deepcopy(b[key])
            else:
                self.add_error("Type mismatch on merge: %s" % context)

        elif isinstance(result, list):
            if isinstance(b, list):
                result.extend(b)
            else:
                result.append(b)

        else:
            result = b

        return result

    #
    # Expand a set of network tags into a dict keyed by the network group
    #
    def _get_network_tags(self, cp_name, config_list, config_data):

        result = {}

        for config_name in config_list:
            context = "Control Plane '%s' Configuration Data '%s'" % (cp_name, config_name)
            data = config_data[config_name]

            if 'network-tags' in data and 'neutron' not in data['services']:
                msg = ("Invalid network-tags attribute in configuration-data '%s'. "
                       "Network tags can only be defined when neutron is in the list "
                       "of services." % (config_name))
                self.add_error(msg)
                continue

            for network_tag in data.get('network-tags', []):
                net_group = network_tag['network-group']
                if net_group not in result:
                    result[net_group] = []

                # Need to keep track of the context we found the tag in
                # for error reporting later
                result[net_group].append({'context': context,
                                          'tags': network_tag['tags']})
        return result

    #
    # Expand a set of network tags into a dict keyed by the network group
    #
    def _get_provider_nets(self, cp_name, config_list, config_data):

        result = []
        for config_name in config_list:
            data = config_data[config_name]
            result.extend(data.get('neutron-provider-nets', []))
        return result

    #
    # Check network tags not defined
    #
    def _check_no_network_tags(self, context, config_list, config_data):

        for config_name in config_list:
            data = config_data[config_name]

            if 'network-tags' in data:
                msg = ("Network tags in configuration data '%s' referenced from %s will "
                       "be ignored as these can only be defined at the control plane level." %
                       (config_name, context))
                self.add_warning(msg)

    def get_dependencies(self):
        return ['encryption-key',
                'internal-model-2.0']
