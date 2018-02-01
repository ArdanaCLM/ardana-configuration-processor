# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
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

from ardana_configurationprocessor.cp.model.CPLogging import \
    CPLogging as KenLog
from ardana_configurationprocessor.cp.model.GeneratorPlugin \
    import GeneratorPlugin
from ardana_configurationprocessor.cp.model.v2_0.CloudModel \
    import CloudModel


LOG = logging.getLogger(__name__)


class DpdkDeviceGenerator(GeneratorPlugin):
    def __init__(self, instructions, models, controllers):
        super(DpdkDeviceGenerator, self).__init__(
            2.0, instructions, models, controllers,
            'dpdk-device-generator-2.0')
        LOG.info('%s()' % KenLog.fcn())

    def generate(self):

        LOG.info('%s()' % KenLog.fcn())

        self._action = KenLog.fcn()
        self._valid = True

        cloud_internal = CloudModel.internal(self._models['CloudModel'])
        cloud_version = CloudModel.version(self._models['CloudModel'], self._version)

        servers = CloudModel.get(cloud_internal, 'servers', {})
        components = CloudModel.get(cloud_internal, 'components', {})

        interface_models = {}
        for model in CloudModel.get(cloud_version, 'interface-models', []):
            interface_models[model['name']] = model

        server_roles = {}
        for role in CloudModel.get(cloud_version, 'server-roles', []):
            server_roles[role['name']] = role

        for s in servers:
            if s['state'] != 'allocated':
                continue

            server_role = server_roles[s['role']]

            interface_model = interface_models[server_role['interface-model']]

            # Create a structure indexed by device name
            iface_devices = {}
            for iface, iface_data in s['interfaces'].iteritems():
                iface_devices[iface_data['device']['name']] = iface_data

            # Find out which devices we should configure based on the
            # components on this server
            server_dpdk_data = {}
            dpdk_devices = {}
            for dpdk_data in interface_model.get('dpdk-devices', []):

                # Build a list of the devices so we can check we match
                # each only once based on the components
                for device in dpdk_data['devices']:
                    if device['name'] not in dpdk_devices:
                        dpdk_devices[device['name']] = {'possible': [],
                                                        'matched': []}
                        if 'driver' in device:
                            dpdk_devices[device['name']]['driver'] = device['driver']

                for component in dpdk_data['components']:
                    for device in dpdk_data['devices']:
                        dpdk_devices[device['name']]['possible'].append(component)

                    if component in s['components']:
                        mnemonic = components[component]['mnemonic'].replace('-', '_')

                        # Anything other than devices is a server level attribute
                        if mnemonic not in server_dpdk_data:
                            server_dpdk_data[mnemonic] = {'devices': []}
                        for k in dpdk_data:
                            if k in ['components', 'devices']:
                                continue
                            server_dpdk_data[mnemonic][str(k).replace('-', '_')] = dpdk_data[k]

                        for device in dpdk_data['devices']:
                            dpdk_devices[device['name']]['matched'].append(component)

            # Check we have one component for each device
            for device_name, dpdk_data in dpdk_devices.iteritems():

                # Multiple dpdk devices can be grouped into a collection and there
                # are several dpdk applications that can use a dpdk collection.
                # The only dpdk collection currently understood is an Open vSwitch bond

                # Check to see if this device is part of a dpdk bond
                dpdk_collection = False
                for idev, idev_data in iface_devices.iteritems():
                    if 'bond-data' in idev_data:
                        for dpdk_dev in idev_data['bond-data']['devices']:
                            if dpdk_dev['name'] == device_name:
                                dpdk_collection = True
                                dpdk_collection_name = idev

                if device_name not in iface_devices and not dpdk_collection:

                    if len(dpdk_data['matched']) > 0:
                        msg = ("DPDK data for device '%s' has not been applied to "
                               "server '%s' (id: %s role: %s) because the device is "
                               "not used on the server although at least one of the "
                               "associated components is on the server: %s" %
                               (device_name, s['name'], s['id'], s['role'],
                                str(dpdk_data['matched']).strip('[]')))
                        self.add_warning(msg)

                else:

                    if len(dpdk_data['matched']) > 1:
                        msg = ("DPDK data for device '%s' on server '%s' (id: %s role: %s) "
                               "matches more than one component: %s." %
                               (device_name, s['name'], s['id'], s['role'],
                                str(dpdk_data['matched']).strip('[]')))
                        self.add_error(msg)
                        self._valid = False

                    elif len(dpdk_data['matched']) == 0:
                        msg = ("DPDK data for device '%s' has not been applied to "
                               "server '%s' (id: %s role: %s) because none of the "
                               "components are on the server: %s." %
                               (device_name, s['name'], s['id'], s['role'],
                                str(dpdk_data['possible']).strip('[]')))
                        self.add_warning(msg)

                    else:
                        check_name = dpdk_collection_name if dpdk_collection else device_name

                        # Check we're not trying to configure DPDK on the server's config
                        # interface
                        for net_name, net_data in iface_devices[check_name]['networks'].iteritems():
                            if 'addr' in net_data and net_data['addr'] == s['addr']:
                                msg = ("Device '%s' on server '%s' (id: %s role: %s) "
                                       "cannot be used for DPDK as it is also the "
                                       "interface used by the lifecycle manager." %
                                       (check_name, s['name'], s['id'], s['role']))
                                self.add_error(msg)
                                self._valid = False
                                break
                            else:
                                mnemonic = components[dpdk_data['matched'][0]]['mnemonic'].replace('-', '_')
                                iface_dpdk_data = {'component': mnemonic, 'composite': False}

                                if not dpdk_collection:
                                    if 'driver' in dpdk_data:
                                        iface_dpdk_data['driver'] = dpdk_data['driver']
                                else:
                                    # get the current data as it may already have devices
                                    iface_dpdk_data = iface_devices[check_name].get('dpdk-data', iface_dpdk_data)

                                    iface_dpdk_data['composite'] = True

                                    if 'devices' not in iface_dpdk_data:
                                        iface_dpdk_data['devices'] = []

                                    dev_data = {'name': device_name}
                                    if 'driver' in dpdk_data:
                                        dev_data['driver'] = dpdk_data['driver']

                                    iface_dpdk_data['devices'].append(dev_data)

                                iface_devices[check_name]['dpdk-data'] = iface_dpdk_data

            s['dpdk-data'] = server_dpdk_data

    def get_dependencies(self):
        return ['encryption-key',
                'internal-model-2.0',
                'cloud-cplite-2.0']
