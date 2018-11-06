#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# (c) Copyright 2018 SUSE LLC
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

import argparse
import os
import re
import yaml


class CLMModel(object):
    _ipv4regex = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

    def __init__(self, file_name=None, root=None):
        self._root = root
        if not file_name:
            return
        with open(file_name, "r") as f:
            if self._root:
                self._model = yaml.load(f)[self._root]
            else:
                self._model = yaml.load(f)

    def append_to_file(self, file_name):
        _dict = {self._root: self._model} if self._root else self._model
        with open(file_name, 'a+') as f:
            yaml.dump(_dict, f, default_flow_style=False)

    def obfuscate_values(self, old_str, new_str):
        CLMModel.replace_string_in_values(self._model, old_str, new_str)

    def obfuscate_keys(self, old_key, new_key):
        CLMModel.replace_keys(self._model, old_key, new_key)

    @property
    def model(self):
        return self._model

    @model.setter
    def model(self, value):
        self._model = value

    @property
    def root(self):
        return self._root

    @root.setter
    def root(self, value):
        self._root = value

    @staticmethod
    def replace_string_in_values(data_structure, old_str, new_str):
        if isinstance(data_structure, dict):
            for key, item in data_structure.items():
                if isinstance(item, dict) or isinstance(item, list):
                    CLMModel.replace_string_in_values(item, old_str, new_str)
                elif isinstance(item, str) and old_str in item:
                        data_structure[key] = new_str
        elif isinstance(data_structure, list):
            for item in data_structure:
                if isinstance(item, dict) or isinstance(item, list):
                    CLMModel.replace_string_in_values(item, old_str, new_str)
                elif isinstance(item, str) and old_str in item:
                    data_structure[data_structure.index(item)] = item.replace(
                        old_str, new_str)

    @staticmethod
    def replace_keys(data_structure, old_key, new_key):
        if isinstance(data_structure, dict):
            for key, item in data_structure.items():
                if isinstance(item, dict) or isinstance(item, list):
                    CLMModel.replace_keys(item, old_key, new_key)
                if isinstance(key, str) and old_key in key:
                    replace_key = key.replace(old_key, new_key)
                    data_structure[replace_key] = data_structure.pop(key)

    @staticmethod
    def replace_ipv4_func(ipv4):
        # TODO (spacefito): at some point this function should
        #                  probably return a more meaningful value
        #                  It would be great to use a class scope
        #                  dictionary to add ips into so the same
        #                  value maybe used to replace the ip everywhere
        return "X" * len(ipv4)

    @staticmethod
    def regex_replace_values(data_structure, regex_obj, replace_function):
        if isinstance(data_structure, dict):
            for key, item in data_structure.items():
                if isinstance(item, dict) or isinstance(item, list):
                    CLMModel.regex_replace_values(item, regex_obj,
                                                  replace_function)
                elif isinstance(item, bool):
                    pass
                else:
                    if isinstance(item, str):
                        m = regex_obj.match(item)
                        if m:
                            data_structure[key] = replace_function(item)

    @staticmethod
    def regex_replace_keys(data_structure, regex_obj, replace_function):
        if isinstance(data_structure, dict):
            for key, item in data_structure.items():
                if isinstance(item, dict) or isinstance(item, list):
                    CLMModel.regex_replace_keys(item, regex_obj,
                                                replace_function)
                if isinstance(key, str):
                    m = regex_obj.match(key)
                    if m:
                        data_structure[
                            replace_function(key)] = data_structure.pop(key)

    def obfuscate_ipv4_addresses(self):
        CLMModel.regex_replace_keys(self._model, self._ipv4regex,
                                    CLMModel.replace_ipv4_func)
        CLMModel.regex_replace_values(self._model, self._ipv4regex,
                                      CLMModel.replace_ipv4_func)

    def __str__(self):
        _dict = {self._root: self._model} if self._root else self._model
        return yaml.dump(_dict, default_flow_style=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--output',
                        help='output filename. output is redirected'
                             'to the specified file.'
                        )

    parser.add_argument('-b', '--obfuscate', action='store_true',
                        help='Obfuscate output. Removes ip addresses and '
                             'hostnames from output.'
                        )

    parser.add_argument('-at', '--all-topologies', action='store_true',
                        help="Include all topologies")

    parser.add_argument('-ct', '--control-plane-topology', action='store_true',
                        help='output control-plane topology')

    parser.add_argument('-rt', '--region-topology', action='store_true',
                        help='output region topology')

    parser.add_argument('-nt', '--network-topology', action='store_true',
                        help='output network topology ')

    parser.add_argument('-st', '--service-topology', action='store_true',
                        help='output service topology ')

    parser.add_argument('-sl', '--service-list', action='store_true',
                        help='List all services running in control-plane')

    parser.add_argument('-si', '--show-server-info', action='store_true',
                        help='show server information')

    default_dir = os.path.join(os.path.expanduser('~'), 'openstack',
                               'my_cloud', 'info')
    parser.add_argument('-d', '--source-directory',
                        help='path to directory where yml models are stored. '
                             'Default ~/openstack/my_cloud/info',
                        default=default_dir)

    parser.add_argument('--show-network', dest='network_name',
                        help='displays list of servers attached to the '
                             'given network along with their ip addresses.')

    parser.add_argument('--list-nics', action='store_true',
                        help='displays network cards by server. '
                             'server:nic_name')

    parser.add_argument('--debug', action='store_true',
                        help='debug flag for developing')

    args = parser.parse_args()

    # tuples for each model file to read in: (file_name, root_node)
    sub_model_list = [('control_plane_topology', 'control_planes'),
                      ('region_topology', 'regions'),
                      ('network_topology', 'network_groups'),
                      ('service_topology', 'services'),
                      ('server_info', None)]

    # for every model create a CLMModel object
    mdl = {k: CLMModel(
        os.path.join(args.source_directory, k + '.yml'), root)
        for (k, root) in sub_model_list} if not args.debug else {}

    output = {}

    if args.network_name:
        output[
            'show_network'] = 'show_network not implemented'
        raise NotImplementedError(output['show_network'])

    if args.list_nics:
        output['nic_list'] = CLMModel(root='nic_list')
        output['nic_list'].model = [
            ':'.join([server, nic])
            for server in mdl['server_info'].model
            for nic in mdl['server_info'].model[server]['net_data']
        ]

    if args.show_server_info:
        output['server_info'] = mdl['server_info']

    if args.control_plane_topology or args.all_topologies:
        output['control_plane_topology'] = mdl['control_plane_topology']

    if args.region_topology or args.all_topologies:
        output['region_topology'] = mdl['region_topology']

    if args.network_topology or args.all_topologies:
        output['network_topology'] = mdl['network_topology']

    if args.service_topology or args.all_topologies:
        output['service_topology'] = mdl['service_topology']

    if args.service_list:
        output['service_list'] = CLMModel(root='service_list')
        output['service_list'].model = mdl['service_topology'].model.keys()

    if args.obfuscate:

        # create a mapping of hostnames to simple server_names
        hm = {}
        regexp = re.compile('\A\w+-\w+-\w+')
        regexv = re.compile('\A\w+-\w+-')
        for server in mdl['server_info'].model:
            hostname = mdl['server_info'].model[server]['hostname']
            m = regexp.match(hostname)
            if m:
                hm[m.group(0)] = server
                v = regexv.match(m.group(0))
                if v:
                    vip_name = v.group(0) + 'vip'
                    hm[vip_name] = server + '-vip'

        # obfuscate hostnames
        for hostname in hm:
            for model in output.values():
                model.obfuscate_values(hostname, hm[hostname])
                model.obfuscate_keys(hostname, hm[hostname])

        # obfuscate ipv4 addresses
        for model in output.values():
            model.obfuscate_ipv4_addresses()

    for model in output.values():
        if args.output:
            model.append_to_file(args.output)
        else:
            print(model)


if __name__ == '__main__':
    main()
