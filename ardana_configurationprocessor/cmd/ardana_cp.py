#!/usr/bin/env python
#
# (c) Copyright 2015,2016 Hewlett Packard Enterprise Development LP
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

import getpass
import sys
import argparse

import ardana_configurationprocessor.cp.model.CPVariables as KenVar
from ardana_configurationprocessor.cp.model.CPSecurity \
    import CPSecurity
from ardana_configurationprocessor.cp.processor.ConfigurationProcessor \
    import ConfigurationProcessor

all_generators = ['encryption-key',
                  'internal-model-2.0',
                  'cloud-cplite-2.0',
                  'ring-specifications-2.0',
                  'firewall-generator-2.0',
                  'audit-generator-2.0',
                  'cert-generator-2.0',
                  'consumes-generator-2.0',
                  'provides-data-generator-2.0',
                  'advertises-generator-2.0',
                  'route-generator-2.0',
                  'network-generator-2.0',
                  'dpdk-device-generator-2.0',
                  'deleted-component-generator-2.0',
                  'configuration-data-generator-2.0',
                  'network-tag-generator-2.0',
                  'memory-model-generator-2.0',
                  'topology-generator-2.0',
                  'cpu-assignment-generator-2.0',
                  'vm-factory-2.0'
                  ]

all_validators = ['encryption-key',
                  'cloudconfig-2.0',
                  'services-2.0',
                  'service-components-2.0',
                  'disk-model-2.0',
                  'memory-model-2.0',
                  'cpu-model-2.0',
                  'interface-models-2.0',
                  'network-groups-2.0',
                  'networks-2.0',
                  'server-roles-2.0',
                  'server-groups-2.0',
                  'servers-2.0',
                  'control-planes-2.0',
                  'regions-2.0',
                  'nic-mappings-2.0',
                  'nic-device-types-2.0',
                  'nic-device-families-2.0',
                  'pass-through-2.0',
                  'ring-specifications-2.0',
                  'cross-reference-2.0',
                  'firewall-rules-2.0',
                  'deployer-network-lifecycle-mgr-2.0',
                  'config-data-2.0',
                  'load-balancer-2.0',
                  'vm-factory-2.0'
                  ]

all_builders = ['ans-encr-artifacts',
                'hosts-file-2.0',
                'ansible-hosts-2.0',
                'ansible-all-vars-2.0',
                'ans-host-vars-2.0',
                'ans-group-vars-2.0',
                'net-info-2.0',
                'route-info-2.0',
                'server-info-2.0',
                'firewall-info-2.0',
                'topology-info-2.0',
                'cert-req-2.0',
                'diagram-2.0',
                'persistent-state-2.0',
                'html-diagram-2.0',
                'private-data-meta-data-2.0'
                ]

all_checkpointers = ['desired-state',
                     'config',
                     'persistent-state'
                     ]

all_explainers = ['cloud-structure',
                  'services',
                  'network-traffic-groups',
                  'servers',
                  'servers-2.0',
                  'override-vars',
                  'override-blocks'
                  ]

all_migrators = ['service-name-to-mnemonic-2.0',
                 'resource-nodes-to-resources-2.0',
                 'component-list-expansion-2.0',
                 'swift-rings-2.0'
                 ]

all_finalizers = ['cloud-model-2.0',
                  'service-view-2.0',
                  'address-allocation-2.0'
                  ]


allowed_input_formats = ['json', 'yaml', 'yml']


def print_about():
    print('Process Name: Ardana Configuration Processor')
    print('Driver: %s' % sys.argv[0])
    print('Version: %s' % str(KenVar.MODEL_VERSION))


def _get_options():
    parser = argparse.ArgumentParser(
        description='Ardana Configuration Processor')
    parser.add_argument("-a", "--ansible_input", dest="ansible_input_path",
                        help="The location of the ansible input data files")
    parser.add_argument("-i", "--icinga_input", dest="icinga_input_path",
                        help="The location of the icinga input data files")
    parser.add_argument("-s", "--site_input", dest="site_input_path",
                        help="The location of the site-level input data files")
    parser.add_argument("-r", "--validator", dest="cloud_schema_path",
                        help="The location of the schema files. Defaults to "
                        "site_input_path and fallbacks to the data/ dir "
                        "delivered via the ardana_configurationprocessor python"
                        " module")
    parser.add_argument("-c", "--cloud_config", dest="cloud_input_path",
                        help="The location of the cloud config input file.")
    parser.add_argument("-e", "--encryption", dest="encryption",
                        action="store_true", help="Run with encryption",
                        default=False)
    parser.add_argument("-k", "--encryption_key_change",
                        dest="encryption_key_change",
                        action="store_true", help="Run with encryption and "
                        "change the old encryption key", default=False)
    parser.add_argument("-x", "--encryption_key", dest="encryption_key_input",
                        help="Encryption key.")
    parser.add_argument("-y", "--old_encryption_key",
                        dest="old_encryption_key_input",
                        help="Old encryption key if rekeying.")
    parser.add_argument("-C", "--checkpoint", dest="checkpoint_name",
                        help="Run the checkpoint command")
    parser.add_argument("-o", "--_output_path",
                        dest="output_path",
                        help="The location of the output files",
                        default="./clouds")
    parser.add_argument("-d", "--remove_deleted_servers",
                        dest="remove_deleted_servers", action="store_true",
                        help="Remove deleted servers from persistent state",
                        default=False)
    parser.add_argument("-f", "--free_unused_addresses",
                        dest="free_unused_addresses",
                        action="store_true", help="Free-up unused ip addresses",
                        default=False)
    parser.add_argument("-l", "--log_dir",
                        dest="log_dir",
                        help="The location of the log files",
                        default="/var/log/ardana/configuration_processor")
    parser.set_defaults(local=False)
    parser.add_argument("-w", "--write_local",
                        action="store_true",
                        dest="local",
                        help="Write output at this level of dir hierarchy")
    parser.add_argument("-p", "--refresh_all_secrets",
                        dest="refresh_all_secrets",
                        action="store_true",
                        help="Force a refresh of all secrets", default=False)
    parser.add_argument("-P", "--credential_change",
                        dest="credential_change_path",
                        help="The location of the credential_change directory.",
                        default=None)
    parser.add_argument("-q", "--quiet", dest="quiet",
                        action="store_true",
                        help="Run without prompting for input", default=False)
    parser.add_argument("-n", "--service_names", dest="use_service_names",
                        action="store_true",
                        help="Store output artifacts using service names "
                        "instead of service mnemonics")
    parser.add_argument("-L", "--lowercase-hostnames",
                        dest="lowercase_hostnames", action="store_true",
                        help="Store output artifacts using lowercase host names"
                        " instead of uppercase host names")
    parser.add_argument("-U", "--uppercase-hostnames",
                        dest="uppercase_hostnames", action="store_true",
                        help="Store output artifacts using uppercase host names"
                        " instead of lowercase host names")
    parser.add_argument("-m", "--store-internal-model",
                        dest="store_internal_model", action="store_true",
                        help="Store the internal models", default=False)
    parser.add_argument("-V", "--verbose", dest="verbose", action="store_true",
                        help="Run in verbose mode", default=False)
    parser.add_argument("-A", "--about", dest="about", action="store_true",
                        help="Print information about the Configuration "
                        "Processor client", default=False)

    args = parser.parse_args()

    if args.about:
        print_about()
        sys.exit(0)

    if not args.site_input_path:
        parser.error("Site Input Path (-s) is required")

    if not args.cloud_input_path:
        parser.error("Cloud Config Input Path (-c) is required")

    if not args.cloud_schema_path:
        args.cloud_schema_path = args.site_input_path

    input_format = args.cloud_input_path.split('.')
    if input_format[-1] not in allowed_input_formats:
        parser.error("Cloud Config Input Path (-c) must point to a "
                     "file of type %s (e.g., cloudConfig.json)" % ', '.join(
                         allowed_input_formats))

    if not args.ansible_input_path:
        args.ansible_input_path = None

    if not args.icinga_input_path:
        args.icinga_input_path = None

    user_instructions = dict()
    user_instructions['model_version'] = '%03.1f' % KenVar.MODEL_VERSION

    user_instructions['run_validate'] = True
    user_instructions['run_build'] = True

    if args.checkpoint_name:
        user_instructions['run_checkpoint'] = True
        user_instructions['checkpoint_name'] = args.checkpoint_name
    else:
        user_instructions['run_checkpoint'] = False
        user_instructions['checkpoint_name'] = None

    user_instructions['generators'] = all_generators
    user_instructions['builders'] = all_builders
    user_instructions['explainers'] = all_explainers
    user_instructions['migrators'] = all_migrators
    user_instructions['validators'] = all_validators
    user_instructions['checkpointers'] = all_checkpointers
    user_instructions['finalizers'] = all_finalizers

    user_instructions['ansible_input_path'] = args.ansible_input_path
    user_instructions['icinga_input_path'] = args.icinga_input_path
    user_instructions['cloud_input_path'] = args.cloud_input_path
    user_instructions['site_input_path'] = args.site_input_path
    user_instructions['cloud_schema_path'] = args.cloud_schema_path
    user_instructions[
        'site_config_path'] = args.cloud_schema_path + '/../Config'
    user_instructions['output_path'] = args.output_path
    user_instructions['log_dir'] = args.log_dir
    user_instructions['json_builder'] = dict()

    user_instructions['refresh_all_secrets'] = args.refresh_all_secrets
    user_instructions['store_internal_model'] = args.store_internal_model
    user_instructions['verbose'] = args.verbose
    user_instructions['clean'] = True
    user_instructions['quiet'] = args.quiet
    user_instructions['remove_deleted_servers'] = args.remove_deleted_servers
    user_instructions['free_unused_addresses'] = args.free_unused_addresses
    user_instructions['credential_change_path'] = args.credential_change_path

    if args.encryption_key_input:
        user_instructions['encryption_key_input'] = \
            args.encryption_key_input
    if args.old_encryption_key_input:
        user_instructions['old_encryption_key_input'] = \
            args.old_encryption_key_input

    if not args.local:
        user_instructions['cloud_output_path'] = \
            '%s/@CLOUD_NAME@/@CLOUD_VERSION@/stage' % args.output_path
        user_instructions['network_output_path'] = \
            '%s/@CLOUD_NAME@/@CLOUD_VERSION@/stage/net' % args.output_path
        user_instructions['cloud_checkpoint_path'] = \
            '%s/@CLOUD_NAME@/@CLOUD_VERSION@/checkpoint' % args.output_path
        user_instructions['persistent_state'] = \
            '%s/@CLOUD_NAME@/@CLOUD_VERSION@/persistent_state/' % args.output_path
    else:
        user_instructions['cloud_output_path'] = './stage'
        user_instructions['network_output_path'] = './stage/net'
        user_instructions['cloud_checkpoint_path'] = './checkpoint'
        user_instructions['persistent_state'] = './persistent_state/'

    user_instructions['global_output_path'] = \
        '/var/lib/ardana/configuration_processor'

    user_instructions['hostsfile_builder'] = dict()
    user_instructions['hostsfile_builder']['filename'] = 'hosts.hf'

    user_instructions['interfaces_builder'] = dict()
    user_instructions['interfaces_builder']['dirname'] = 'intf'

    if args.use_service_names:
        user_instructions['use_service_names'] = True

    user_instructions['uppercase_hostnames'] = True
    if args.lowercase_hostnames:
        user_instructions['uppercase_hostnames'] = False

    if args.encryption_key_change:
        args.encryption = True
        print('')
        user_instructions['previous_encryption_key'] = \
            user_instructions['previous_encryption_key'] = \
            CPSecurity.make_key(
                getpass.getpass(
                    'Enter the PREVIOUS key that was used for: '
                    'encryption: ')
                if not user_instructions['quiet'] else
                user_instructions['old_encryption_key_input'])

    if args.encryption:
        print('')
        if args.encryption_key_change:
            key_type = 'NEW'
        else:
            key_type = 'current'

        user_instructions['encryption_key'] = \
            user_instructions['encryption_key'] = \
            CPSecurity.make_key(
                getpass.getpass(
                    'Enter the %s key to be used for encryption: ' % key_type)
                if not user_instructions['quiet'] else
                user_instructions['encryption_key_input'])

    return user_instructions


def has_errors(ardana_cp):
    return len(ardana_cp.errors) > 0


def print_errors(ardana_cp):
    print('')
    print('#' * 80)
    print("# The configuration processor failed.  ")
    for w in ardana_cp.warnings:
        print(w)
    for e in ardana_cp.errors:
        print(e)
    print('#' * 80)


def print_warnings_or_success(ardana_cp, return_value):
    if len(ardana_cp.warnings) > 0:
        print('')
        print('#' * 80)
        print("# The configuration processor completed with warnings.")
        for w in ardana_cp.warnings:
            print(w)
        print('#' * 80)
    else:
        if return_value == 0:
            print('')
            print('#' * 80)
            print("# The configuration processor completed successfully.")
            print('#' * 80)
        else:
            print('')
            print('#' * 80)
            print("# The configuration processor failed.")
            print('#' * 80)


def main():
    instructions = _get_options()

    ardana_cp = ConfigurationProcessor(instructions)

    return_value = 0

    status = ardana_cp.process_input()
    if not status:
        print_errors(ardana_cp)
        sys.exit(-1)

    status = ardana_cp.validate()
    if not status:
        print_errors(ardana_cp)
        sys.exit(-2)

    status = ardana_cp.create_models()
    if not status:
        print_errors(ardana_cp)
        sys.exit(-3)

    status = ardana_cp.create_controllers()
    if not status:
        print_errors(ardana_cp)
        sys.exit(-4)

    status = ardana_cp.read_persistent_state_creds_change()
    if not status:
        print_errors(ardana_cp)
        sys.exit(-5)

    status = ardana_cp.clean_up_stage()
    if not status:
        print_errors(ardana_cp)
        sys.exit(-6)

    if not instructions['run_checkpoint']:
        status = ardana_cp.migrate()
        if not status:
            return_value = -7

        if return_value == 0:
            status = ardana_cp.generate()
            if not status:
                return_value = -8

        if return_value == 0:
            status = ardana_cp.build()
            if not status:
                return_value = -9

        if return_value == 0:
            status = ardana_cp.explain()
            if not status:
                return_value = -10

        status = ardana_cp.finalize()
        if not status:
            return_value = -11

    if instructions['run_checkpoint']:
        status = ardana_cp.checkpoint()
        if not status:
            print_errors(ardana_cp)
            sys.exit(-12)

    if has_errors(ardana_cp):
        print_errors(ardana_cp)
    else:
        print_warnings_or_success(ardana_cp, return_value)

    sys.exit(return_value)


if __name__ == "__main__":
    main()
