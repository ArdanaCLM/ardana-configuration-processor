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
from setuptools import setup, find_packages

setup(
    name='ardana-configurationprocessor',
    version='0.4.0',
    author='SUSE LLC',
    author_email='ardana@googlegroups.com',
    packages=find_packages(),
    include_package_data=True,
    scripts=[],
    url='https://github.com/ArdanaCLM',
    license='Apache-2.0',
    description='Configuration Processor for Ardana CLM',
    long_description=open('README.txt').read(),
    install_requires=['six', 'stevedore', 'netaddr', 'pycryptodome',
                      'cryptography', 'simplejson', 'jsonschema', 'html',
                      'PyYAML', 'pbs' if os.name == 'nt' else 'sh'],
    zip_safe=False,
    entry_points={
        'console_scripts': [
            'ardana-cp = ardana_configurationprocessor.cmd.ardana_cp:main',
            'ardana-cp-decrypt = ' \
            'ardana_configurationprocessor.cmd.ardana_cp_decrypt.py:main',
            # ardana-dv.py for backwards compat
            'ardana-dv.py = ' \
            'ardana_configurationprocessor.cmd.ardana_cp_decrypt.py:main',
            'ardana-cp-passwordchecker = ' \
            'ardana_configurationprocessor.cmd.ardana_cp_passwordchecker:main',
            # ardana-pc.py for backwards compat
            'ardana-pc.py = ' \
            'ardana_configurationprocessor.cmd.ardana_cp_passwordchecker:main',
        ],
        'ardana.configurationprocessor.generator': [
            'cloud-init = '
            'ardana_configurationprocessor.plugins.generators.'
            'CloudGenerator:CloudGenerator',

            'machine-init = '
            'ardana_configurationprocessor.plugins.generators.'
            'MachineGenerator:MachineGenerator',

            'network-init = '
            'ardana_configurationprocessor.plugins.generators.'
            'NetworkGenerator:NetworkGenerator',

            'cfg-vars = '
            'ardana_configurationprocessor.plugins.generators.'
            'CfgVarsGenerator:CfgVarsGenerator',

            'control-plane-init = '
            'ardana_configurationprocessor.plugins.generators.'
            'ControlPlaneGenerator:ControlPlaneGenerator',

            'member-init = '
            'ardana_configurationprocessor.plugins.generators.'
            'MemberGenerator:MemberGenerator',

            'resource-node-init = '
            'ardana_configurationprocessor.plugins.generators.'
            'ResourceNodeGenerator:ResourceNodeGenerator',

            'service-init = '
            'ardana_configurationprocessor.plugins.generators.'
            'ServiceGenerator:ServiceGenerator',

            'network-ref-init = '
            'ardana_configurationprocessor.plugins.generators.'
            'NetworkRefGenerator:NetworkRefGenerator',

            'network-topology-init = '
            'ardana_configurationprocessor.plugins.generators.'
            'NetworkTopologyGenerator:NetworkTopologyGenerator',

            'node-init = '
            'ardana_configurationprocessor.plugins.generators.'
            'NodeGenerator:NodeGenerator',

            'baremetal-init = '
            'ardana_configurationprocessor.plugins.generators.'
            'BaremetalGenerator:BaremetalGenerator',

            'server-init = '
            'ardana_configurationprocessor.plugins.generators.'
            'ServerGenerator:ServerGenerator',

            'server-allocation = '
            'ardana_configurationprocessor.plugins.generators.'
            'ServerAllocationGenerator:ServerAllocationGenerator',

            'environment-init = '
            'ardana_configurationprocessor.plugins.generators.'
            'EnvironmentGenerator:EnvironmentGenerator',

            'external-services = '
            'ardana_configurationprocessor.plugins.generators.'
            'ExternalServicesGenerator:ExternalServicesGenerator',

            'encryption-key = '
            'ardana_configurationprocessor.plugins.generators.'
            'EncryptionKeyGenerator:EncryptionKeyGenerator',

            'node-type = '
            'ardana_configurationprocessor.plugins.generators.'
            'NodeTypeGenerator:NodeTypeGenerator',

            'service-var-overrides = '
            'ardana_configurationprocessor.plugins.generators.'
            'ServiceVarOverridesGenerator:ServiceVarOverridesGenerator',

            'network-repo-address = '
            'ardana_configurationprocessor.plugins.generators.'
            'NetworkRepoAddressGenerator:NetworkRepoAddressGenerator',

            'failure-zone-1.0 = '
            'ardana_configurationprocessor.plugins.generators.'
            'FailureZoneGenerator:FailureZoneGenerator',

            'internal-model-2.0 = '
            'ardana_configurationprocessor.plugins.generators.2_0.'
            'InternalModelGenerator:InternalModelGenerator',

            'cloud-cplite-2.0 = '
            'ardana_configurationprocessor.plugins.generators.2_0.'
            'CloudCpLiteGenerator:CloudCpLiteGenerator',

            'consumes-generator-2.0 = '
            'ardana_configurationprocessor.plugins.generators.2_0.'
            'ConsumesGenerator:ConsumesGenerator',

            'provides-data-generator-2.0 = '
            'ardana_configurationprocessor.plugins.generators.2_0.'
            'ProvidesDataGenerator:ProvidesDataGenerator',

            'advertises-generator-2.0 = '
            'ardana_configurationprocessor.plugins.generators.2_0.'
            'AdvertisesGenerator:AdvertisesGenerator',

            'memory-model-generator-2.0 = '
            'ardana_configurationprocessor.plugins.generators.2_0.'
            'MemoryModelGenerator:MemoryModelGenerator',

            'route-generator-2.0 = '
            'ardana_configurationprocessor.plugins.generators.2_0.'
            'RouteGenerator:RouteGenerator',

            'ring-specifications-2.0 = '
            'ardana_configurationprocessor.plugins.generators.2_0.'
            'RingSpecificationsGenerator:RingSpecificationsGenerator',

            'firewall-generator-2.0 = '
            'ardana_configurationprocessor.plugins.generators.2_0.'
            'FirewallGenerator:FirewallGenerator',

            'audit-generator-2.0 = '
            'ardana_configurationprocessor.plugins.generators.2_0.'
            'AuditGenerator:AuditGenerator',

            'cert-generator-2.0 = '
            'ardana_configurationprocessor.plugins.generators.2_0.'
            'CertGenerator:CertGenerator',

            'network-generator-2.0 = '
            'ardana_configurationprocessor.plugins.generators.2_0.'
            'NetworkGenerator:NetworkGenerator',

            'dpdk-device-generator-2.0 = '
            'ardana_configurationprocessor.plugins.generators.2_0.'
            'DpdkDeviceGenerator:DpdkDeviceGenerator',

            'deleted-component-generator-2.0 = '
            'ardana_configurationprocessor.plugins.generators.2_0.'
            'DeletedComponentGenerator:DeletedComponentGenerator',

            'configuration-data-generator-2.0 = '
            'ardana_configurationprocessor.plugins.generators.2_0.'
            'ConfigurationDataGenerator:ConfigurationDataGenerator',

            'network-tag-generator-2.0 = '
            'ardana_configurationprocessor.plugins.generators.2_0.'
            'NetworkTagGenerator:NetworkTagGenerator',

            'topology-generator-2.0 = '
            'ardana_configurationprocessor.plugins.generators.2_0.'
            'TopologyGenerator:TopologyGenerator',

            'cpu-assignment-generator-2.0 = '
            'ardana_configurationprocessor.plugins.generators.2_0.'
            'CpuAssignmentGenerator:CpuAssignmentGenerator',

            'vm-factory-2.0 = '
            'ardana_configurationprocessor.plugins.generators.2_0.'
            'VMFactoryGenerator:VMFactoryGenerator'
        ],

        'ardana.configurationprocessor.builder': [
            'ans-all-vars = '
            'ardana_configurationprocessor.plugins.builders.'
            'Ansible.AnsAllVarsBuilder:AnsAllVarsBuilder',

            'ans-group-vars = '
            'ardana_configurationprocessor.plugins.builders.'
            'Ansible.AnsGroupVarsBuilder:AnsGroupVarsBuilder',

            'ans-host-vars = '
            'ardana_configurationprocessor.plugins.builders.'
            'Ansible.AnsHostVarsBuilder:AnsHostVarsBuilder',

            'ans-hosts = '
            'ardana_configurationprocessor.plugins.builders.'
            'Ansible.AnsHostsBuilder:AnsHostsBuilder',

            'ans-config = '
            'ardana_configurationprocessor.plugins.builders.'
            'Ansible.AnsConfigBuilder:AnsConfigBuilder',

            'ans-verb-hosts = '
            'ardana_configurationprocessor.plugins.builders.'
            'Ansible.AnsVerbHostsBuilder:AnsVerbHostsBuilder',

            'ans-encr-artifacts = '
            'ardana_configurationprocessor.plugins.builders.'
            'Ansible.AnsEncryptArtifactsBuilder:AnsEncryptArtifactsBuilder',

            'ans-tlpb-commit = '
            'ardana_configurationprocessor.plugins.builders.'
            'Ansible.TopLevelPlaybooks.'
            'AnsCommitBuilder:AnsCommitBuilder',

            'ans-tlpb-verb = '
            'ardana_configurationprocessor.plugins.builders.'
            'Ansible.TopLevelPlaybooks.'
            'AnsVerbBuilder:AnsVerbBuilder',

            'ans-tlpb-action = '
            'ardana_configurationprocessor.plugins.builders.'
            'Ansible.TopLevelPlaybooks.'
            'AnsActionBuilder:AnsActionBuilder',

            'ans-carrier-grade-verb-1.0 = '
            'ardana_configurationprocessor.plugins.builders.'
            'Ansible.TopLevelPlaybooks.'
            'AnsCarrierGradeVerbBuilder:AnsCarrierGradeVerbBuilder',

            'diagram = '
            'ardana_configurationprocessor.plugins.builders.'
            'Diagram.DiagramBuilder:DiagramBuilder',

            'hosts-file = '
            'ardana_configurationprocessor.plugins.builders.'
            'Network.HostsFileBuilder:HostsFileBuilder',

            'interfaces = '
            'ardana_configurationprocessor.plugins.builders.'
            'Network.InterfacesBuilder:InterfacesBuilder',

            'pci-bus-enumeration = '
            'ardana_configurationprocessor.plugins.builders.'
            'Network.PciBusEnumerationBuilder:PciBusEnumerationBuilder',

            'ic2-zone-hosts = '
            'ardana_configurationprocessor.plugins.builders.'
            'Icinga.Ic2ZoneHostsBuilder:Ic2ZoneHostsBuilder',

            'ic2-zone-services = '
            'ardana_configurationprocessor.plugins.builders.'
            'Icinga.Ic2ZoneServicesBuilder:Ic2ZoneServicesBuilder',

            'ic2-zone-templates = '
            'ardana_configurationprocessor.plugins.builders.'
            'Icinga.Ic2ZoneTemplatesBuilder:Ic2ZoneTemplatesBuilder',

            'fs-prep = '
            'ardana_configurationprocessor.plugins.builders.'
            'Internal.FileSystemPrepBuilder:FileSystemPrepBuilder',

            'server-addresses = '
            'ardana_configurationprocessor.plugins.builders.'
            'ServerAddressesBuilder:ServerAddressesBuilder',

            'service-block-overrides = '
            'ardana_configurationprocessor.plugins.builders.'
            'ServiceBlockOverridesBuilder:ServiceBlockOverridesBuilder',

            'wr-config-1.0 = '
            'ardana_configurationprocessor.plugins.builders.'
            'WindRiver.WRConfigBuilder:WRConfigBuilder',

            'hosts-file-2.0 = '
            'ardana_configurationprocessor.plugins.builders.2_0.'
            'HostsFileBuilder:HostsFileBuilder',

            'ansible-hosts-2.0 = '
            'ardana_configurationprocessor.plugins.builders.2_0.'
            'AnsibleHostsBuilder:AnsibleHostsBuilder',

            'ansible-all-vars-2.0 = '
            'ardana_configurationprocessor.plugins.builders.2_0.'
            'AnsibleAllVarsBuilder:AnsibleAllVarsBuilder',

            'ans-host-vars-2.0 = '
            'ardana_configurationprocessor.plugins.builders.2_0.'
            'AnsHostVarsBuilder:AnsHostVarsBuilder',

            'ans-group-vars-2.0 = '
            'ardana_configurationprocessor.plugins.builders.2_0.'
            'AnsGroupVarsBuilder:AnsGroupVarsBuilder',

            'net-info-2.0 = '
            'ardana_configurationprocessor.plugins.builders.2_0.'
            'NetworkInfoBuilder:NetworkInfoBuilder',

            'route-info-2.0 = '
            'ardana_configurationprocessor.plugins.builders.2_0.'
            'RouteInfoBuilder:RouteInfoBuilder',

            'server-info-2.0 = '
            'ardana_configurationprocessor.plugins.builders.2_0.'
            'ServerInfoBuilder:ServerInfoBuilder',

            'firewall-info-2.0 = '
            'ardana_configurationprocessor.plugins.builders.2_0.'
            'FirewallInfoBuilder:FirewallInfoBuilder',

            'topology-info-2.0 = '
            'ardana_configurationprocessor.plugins.builders.2_0.'
            'TopologyInfoBuilder:TopologyInfoBuilder',

            'cert-req-2.0 = '
            'ardana_configurationprocessor.plugins.builders.2_0.'
            'CertReqBuilder:CertReqBuilder',

            'diagram-2.0 = '
            'ardana_configurationprocessor.plugins.builders.2_0.'
            'DiagramBuilder:DiagramBuilder',

            'persistent-state-2.0 = '
            'ardana_configurationprocessor.plugins.builders.2_0.'
            'PersistentStateBuilder:PersistentStateBuilder',

            'html-diagram-2.0 = '
            'ardana_configurationprocessor.plugins.builders.2_0.'
            'HTMLDiagramBuilder:HTMLDiagramBuilder',

            'private-data-meta-data-2.0 = '
            'ardana_configurationprocessor.plugins.builders.2_0.'
            'PrivateDataMetaDataBuilder:PrivateDataMetaDataBuilder'
        ],

        'ardana.configurationprocessor.validator': [
            'cloudarch = '
            'ardana_configurationprocessor.plugins.validators.'
            'CloudArchitectureValidator:CloudArchitectureValidator',

            'cloudconfig = '
            'ardana_configurationprocessor.plugins.validators.'
            'CloudConfigValidator:CloudConfigValidator',

            'controlplane = '
            'ardana_configurationprocessor.plugins.validators.'
            'ControlPlaneValidator:ControlPlaneValidator',

            'environmentconfig = '
            'ardana_configurationprocessor.plugins.validators.'
            'EnvironmentConfigValidator:EnvironmentConfigValidator',

            'machine-architecture = '
            'ardana_configurationprocessor.plugins.validators.'
            'MachineArchitectureValidator:MachineArchitectureValidator',

            'networkconfig = '
            'ardana_configurationprocessor.plugins.validators.'
            'NetworkConfigValidator:NetworkConfigValidator',

            'baremetalconfig = '
            'ardana_configurationprocessor.plugins.validators.'
            'BaremetalConfigValidator:BaremetalConfigValidator',

            'serverconfig = '
            'ardana_configurationprocessor.plugins.validators.'
            'ServerConfigValidator:ServerConfigValidator',

            'icinga = '
            'ardana_configurationprocessor.plugins.validators.'
            'IcingaValidator:IcingaValidator',

            'ansible = '
            'ardana_configurationprocessor.plugins.validators.'
            'AnsibleValidator:AnsibleValidator',

            'logical-network = '
            'ardana_configurationprocessor.plugins.validators.'
            'LogicalNetworkValidator:LogicalNetworkValidator',

            'encryption-key = '
            'ardana_configurationprocessor.plugins.validators.'
            'EncryptionKeyValidator:EncryptionKeyValidator',

            'fs-prep = '
            'ardana_configurationprocessor.plugins.validators.'
            'FileSystemPrepValidator:FileSystemPrepValidator',

            'node-type = '
            'ardana_configurationprocessor.plugins.validators.'
            'NodeTypeValidator:NodeTypeValidator',

            'disk-model-2.0 = '
            'ardana_configurationprocessor.plugins.validators.2_0.'
            'DiskModelValidator:DiskModelValidator',

            'memory-model-2.0 = '
            'ardana_configurationprocessor.plugins.validators.2_0.'
            'MemoryModelValidator:MemoryModelValidator',

            'cpu-model-2.0 = '
            'ardana_configurationprocessor.plugins.validators.2_0.'
            'CpuModelValidator:CpuModelValidator',

            'cloudconfig-2.0 = '
            'ardana_configurationprocessor.plugins.validators.2_0.'
            'CloudConfigValidator:CloudConfigValidator',

            'services-2.0 = '
            'ardana_configurationprocessor.plugins.validators.2_0.'
            'ServiceValidator:ServiceValidator',

            'service-components-2.0 = '
            'ardana_configurationprocessor.plugins.validators.2_0.'
            'ServiceComponentValidator:ServiceComponentValidator',

            'interface-models-2.0 = '
            'ardana_configurationprocessor.plugins.validators.2_0.'
            'InterfaceModelsValidator:InterfaceModelsValidator',

            'network-groups-2.0 = '
            'ardana_configurationprocessor.plugins.validators.2_0.'
            'NetworkGroupsValidator:NetworkGroupsValidator',

            'networks-2.0 = '
            'ardana_configurationprocessor.plugins.validators.2_0.'
            'NetworksValidator:NetworksValidator',

            'server-roles-2.0 = '
            'ardana_configurationprocessor.plugins.validators.2_0.'
            'ServerRolesValidator:ServerRolesValidator',

            'server-groups-2.0 = '
            'ardana_configurationprocessor.plugins.validators.2_0.'
            'ServerGroupsValidator:ServerGroupsValidator',

            'servers-2.0 = '
            'ardana_configurationprocessor.plugins.validators.2_0.'
            'ServersValidator:ServersValidator',

            'control-planes-2.0 = '
            'ardana_configurationprocessor.plugins.validators.2_0.'
            'ControlPlanesValidator:ControlPlanesValidator',

            'regions-2.0 = '
            'ardana_configurationprocessor.plugins.validators.2_0.'
            'RegionsValidator:RegionsValidator',

            'nic-mappings-2.0 = '
            'ardana_configurationprocessor.plugins.validators.2_0.'
            'NicMappingsValidator:NicMappingsValidator',

            'nic-device-types-2.0 = '
            'ardana_configurationprocessor.plugins.validators.2_0.'
            'NicDeviceTypesValidator:NicDeviceTypesValidator',

            'nic-device-families-2.0 = '
            'ardana_configurationprocessor.plugins.validators.2_0.'
            'NicDeviceFamiliesValidator:NicDeviceFamiliesValidator',

            'pass-through-2.0 = '
            'ardana_configurationprocessor.plugins.validators.2_0.'
            'PassThroughValidator:PassThroughValidator',

            'ring-specifications-2.0 = '
            'ardana_configurationprocessor.plugins.validators.2_0.'
            'RingSpecificationsValidator:RingSpecificationsValidator',

            'firewall-rules-2.0 = '
            'ardana_configurationprocessor.plugins.validators.2_0.'
            'FirewallRulesValidator:FirewallRulesValidator',

            'cross-reference-2.0 = '
            'ardana_configurationprocessor.plugins.validators.2_0.'
            'CrossReferenceValidator:CrossReferenceValidator',

            'deployer-network-lifecycle-mgr-2.0 = '
            'ardana_configurationprocessor.plugins.validators.2_0.'
            'DeployerNetworkLifecycleMgrValidator:DeployerNetworkLifecycleMgrValidator',

            'config-data-2.0 = '
            'ardana_configurationprocessor.plugins.validators.2_0.'
            'ConfigDataValidator:ConfigDataValidator',

            'load-balancer-2.0 = '
            'ardana_configurationprocessor.plugins.validators.2_0.'
            'LoadBalancerValidator:LoadBalancerValidator',

            'vm-factory-2.0 = '
            'ardana_configurationprocessor.plugins.validators.2_0.'
            'VMFactoryValidator:VMFactoryValidator'
        ],

        'ardana.configurationprocessor.variable': [
            'control-plane-id = '
            'ardana_configurationprocessor.plugins.variables.'
            'ControlPlaneIdVariable:ControlPlaneIdVariable',

            'control-plane-prefix = '
            'ardana_configurationprocessor.plugins.variables.'
            'ControlPlanePrefixVariable:ControlPlanePrefixVariable',

            'failure-zone = '
            'ardana_configurationprocessor.plugins.variables.'
            'FailureZoneVariable:FailureZoneVariable',

            'host-address = '
            'ardana_configurationprocessor.plugins.variables.'
            'HostAddressVariable:HostAddressVariable',

            'host-name = '
            'ardana_configurationprocessor.plugins.variables.'
            'HostNameVariable:HostNameVariable',

            'member-id = '
            'ardana_configurationprocessor.plugins.variables.'
            'MemberIdVariable:MemberIdVariable',

            'member-in-tier = '
            'ardana_configurationprocessor.plugins.variables.'
            'MemberInTierVariable:MemberInTierVariable',

            'random-password = '
            'ardana_configurationprocessor.plugins.variables.'
            'RandomPasswordVariable:RandomPasswordVariable',

            'random-string = '
            'ardana_configurationprocessor.plugins.variables.'
            'RandomStringVariable:RandomStringVariable',

            'tier-id = '
            'ardana_configurationprocessor.plugins.variables.'
            'TierIdVariable:TierIdVariable',

            'tier-prefix = '
            'ardana_configurationprocessor.plugins.variables.'
            'TierPrefixVariable:TierPrefixVariable',

            'sequence-number = '
            'ardana_configurationprocessor.plugins.variables.'
            'SequenceNumberVariable:SequenceNumberVariable',

            'random-password-2.0 = '
            'ardana_configurationprocessor.plugins.variables.2_0.'
            'RandomPasswordVariable:RandomPasswordVariable',

            'random-string-2.0 = '
            'ardana_configurationprocessor.plugins.variables.2_0.'
            'RandomStringVariable:RandomStringVariable',

            'random-sshkey-2.0 = '
            'ardana_configurationprocessor.plugins.variables.2_0.'
            'RandomSshKeyVariable:RandomSshKeyVariable',

            'sequence-number-2.0 = '
            'ardana_configurationprocessor.plugins.variables.2_0.'
            'SequenceNumberVariable:SequenceNumberVariable',

            'uuid-2.0 = '
            'ardana_configurationprocessor.plugins.variables.2_0.'
            'UUIDVariable:UUIDVariable'
        ],

        'ardana.configurationprocessor.checkpointer': [
            'desired-state = '
            'ardana_configurationprocessor.plugins.checkpointers.'
            'DesiredStateCheckpointer:DesiredStateCheckpointer',

            'config = '
            'ardana_configurationprocessor.plugins.checkpointers.'
            'ConfigCheckpointer:ConfigCheckpointer',

            'persistent-state = '
            'ardana_configurationprocessor.plugins.checkpointers.'
            'PersistentStateCheckpointer:PersistentStateCheckpointer'
        ],

        'ardana.configurationprocessor.explainer': [
            'cloud-structure = '
            'ardana_configurationprocessor.plugins.explainers.'
            'CloudStructureExplainer:CloudStructureExplainer',

            'services = '
            'ardana_configurationprocessor.plugins.explainers.'
            'ServicesExplainer:ServicesExplainer',

            'network-traffic-groups = '
            'ardana_configurationprocessor.plugins.explainers.'
            'NetworkTrafficGroupsExplainer:NetworkTrafficGroupsExplainer',

            'servers = '
            'ardana_configurationprocessor.plugins.explainers.'
            'ServersExplainer:ServersExplainer',

            'override-vars = '
            'ardana_configurationprocessor.plugins.explainers.'
            'OverrideVarsExplainer:OverrideVarsExplainer',

            'override-blocks = '
            'ardana_configurationprocessor.plugins.explainers.'
            'OverrideBlocksExplainer:OverrideBlocksExplainer',

            'servers-2.0 = '
            'ardana_configurationprocessor.plugins.explainers.2_0.'
            'ServersExplainer:ServersExplainer'
        ],

        'ardana.configurationprocessor.migrator': [
            'service-name-to-mnemonic = '
            'ardana_configurationprocessor.plugins.migrators.'
            'ServiceNameToMnemonicMigrator:ServiceNameToMnemonicMigrator',

            'service-name-to-mnemonic-2.0 = '
            'ardana_configurationprocessor.plugins.migrators.2_0.'
            'ServiceNameToMnemonicMigrator:ServiceNameToMnemonicMigrator',

            'resource-nodes-to-resources-2.0 = '
            'ardana_configurationprocessor.plugins.migrators.2_0.'
            'ResourceNodesMigrator:ResourceNodesMigrator',

            'component-list-expansion-2.0 = '
            'ardana_configurationprocessor.plugins.migrators.2_0.'
            'ComponentListMigrator:ComponentListMigrator',

            'swift-rings-2.0 = '
            'ardana_configurationprocessor.plugins.migrators.2_0.'
            'SwiftRingsMigrator:SwiftRingsMigrator'
        ],

        'ardana.configurationprocessor.finalizer': [
            'cloud-model-1.0 = '
            'ardana_configurationprocessor.plugins.finalizers.'
            'CloudModelFinalizer:CloudModelFinalizer',

            'service-map-1.0 = '
            'ardana_configurationprocessor.plugins.finalizers.'
            'ServiceMapFinalizer:ServiceMapFinalizer',

            'network-map-1.0 = '
            'ardana_configurationprocessor.plugins.finalizers.'
            'NetworkMapFinalizer:NetworkMapFinalizer',

            'node-map-1.0 = '
            'ardana_configurationprocessor.plugins.finalizers.'
            'NodeMapFinalizer:NodeMapFinalizer',

            'cloud-model-2.0 = '
            'ardana_configurationprocessor.plugins.finalizers.2_0.'
            'CloudModelFinalizer:CloudModelFinalizer',

            'service-view-2.0 = '
            'ardana_configurationprocessor.plugins.finalizers.2_0.'
            'ServiceViewFinalizer:ServiceViewFinalizer',

            'address-allocation-2.0 = '
            'ardana_configurationprocessor.plugins.finalizers.2_0.'
            'AddressAllocationFinalizer:AddressAllocationFinalizer'
        ],

        'ardana.configurationprocessor.relationship': [
            'produces-log-files-1.0 = '
            'ardana_configurationprocessor.plugins.relationships.'
            'ProducesLogFilesRelationship:ProducesLogFilesRelationship',

            'consumes-1.0 = '
            'ardana_configurationprocessor.plugins.relationships.'
            'ConsumesRelationship:ConsumesRelationship',

            'has-proxy-1.0 = '
            'ardana_configurationprocessor.plugins.relationships.'
            'HasProxyRelationship:HasProxyRelationship',

            'advertises-1.0 = '
            'ardana_configurationprocessor.plugins.relationships.'
            'AdvertisesRelationship:AdvertisesRelationship',

            'has-container-1.0 = '
            'ardana_configurationprocessor.plugins.relationships.'
            'HasContainerRelationship:HasContainerRelationship'
        ]
    }
)
