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
from html import HTML

from ardana_configurationprocessor.cp.model.v2_0.ArdanaPaths \
    import ArdanaPaths
from ardana_configurationprocessor.cp.model.v2_0.CloudDescription \
    import CloudDescription
from ardana_configurationprocessor.cp.model.v2_0.CloudModel \
    import CloudModel

from ardana_configurationprocessor.cp.model.BuilderPlugin \
    import BuilderPlugin
from ardana_configurationprocessor.cp.model.BuilderPlugin \
    import ArtifactMode
from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog

# HTML Mixin classes
from ardana_configurationprocessor.plugins.builders.HTMLDiagram.ControlPlanes import ControlPlanes
from ardana_configurationprocessor.plugins.builders.HTMLDiagram.InterfaceModels import InterfaceModels
from ardana_configurationprocessor.plugins.builders.HTMLDiagram.Networks import Networks
from ardana_configurationprocessor.plugins.builders.HTMLDiagram.Regions import Regions
from ardana_configurationprocessor.plugins.builders.HTMLDiagram.ServerGroups import ServerGroups
from ardana_configurationprocessor.plugins.builders.HTMLDiagram.Servers import Servers
from ardana_configurationprocessor.plugins.builders.HTMLDiagram.Services import Services
from ardana_configurationprocessor.plugins.builders.HTMLDiagram.ServerRoles import ServerRoles
from ardana_configurationprocessor.plugins.builders.HTMLDiagram.DiskModels import DiskModels
from ardana_configurationprocessor.plugins.builders.HTMLDiagram.MemoryModels import MemoryModels
from ardana_configurationprocessor.plugins.builders.HTMLDiagram.CPUModels import CPUModels


LOG = logging.getLogger(__name__)

SP = "&nbsp"


class HTMLDiagramBuilder(ControlPlanes,
                         InterfaceModels,
                         Networks,
                         Regions,
                         ServerGroups,
                         Servers,
                         Services,
                         ServerRoles,
                         DiskModels,
                         MemoryModels,
                         CPUModels,
                         BuilderPlugin):
    def __init__(self, instructions, models, controllers):
        super(HTMLDiagramBuilder, self).__init__(
            2.0, instructions, models, controllers,
            'html-diagram-2.0')
        LOG.info('%s()' % KenLog.fcn())

        self.cloud_desc = self._models['CloudDescription']['cloud']
        self._file_path = ArdanaPaths.get_output_path(self._instructions,
                                                      self.cloud_desc)
        self._file_path = os.path.join(self._file_path, 'html')

        self._cloud_model = self._models['CloudModel']
        self._cloud_version = CloudModel.version(self._cloud_model,
                                                 self._version)
        self._cloud_internal = CloudModel.internal(self._cloud_model)

        self.cloud_name = CloudDescription.get_cloud_name(self.cloud_desc)
        self.control_planes = CloudModel.get(self._cloud_internal, 'control-planes')
        self.iface_models = CloudModel.get(self._cloud_version, 'interface-models')
        self.server_roles = CloudModel.get(self._cloud_version, 'server-roles')
        self.disk_models = CloudModel.get(self._cloud_version, 'disk-models', [])
        self.memory_models = CloudModel.get(self._cloud_version, 'memory-models', [])
        self.cpu_models = CloudModel.get(self._cloud_version, 'cpu-models', [])
        self.components = CloudModel.get(self._cloud_internal, 'components')
        self.services = CloudModel.get(self._cloud_internal, 'services')
        self.servers = CloudModel.get(self._cloud_internal, 'servers')
        self.server_groups = CloudModel.get(self._cloud_internal, 'server-groups')
        self.network_groups = CloudModel.get(self._cloud_internal, 'network-groups')

        self.region_topology = CloudModel.get(self._cloud_internal, 'region-topology')
        self.service_topology = CloudModel.get(self._cloud_internal, 'service-topology')
        self.cp_topology = CloudModel.get(self._cloud_internal, 'cp-topology')
        self.network_topology = CloudModel.get(self._cloud_internal, 'network-topology')

        self.components_by_mnemonic = {}
        for comp_name, comp_data in self.components.iteritems():
            if 'alias-for' not in comp_data:
                self.components_by_mnemonic[comp_data['mnemonic']] = comp_name

        ArdanaPaths.make_path(self._file_path)
        for subdir in ['Servers']:
            ArdanaPaths.make_path(self._file_path + "/%s" % subdir)

        # Create a mapping from hostname to server id
        self.server_by_hostname = {}
        self.server_by_name = {}
        for s in self.servers:
            if 'hostname' in s:
                self.server_by_hostname[s['hostname']] = s
            if 'name' in s:
                self.server_by_name[s['name']] = s

    def build(self):
        LOG.info('%s()' % KenLog.fcn())

        self._write_style_sheet()

        self._render_cloud()

    def _write_style_sheet(self):

        filename = '%s/ardana.css' % self._file_path
        self.add_artifact(filename, ArtifactMode.CREATED)
        with open(filename, 'w') as f:

            f.write("table, tr {\n")
            f.write("    border:2px solid #01A982;\n")
            f.write("    background-color:#C6C9CA;\n")
            f.write("    padding:5;\n")
            f.write("    border-spacing:5;\n")
            f.write("}\n")
            f.write("td {\n")
            f.write("    border:1px solid #01A982;\n")
            f.write("    background-color:#E6E9EA;\n")
            f.write("    padding:5;\n")
            f.write("    border-spacing:5;\n")
            f.write("}\n")
            f.write(".title {\n")
            f.write("    background-color:#C6C9CA;\n")
            f.write("    border:0px ;\n")
            f.write("    padding:0;\n")
            f.write("    margin-left:10;\n")
            f.write("    font-weight:bold;\n")
            f.write("}\n")
            f.write(".tab {\n")
            f.write("    border:0px ;\n")
            f.write("    background-color:#E6E9EA;\n")
            f.write("    padding:0;\n")
            f.write("    padding-right:4;\n")
            f.write("    border-spacing:10 1;\n")
            f.write("    vertical-align:top;\n")
            f.write("}\n")
            f.write(".used_by {\n")
            f.write("    border:0px ;\n")
            f.write("    background-color:#E6E9EA;\n")
            f.write("    padding:0;\n")
            f.write("    padding-right:10;\n")
            f.write("    border-spacing:20 4;\n")
            f.write("}\n")

    def _create_page(self, link_prefix=""):

        h = HTML('html', '')
        h.h1("Cloud: %s" % self.cloud_name)
        head = h.head()
        head.link(rel="stylesheet", type="text/css", href="%sardana.css" % link_prefix)

        heading = h.h2()
        heading.a("Control Plane View", href="%sControl_Planes.html" % link_prefix)
        heading.text(SP * 10, escape=False)

        heading.a("Region View", href="%sRegions.html" % link_prefix)
        heading.text(SP * 10, escape=False)

        heading.a("Service View", href="%sServices.html" % link_prefix)
        heading.text(SP * 10, escape=False)

        heading.a("Network View", href="%sNetworks.html" % link_prefix)
        heading.text(SP * 10, escape=False)

        heading.a("Server View", href="%sServer_View.html" % link_prefix)
        heading.text(SP * 10, escape=False)

        heading.a("Server Groups View", href="%sServer_Groups.html" % link_prefix)
        heading.text(SP * 10, escape=False)

        h.br
        return h

    def _render_cloud(self):

        self.render_control_planes()
        self.render_regions()
        self.render_services()
        self.render_networks()
        self.render_server_groups()
        self.render_servers()
        self.render_server_roles()
        self.render_iface_models()
        self.render_disk_models()
        self.render_memory_models()
        self.render_cpu_models()
