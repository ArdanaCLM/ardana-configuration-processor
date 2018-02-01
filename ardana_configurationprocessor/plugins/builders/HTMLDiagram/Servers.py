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

from ardana_configurationprocessor.cp.model.BuilderPlugin \
    import ArtifactMode

LOG = logging.getLogger(__name__)

SP = "&nbsp"


class Servers(object):

    def render_servers(self):

        def _add_server_row(table, s, hypervisor=None, num_vms=0, show_hypervisor=False):

            row = table.tr
            if hypervisor:
                if show_hypervisor:
                    span = num_vms + 1
                    id = row.td(rowspan=str(span))
                    id.a("%s" % hypervisor, href="Servers/%s.html" % hypervisor)
                elif hypervisor == 'None':
                    # Special case for non hypervisor servers when we have hypervisors
                    # in the cloud
                    id = row.td(klass='title')

            if s['id'] != hypervisor:
                id = row.td()
                id.a("%s" % s['id'], href="Servers/%s.html" % s['id'])
            else:
                id = row.td(klass='title')

            td = row.td('')
            td.a(s['role'], href="Server_Roles.html#%s.html" % s['role'])
            row.td(s.get('server_group', ''), escape=False)
            row.td(s['state'])

            if s['state'] == 'available':
                # No other data if the server / vm isn't allocated
                return

            cp = row.td
            if 'control-plane-name' in s:
                cp.a("  %s" % s['control-plane-name'],
                     href="../Control_Planes.html#%s" % s['control-plane-name'])

            row.td(s.get('failure-zone', ''), escape=False)
            row.td(s.get('name', ''), escape=False)

            if s.get('hypervisor-id'):
                row.td(str(s.get('vm_no_of_vcpus', '')), escape=False)
                mem_size = s.get('memory-model', {}).get('vm_ram_size_in_k', 0)
                row.td(self.mem_size_string(mem_size))

        # Create a page for each server
        for s in sorted(self.servers, key=lambda s: s['id']):
            self._render_server(s)

        h = self._create_page()

        table = h.table()

        # Add the Titles
        title_row = table.tr

        # See if we have any vm-factories in this model
        vm_factories = {}
        for s in self.servers:
            if s.get('vm-factory', False):
                vm_factories[s['id']] = {'hypervisor': s,
                                         'vms': []}
        for s in self.servers:
            hypervisor = s.get('hypervisor-id')
            if hypervisor:
                vm_factories[hypervisor]['vms'].append(s)

        if vm_factories:
            title_row.td("Hypervisor", klass='title', align='center')
        for x in ['Id', 'Role', 'Group', 'State', 'Control Plane', 'Failure Zone', 'Name']:
            title_row.td(x, klass='title', align='center')
        if vm_factories:
            title_row.td("VCPUs", klass='title', align='center')
            title_row.td("Memory", klass='title', align='center')

        # Do any hypervisors and thier Vms first
        for hypervisor_name in sorted(vm_factories):
            hypervisor = vm_factories[hypervisor_name]
            first = True
            for vm in sorted(hypervisor['vms'], key=lambda vm: vm['id']):
                _add_server_row(table, vm, hypervisor_name, len(hypervisor['vms']), show_hypervisor=first)
                first = False
            _add_server_row(table, hypervisor['hypervisor'], hypervisor_name, show_hypervisor=False)

        # Add any other servers
        for s in sorted(self.servers, key=lambda s: s['id']):
            if not s.get('hypervisor-id') and not s.get('vm-factory', False):
                if vm_factories:
                    _add_server_row(table, s, hypervisor='None', show_hypervisor=False)
                else:
                    _add_server_row(table, s, show_hypervisor=False)

        file_name = "%s/Server_View.html" % (self._file_path)
        self.add_artifact(file_name, ArtifactMode.CREATED)
        fp = open(file_name, 'w')
        fp.write(str(h))
        fp.close

    def _render_server(self, s):

        h = self._create_page(link_prefix="../")
        h.br
        h.h2("Server ID: %s" % s['id'])
        title = h.h3()
        title.text("Role: ")
        title.a("%s" % s['role'],
                href="../Server_Roles.html#%s" % s['role'])
        h.h3("Status: %s" % s['state'])

        h_name = h.h3
        h_name.text("Hostname: ")
        if 'hostname' in s and s.get('hostname'):
            h_name.text(str(s['hostname']))

        cp_link = h.h3
        cp_link.text("Control Plane:")
        if 'control-plane-name' in s:
            cp_link.a("  %s" % s['control-plane-name'],
                      href="../Control_Planes.html#%s" % s['control-plane-name'])

        zone_link = h.h3
        zone_link.text("Failure Zone:")
        if 'failure-zone' in s:
            zone_link.a("  %s" % s['failure-zone'], href="../Server_Groups.html")

        #
        # VMs
        #
        if 'vms' in s:
            h.h3("VMs")
            vm_table = h.table
            title_row = vm_table.tr
            for x in ['Id', 'vCPUs', 'Memory']:
                title_row.td(x, klass='title', align='center')
            for vm in s.get('vms', []):
                row = vm_table.tr
                id = row.td()
                id.a("%s" % vm['vm'], href="%s.html" % vm['vm'])
                row.td(str(vm['vcpus']))
                row.td(self.mem_size_string(vm['ram']))
            h.br
            h.br

        #
        # Services
        #
        h.h3("Services")
        service_table = h.table
        for service, components in s.get('services', {}).iteritems():
            row = service_table.tr
            row.td(service, valign='top')
            comp_text = row.td("", valign='top')
            for comp in components:
                comp_text.text(comp)
                comp_text.br
        h.br
        h.br

        #
        # Disks
        #
        title = h.h3()
        title.text("Disks (")
        title.a("%s" % s['disk-model']['name'],
                href="../Disk_Models.html#%s" % s['disk-model']['name'])
        title.text(")")
        self.render_disk_model(h, s['disk-model'])
        h.br
        h.br

        #
        # Networks
        #
        title = h.h3()
        title.text("Network Interfaces (")
        title.a("%s" % s['if-model'],
                href="../Interface_Models.html#%s" % s['if-model'])
        title.text(")")

        iface_table = h.table()
        # Count the number of networks
        nr_networks = 0
        interfaces = s['interfaces']

        # Un allcoated servers have a list instead of a dict
        if isinstance(interfaces, list):
            iface = {}
            for i in interfaces:
                iface[i['name']] = i
            interfaces = iface

        for if_name, if_data in interfaces.iteritems():
            nr_networks += len(if_data.get('networks', {}))

        for if_name, if_data in interfaces.iteritems():
            row = iface_table.tr
            networks = if_data.get('networks', {})
            row.td(if_name, rowspan=str(len(networks)))
            first_net = True
            for net_name, net_data in networks.iteritems():
                if not first_net:
                    row = iface_table.tr
                else:
                    first_net = False
                text = row.td("")
                text.a(net_name, href="../Networks.html#%s" % (net_name))
                if 'addr' in net_data:
                    text.text("%s(%s)" % (SP, net_data['addr']), escape=False)
                text.text("<br>", escape=False)

                # Routes
                routes_td = row.td("", valign='top')
                if 'routes' in net_data:
                    routes_td.text("Routes%sto:<br>" % SP, escape=False)
                    for route in net_data['routes']:
                        if route['default']:
                            routes_td.text("%s<I>default</I><br>" % (SP * 4), escape=False)
                        else:
                            routes_td.text("%s" % (SP * 4), escape=False)
                            routes_td.a(route['net_name'], href="../Networks.html#%s" % route['net_name'])
                            routes_td.br
        h.br
        h.br

        #
        # Nic Mapping
        #
        title = h.h3()
        if not s['nic_map']:
            title.text("NIC Mapping: None")
        else:
            title.text("NIC Mapping (%s)" % s['nic_map']['name'])
            nic_map_table = h.table
            title_row = nic_map_table.tr()
            title_row.td("Name", klass="title", align='center')
            title_row.td("Bus Address", klass="title", align='center')
            title_row.td("Type", klass="title", align='center')
            for port in s['nic_map']['physical-ports']:
                if 'nic-device-type' in port:
                    title_row.td("Device Type", klass="title", align='center')
                    break

            for port in s['nic_map']['physical-ports']:
                row = nic_map_table.tr
                row.td(port['logical-name'])
                row.td(port['bus-address'])
                row.td(port['type'])
                if 'nic-device-type' in port:
                    row.td("%s (%s)" % (port['nic-device-type']['name'],
                                        port['nic-device-type']['family']))
        h.br
        h.br

        #
        # Memory Model
        #
        if s.get('memory-model', {}):
            title = h.h3()
            title.text("Memory Model (")
            title.a("%s" % s['memory-model']['name'],
                    href="../Memory_Models.html#%s" % s['memory-model']['name'])
            title.text(")")
            for model in self.memory_models:
                if model['name'] == s['memory-model']['name']:
                    self.render_memory_model(h, model)
            h.br
            h.br

        file_name = "%s/Servers/%s.html" % (self._file_path, s['id'])
        self.add_artifact(file_name, ArtifactMode.CREATED)
        fp = open(file_name, 'w')
        fp.write(str(h))
        fp.close

    @staticmethod
    def mem_size_string(mem_size):
        suffix = ''
        if mem_size > 1024:
            suffix = 'M'
            mem_size = int(mem_size / 1024)
        if mem_size > 1024:
            suffix = 'G'
            mem_size = int(mem_size / 1024)
        return "%s%s" % (mem_size, suffix)
