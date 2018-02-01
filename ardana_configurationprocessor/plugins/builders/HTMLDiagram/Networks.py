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


class Networks(object):

    def _render_network_topology(self, h):

        def _build_hover_text(name, net_data):
            result = "%s\n" % name
            for host, addr in net_data['servers'].iteritems():
                if addr:
                    result += "    %s: %s\n" % (host, addr)
                else:
                    result += "    %s\n" % (host)

            for addr, roles in net_data.get('vips', {}).iteritems():
                result += "    VIP: %s (%s)\n" % (addr, str(roles).strip('[]').replace("'", ""))

            if 'service_ips' in net_data:
                result += "\nService IPs\n"
                for service, data in net_data['service_ips'].iteritems():
                    result += "    %s:\n" % service
                    for host, addr in data['hosts'].iteritems():
                        result += "        %s: %s\n" % (host, addr)
                    if 'vip' in data:
                        result += "        %s: %s\n" % ("VIP", data['vip'])
            return result

        def _add_networks(row, net_list):
            net_text = row.td("", valign='top', align='center')
            for net in sorted(net_list):
                net_data = net_list[net]
                hover_text = _build_hover_text(net, net_data)
                net_text.span(net, title=hover_text, escape=False)
                net_text.br

        def _add_group(row, net_group, cp_name, group_name, type):
            net_list = {}
            for net_name, net_data in net_group.iteritems():
                if cp_name not in net_data['control_planes']:
                    continue
                if group_name in net_data['control_planes'][cp_name].get(type, {}):
                    net_list[net_name] = net_data['control_planes'][cp_name][type][group_name]
            if net_list:
                _add_networks(row, net_list)
            else:
                row.td(klass='title')

        def _add_net_group(row, net_group):
            for cp_name in sorted(self.cp_topology['control_planes']):
                cp = self.cp_topology['control_planes'][cp_name]
                for cluster_name, cluster_data in cp['clusters'].iteritems():
                    _add_group(row, net_group, cp_name, cluster_name, 'clusters')

                for r_name, r_data in cp.get('resources', {}).iteritems():
                    _add_group(row, net_group, cp_name, r_name, 'resources')

        table = h.table

        # Add the Titles
        title_row = table.tr
        title_row.td(klass='title')
        for cp_name in sorted(self.cp_topology['control_planes']):
            cp = self.cp_topology['control_planes'][cp_name]
            span = str(len(cp['clusters']) + len(cp.get('resources', {})))
            title = title_row.td("", align='center', colspan=span)
            cp_link = title.b
            cp_link.a(cp_name, href="%s#%s" % ("Control_Planes.html", cp_name))

        title_row = table.tr
        title_row.td(klass='title')
        for cp_name in sorted(self.cp_topology['control_planes']):
            cp = self.cp_topology['control_planes'][cp_name]
            title = title_row.td("", align='center', colspan=str(len(cp['clusters'])))
            title.b("Clusters")
            if cp.get('resources', {}):
                title = title_row.td("", align='center', colspan=str(len(cp['resources'])))
                title.b("Resources")

        title_row = table.tr
        title_row.td(klass='title')
        for cp_name in sorted(self.cp_topology['control_planes']):
            cp = self.cp_topology['control_planes'][cp_name]
            for cluster_name, cluster_data in cp['clusters'].iteritems():
                title = title_row.td("", align='center')
                title.b(cluster_name)
            for r_name, r_data in cp.get('resources', {}).iteritems():
                title = title_row.td("", align='center')
                title.b(r_name)

        for net_group, net_group_data in self.network_topology['network_groups'].iteritems():
            data_row = table.tr
            net_group_name = data_row.td()
            net_group_name.a("%s" % net_group, href="#%s" % net_group)
            _add_net_group(data_row, net_group_data)

    def render_networks(self):

        def _render_group(t, data, cp_name):

            def _render_server(addr, server=None, lb=None, info=None, cp=None):
                if addr:
                    addr_text.text(addr)
                addr_text.br
                if server:
                    s = self.server_by_name[server]
                    if info:
                        server_name = "%s (%s)" % (server, info)
                    else:
                        server_name = server
                    server_text.a(server_name,
                                  href="Servers/%s.html" % s['id'])

                    model = s['if-model']
                    if model != last_model[0]:
                        model_text.a(model, href="Interface_Models.html#%s" % model)
                        last_model[0] = model
                    model_text.br
                elif lb:
                    server_text.a(lb, href="%s#%s" % ("Control_Planes.html", cp_name))
                elif info:
                    server_text.text(info)
                server_text.br

            row = t.tr
            addr_text = row.td("", width='110', klass="tab")
            server_text = row.td("", width='200', klass="tab")
            model_text = row.td("", width='230', klass="tab")
            last_model = [""]
            for host, addr in data.get('servers', {}).iteritems():
                _render_server(addr, host)

            for addr, lb_name in data.get('vips', {}).iteritems():
                _render_server(addr, lb=lb_name, cp=cp_name, info="VIP")

            for service, service_data in data.get('service_ips', {}).iteritems():
                for host, addr in service_data['hosts'].iteritems():
                    _render_server(addr, host, info=service)

                if 'vip' in service_data:
                    _render_server(service_data['vip'], info="VIP (%s)" % service)
            addr_text.br
            server_text.br
            model_text.br

        def _render_net_servers(t, data):
            for cp_name, cp_data in data.iteritems():
                for cluster_name, cluster_data in cp_data.get('clusters', {}).iteritems():
                    _render_group(t, cluster_data, cp_name)
                for r_name, r_data in cp_data.get('resources', {}).iteritems():
                    _render_group(t, r_data, cp_name)

        def _build_tag_hover_text(tag):
            result = "%s\n" % tag['component']
            for k, v in tag.get('values', {}).iteritems():
                result += "  %s: %s\n" % (k, v)
            return result

        h = self._create_page()

        h.h2("Network Topology")
        self._render_network_topology(h)
        h.br
        h.br

        h.h2("Network Groups")
        for group_name in sorted(self.network_groups):
            group = self.network_groups[group_name]
            h.a(name=group_name)
            h.h3(group_name)
            for net in group.get('networks', []):
                h.a(name=net['name'])
            ng_table = h.table()

            title_row = ng_table.tr
            title_row.td("Network Group", klass='title')
            title_row.td("Networks", klass='title')
            address_td = title_row.td(klass='title')
            address_tbl = address_td.table(klass='title')
            address_row = address_tbl.tr
            address_row.td("Address", klass='title', width='120')
            address_row.td("Server", klass='title', width='210')
            address_row.td("Interface Model", klass='title')

            ng_row = ng_table.tr
            ng_text = ng_row.td(rowspan=str(len(group['networks'])),
                                valign='top', width='240')

            components = (group.get('component-endpoints', []) +
                          group.get('tls-component-endpoints', []))
            if components:
                ng_text.text("Components:")
                ng_text.br
                for comp in sorted(components):
                    ng_text.text("%s%s" % (SP * 4, comp), escape=False)
                    if comp in group.get('tls-component-endpoints', []):
                        ng_text.text("%s(tls)" % SP, escape=False)
                    ng_text.br
                ng_text.br

            if 'load-balancers' in group:
                ng_text.text("Load Balancers:")
                ng_text.br
                for lb in group['load-balancers']:
                    if isinstance(lb, dict):
                        lb_name = lb['name']
                    else:
                        lb_name = lb

                    ng_text.text("%s%s" % (SP * 4, lb_name), escape=False)
                    ng_text.br
                    for cp_name, cp_data in self.control_planes.iteritems():
                        for cp_lb in cp_data.get('load-balancers', []):
                            if cp_lb['name'] == lb_name:
                                ng_text.text("%s" % (SP * 8), escape=False)
                                ng_text.a(cp_name, href="%s#%s" % ("Control_Planes.html", cp_name))
                                ng_text.br
                ng_text.br

            if 'routes' in group:
                ng_text.text("Routes:")
                ng_text.br
                for route in group['routes']:
                    if route != 'default':
                        ng_text.test("%s" % SP * 4, escape=False)
                        ng_text.a("%s" % route, href="#%s" % route)
                    else:
                        ng_text.text("%s%s" % (SP * 4, route), escape=False)
                    ng_text.br
                ng_text.br

            tags = {}
            for cp_name in sorted(self.control_planes):
                cp_data = self.control_planes[cp_name]
                if group_name in cp_data.get('network-tags', {}):
                    tags[cp_name] = cp_data['network-tags'][group_name]
            if tags:
                ng_text.text("Network Tags:")
                ng_text.br
                for cp_name, tag_list in tags.iteritems():
                    ng_text.text("%sControl Plane: " % (SP * 4), escape=False)
                    ng_text.a(cp_name, href="%s#%s" % ("Control_Planes.html", cp_name))
                    ng_text.br
                    for tag in tag_list:
                        ng_text.text("%s" % (SP * 8), escape=False)
                        hover_text = _build_tag_hover_text(tag)
                        ng_text.span(tag['name'], title=hover_text, escape=False)
                        ng_text.br
                ng_text.br

            nets = {}
            for net in group.get('networks', []):
                nets[net['name']] = net
            for net_name in sorted(nets):
                net = nets[net_name]
                net_text = ng_row.td(net['name'], valign='top', width='240')

                # Put network properties in thier own sub table
                t = net_text.table(klass="tab")
                if 'vlanid' in net:
                    r = t.tr
                    r.td("vlan id:", klass="tab")
                    if net.get('tagged-vlan', True):
                        vlan = "%s (tagged)" % net['vlanid']
                    else:
                        vlan = "%s (untagged)" % net['vlanid']
                    r.td(str(vlan), klass="tab")

                for key in ['cidr', 'gateway-ip', 'mtu']:
                    if key in net:
                        r = t.tr
                        r.td(key + ":", klass="tab")
                        r.td(str(net[key]), klass="tab")

                # Add a new column for the addresses
                addr_td = ng_row.td('', valign='top')
                t = addr_td.table(klass="tab")
                if group_name not in self.network_topology['network_groups']:
                    r = t.tr
                    r.td(klass="tab", width='475')
                    continue

                address_info = self.network_topology['network_groups'][group_name][net['name']]['control_planes']
                if address_info:
                    _render_net_servers(t, address_info)
                else:
                    t.tr
                ng_row = ng_table.tr

            h.br

        file_name = "%s/Networks.html" % (self._file_path)
        self.add_artifact(file_name, ArtifactMode.CREATED)
        fp = open(file_name, 'w')
        fp.write(str(h))
        fp.close
