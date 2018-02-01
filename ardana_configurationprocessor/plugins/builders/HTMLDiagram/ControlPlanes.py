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


class ControlPlanes(object):

    def render_control_planes(self):

        h = self._create_page()
        h.br

        for cp_name in sorted(self.cp_topology['control_planes']):
            self._render_control_plane(cp_name, self.cp_topology['control_planes'][cp_name], h)

        file_name = "%s/Control_Planes.html" % (self._file_path)
        self.add_artifact(file_name, ArtifactMode.CREATED)
        fp = open(file_name, 'w')
        fp.write(str(h))
        fp.close

    def _render_control_plane(self, cp_name, cp_topology, h):

        list_separatly = ['foundation', 'clients', 'ardana']

        def _build_service_hover_text(data):
            result = "Components:\n"
            for c in data['components']:
                result += "    %s\n" % c
            result += "\nRegions:\n"
            for r in data['regions']:
                result += "    %s\n" % r
            return result

        def _render_services(row, name, services, service_list):

            service_text = row.td("", valign='top', align='center')
            service_text.b(name)
            service_text.br
            service_text.br
            for service_name in sorted(service_list):
                if service_name in list_separatly:
                    continue
                if service_name in services:
                    hover_text = _build_service_hover_text(services[service_name])
                    service_text.span("%s" % service_name, title=hover_text, escape=False)
                service_text.br

            service_text.br
            for service_name in list_separatly:
                if service_name in services:
                    hover_text = _build_service_hover_text(services[service_name])
                    service_text.span("%s" % service_name, title=hover_text, escape=False)
                service_text.br

        def _build_vip_hover_text(data):
            result = ""
            for comp_name in sorted(data):
                comp_data = data[comp_name]
                result += "%s  (%s)" % (comp_name, comp_data['port'])
                if comp_data['vip-tls']:
                    result += "   TLS"
                result += "\n"
                for role, alias in comp_data['aliases'].iteritems():
                    result += "    %s\n" % alias
                result += '    hosts:\n'
                for host in comp_data['hosts']:
                    result += "        %s" % host
                    if comp_data['host-tls']:
                        result += "   TLS"
                    result += "\n"
                result += '\n'
            return result

        def _render_service_vip(text, name, data):
            hover_text = _build_vip_hover_text(data)
            text.span(name, title=hover_text, escape=False)

        def _render_load_balancer(row, lb_name, lb_data, service_list):
            lb_text = row.td("", valign='top', align='center')
            lb_text.b(lb_name)
            lb_text.br
            lb_text.br

            for service_name in sorted(service_list):

                if service_name in list_separatly:
                    continue
                if service_name in lb_data['services']:
                    service_data = lb_data['services'][service_name]
                    _render_service_vip(lb_text, service_name, service_data)
                lb_text.br
            lb_text.br

            for service_name in list_separatly:
                if service_name in lb_data['services']:
                    service_data = lb_data['services'][service_name]
                    _render_service_vip(lb_text, service_name, service_data)
                lb_text.br

            lb_text.br
            lb_text.text(str(lb_data['external-name']))
            lb_text.br
            if 'address' in lb_data:
                lb_text.a(lb_data['address'], href="Networks.html#%s" % (lb_data['network']))
            lb_text.br
            lb_text.br

        def _render_servers(row, servers):
            zone_text = row.td("", valign='top', align='center')
            for host in servers:
                s = self.server_by_hostname[host]
                zone_text.a("  %s" % host,
                            href="Servers/%s.html" % s['id'])
                zone_text.text("<br>", escape=False)

        # build a list of all zones
        cp_zones = set()
        for cluster_name, cluster_data in cp_topology['clusters'].iteritems():
            for zone in cluster_data['failure_zones']:
                cp_zones.add(zone)
        for r_name, r_data in cp_topology.get('resources', {}).iteritems():
            for zone in r_data['failure_zones']:
                cp_zones.add(zone)

        h.a("", name="#%s" % cp_name)
        h.h2(cp_name)

        table = h.table()

        # Add the Titles
        title_row = table.tr
        title_row.td(klass='title')
        title = title_row.td("", align='center', colspan=str(len(cp_topology['clusters'])))
        title.b("Clusters")
        if cp_topology.get('resources', {}):
            title = title_row.td("", align='center', colspan=str(len(cp_topology['resources'])))
            title.b("Resources")
        if cp_topology.get('load-balancers', []):
            title = title_row.td("", align='center', colspan=str(len(cp_topology['load-balancers'])))
            title.b("Load Balancers")

        # Build a list of all services so we can align them
        service_list = set()
        for cluster_name, cluster_data in cp_topology['clusters'].iteritems():
            service_list.update(set(cluster_data['services']))
        for r_name, r_data in cp_topology.get('resources', {}).iteritems():
            service_list.update(set(r_data['services']))
        for lb_name, lb_data in cp_topology.get('load-balancers').iteritems():
            service_list.update(set(lb_data['services']))

        data_row = table.tr
        data_row.td(klass='title')
        for cluster_name, cluster_data in cp_topology['clusters'].iteritems():
            _render_services(data_row, cluster_name, cluster_data['services'], service_list)
        for r_name, r_data in cp_topology.get('resources', {}).iteritems():
            _render_services(data_row, r_name, r_data['services'], service_list)
        for lb_name, lb_data in cp_topology.get('load-balancers').iteritems():
            _render_load_balancer(data_row, lb_name, lb_data, service_list)

        for zone in cp_zones:
            data_row = table.tr
            data_row.td(str(zone))
            for cluster_name, cluster_data in cp_topology['clusters'].iteritems():
                _render_servers(data_row, cluster_data['failure_zones'].get(zone, []))
            for r_name, r_data in cp_topology.get('resources', {}).iteritems():
                _render_servers(data_row, r_data['failure_zones'].get(zone, []))

        h.br
        h.br
