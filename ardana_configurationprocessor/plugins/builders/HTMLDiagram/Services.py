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


class Services(object):

    def render_services(self):

        def _build_hover_text(cp_name, comp_info):
            result = "%s\n\n" % cp_name
            result += "Servers:\n"
            for c_name, c_hosts in comp_info.get('clusters', {}).iteritems():
                result += "    %s\n" % c_name
                for s in c_hosts:
                    result += "        %s\n" % s
            for r_name, r_hosts in comp_info.get('resources', {}).iteritems():
                result += "    %s\n" % r_name
                for s in r_hosts:
                    result += "        %s\n" % s
            result += "\nRegions:\n"
            for r in comp_info['regions']:
                result += "    %s\n" % r
            return result

        def _render_cp_entry(td, cp_name, comp_info):
            hover_text = _build_hover_text(cp_name, comp_info)
            td.span("%s" % cp_name, title=hover_text, escape=False)
            td.br

        h = self._create_page()

        service_classes = {}
        for service_name, service_data in self.services.iteritems():
            if 'service-class' in service_data:
                service_class = service_data['service-class']
                if service_class not in service_classes:
                    service_classes[service_class] = []
                service_classes[service_class].append(service_name)

        if service_classes:
            table = h.table()
            # Add the Titles
            title_row = table.tr
            title_row.td("Class", klass='title', align='left')
            title_row.td("Description", klass='title', align='left')
            title_row.td("Service", klass='title', align='left')
            for service_class in sorted(service_classes):
                row = table.tr()
                row.td(service_class, rowspan=str(len(service_classes[service_class])))
                first_row = True
                for service in sorted(service_classes[service_class]):
                    if first_row:
                        first_row = False
                    else:
                        row = table.tr
                    row.td(self.services[service].get('description', ''))
                    td = row.td()
                    td.a(service, href="#%s" % service)
                    td.br
            h.br
            h.br

        for service_name in sorted(self.services):

            service_data = self.services[service_name]
            if service_data.get('hidden', False):
                continue

            h.a("", name="%s" % service_name)
            for comp_name in service_data.get('component-list', []):
                h.a("", name="%s" % comp_name)
            heading = service_name
            if 'description' in service_data:
                heading += " (%s)" % service_data['description']
            h.h2(heading)

            table = h.table()
            # Add the Titles
            title_row = table.tr
            title_row.td("Components", klass='title', align='center', width='150')
            title_row.td("Control Planes", klass='title', align='center', width='150')
            title_row.td("Consumes", klass='title', align='center', width='150')
            title_row.td("Endpoints", klass='title', align='center', width='150')

            row = table.tr

            first_comp = True
            for comp_name in sorted(service_data.get('component-list', [])):
                comp_def = self.components[comp_name]
                if comp_def.get('hidden', False):
                    continue

                if 'alias-for' in comp_def:
                    continue

                if first_comp:
                    first_comp = False
                else:
                    row = table.tr

                row.td(comp_name, valign='top')

                if service_name in self.service_topology['services']:
                    cloud_service_data = self.service_topology['services'][service_name]
                    if comp_name in cloud_service_data['components']:
                        td = row.td("", valign='top')
                        comp_data = cloud_service_data['components'][comp_name]
                        for cp_name in sorted(self.control_planes):
                            comp_info = {'components': {}}
                            if cp_name in comp_data['control_planes']:
                                comp_info = comp_data['control_planes'][cp_name]
                                _render_cp_entry(td, cp_name, comp_info)
                    else:
                        row.td("", klass='title', width='150')
                else:
                    row.td("", klass='title', width='150')

                if 'consumes-services' in comp_def:
                    consume_list = {}
                    optional_list = {}
                    for consumes in comp_def['consumes-services']:
                        consume_name = consumes['service-name']
                        consume_name = self.components_by_mnemonic.get(consume_name, consume_name)
                        consume_service = self.components[consume_name]['service']
                        if not consumes.get('optional', False):
                            if consume_service not in consume_list:
                                consume_list[consume_service] = []
                            consume_list[consume_service].append(consume_name)
                        else:
                            if consume_service not in optional_list:
                                optional_list[consume_service] = []
                            optional_list[consume_service].append(consume_name)
                    td = row.td(valign='top')
                    for consumes_service in sorted(consume_list):
                        comps = consume_list[consumes_service]
                        for comp in sorted(comps):
                            td.a(comp, href="#%s" % comp)
                            td.br
                    if optional_list:
                        if consume_list:
                            td.br
                        td.i("Optional:")
                        td.br
                        for consumes_service in sorted(optional_list):
                            comps = optional_list[consumes_service]
                            for comp in sorted(comps):
                                td.a(comp, href="#%s" % comp)
                                td.br
                else:
                    row.td("", klass='title')

                if 'endpoints' in comp_def:
                    td = row.td(valign='top')
                    ep_table = td.table(klass='tab')
                    for ep in comp_def['endpoints']:
                        ep_row = ep_table.tr(klass='tab')

                        # Role
                        ep_td = ep_row.td('', klass='tab', width='150')
                        ep_td.text(str(ep['roles']).strip('[]').replace("'", ""))

                        # Port
                        ep_td = ep_row.td(str(ep['port']), klass='tab', align='right', width='100')

                        # Protocol
                        ep_td = ep_row.td(ep.get('protocol', 'tcp'), klass='tab')

                        # VIP
                        if ep.get('has-vip', False):
                            ep_td = ep_row.td('VIP', klass='tab')
                        else:
                            ep_td = ep_row.td('', klass='tab')

            h.br
            h.br
        h.br
        h.br

        file_name = "%s/Services.html" % (self._file_path)
        self.add_artifact(file_name, ArtifactMode.CREATED)
        fp = open(file_name, 'w')
        fp.write(str(h))
        fp.close
