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


class Regions(object):

    def render_regions(self):

        def _build_hover_text(data):
            result = "Components:\n"
            for c in data:
                result += "  %s\n" % c
            return result

        def _render_services(row, cp_services, advertised, services):
            service_text = row.td("", align='center', valign='top')
            for service in sorted(cp_services):
                if service in services:
                    hover_text = _build_hover_text(services[service])
                    bold = False
                    for c in services[service]:
                        if c in advertised:
                            bold = True
                    if bold:
                        service_name = "<b>%s</b>" % service
                    else:
                        service_name = "%s" % service
                    service_text.span(service_name, title=hover_text, escape=False)
                service_text.br

        regions = self.region_topology['regions']

        # build a list of the components advertised to keystone
        advertised = {}
        for cp_name, cp in self.control_planes.iteritems():
            cp_advertised = self.control_planes[cp_name].get('advertised', {})
            for adv in cp_advertised.get('keystone-api', []):
                for r in adv['regions']:
                    if r not in advertised:
                        advertised[r] = []
                    advertised[r].append(adv['component_name'])

        h = self._create_page()
        region_table = h.table()

        # Add the Titles
        title_row = region_table.tr
        title_row.td("Control Planes", klass='title', align='center', width='150')
        for region in sorted(regions):
            title_row.td(region, klass='title', align='center', width='150')

        for cp_name in sorted(self.control_planes):
            cp_services = self.control_planes[cp_name]['services']
            data_row = region_table.tr
            cp_text = data_row.td("", valign='top', align='center')
            cp_text.a(cp_name, href="%s#%s" % ("Control_Planes.html", cp_name))

            for region_name in sorted(regions):
                if cp_name in regions[region_name]['control_planes']:
                    region_cp_data = regions[region_name]['control_planes'][cp_name]

                    _render_services(data_row, cp_services, advertised.get(region_name, []),
                                     region_cp_data['services'])
                else:
                    data_row.td("", klass='title')
        h.br
        h.br

        file_name = "%s/Regions.html" % (self._file_path)
        self.add_artifact(file_name, ArtifactMode.CREATED)
        fp = open(file_name, 'w')
        fp.write(str(h))
        fp.close
