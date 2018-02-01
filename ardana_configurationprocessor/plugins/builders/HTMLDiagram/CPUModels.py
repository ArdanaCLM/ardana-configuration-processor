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


class CPUModels(object):

    def render_cpu_models(self):

        h = self._create_page()

        h.h2("CPU Models")
        for model in self.cpu_models:
            model_name = h.h3()
            model_name.a(model['name'], name=model['name'])

            table = h.table()

            if 'assignments' in model:

                title_row = table.tr
                title_row.td("", klass='title')
                title_row.td("Components", klass='title', align='center', width='150')
                title_row.td("Role", klass='title', align='center', width='150')
                title_row.td("CPU IDs", klass='title', align='center', width='150')
                title_row.td("Isolated", klass='title', align='center', width='150')

                rows = 0
                for assignment in model.get('assignments', []):
                    for cpu in assignment['cpu']:
                        rows += 1

                row = table.tr
                td = row.td("Assignments", rowspan=str(rows))

                first_row = True
                for assignment in model.get('assignments', []):
                    if first_row:
                        first_row = False
                    else:
                        row = table.tr
                    td = row.td("", rowspan=str(len(assignment['cpu'])), align='center')
                    for comp in assignment['components']:
                        td.text(comp)
                        td.br

                    first_assignment_row = True
                    for cpu in assignment['cpu']:
                        if first_assignment_row:
                            first_assignment_row = False
                        else:
                            row = table.tr
                        row.td(cpu['role'], align='center')
                        row.td(str(cpu.get('processor-id-string', '')), align='center')
                        row.td(str(cpu.get('isolate', True)), align='center')

            if 'vm-size' in model:
                row = table.tr
                row.td("VM Size")
                row.td("%s vcpus" % model['vm-size'].get('vcpus', ""))

            used_by = h.table(klass='used_by')
            used_by.tr
            used_by.td("Used By:", klass='used_by')
            for role in self.server_roles:
                if role.get('cpu-model', "") == model['name']:
                    role_link = used_by.td(klass='used_by')
                    role_link.a(role['name'], href="Server_Roles.html#%s" % role['name'])
            h.br
            h.br

        file_name = "%s/CPU_Models.html" % (self._file_path)
        self.add_artifact(file_name, ArtifactMode.CREATED)
        fp = open(file_name, 'w')
        fp.write(str(h))
        fp.close
