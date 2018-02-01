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


class MemoryModels(object):

    def render_memory_model(self, h, memory_model):

        table = h.table()
        if 'huge-pages' in memory_model:
            sizes = {}
            for page_data in memory_model.get('huge-pages', []):
                if page_data['size'] not in sizes:
                    sizes[page_data['size']] = []
                sizes[page_data['size']].append(page_data)

            title_row = table.tr
            title_row.td("", klass='title')
            title_row.td("Page Size", klass='title', align='center', width='150')
            title_row.td("Page Count", klass='title', align='center', width='150')
            title_row.td("Numa Node", klass='title', align='center', width='150')

            row = table.tr
            td = row.td("", rowspan=str(len(memory_model['huge-pages'])))
            td.text("Huge Pages")

            first_row = True
            for size in sorted(sizes):
                size_data = sizes[size]
                if first_row:
                    first_row = False
                else:
                    row = table.tr
                size_text = row.td("", align='center', rowspan=str(len(size_data)))
                size_text.text(size)
                if size == memory_model.get('default-huge-page-size', ''):
                    size_text.br
                    size_text.text("(Default)")

                first_size_row = True
                for page_data in size_data:
                    if first_size_row:
                        first_size_row = False
                    else:
                        row = table.tr
                    row.td(str(page_data['count']), align='center')
                    if 'numa-node' in page_data:
                        row.td(str(page_data['numa-node']), align='center')

        if 'vm-size' in memory_model:
            row = table.tr
            row.td("VM Size")
            row.td(memory_model['vm-size'].get('ram', ""))

    def render_memory_models(self):

        h = self._create_page()

        h.h2("Memory Models")
        for model in self.memory_models:
            model_name = h.h3()
            model_name.a(model['name'], name=model['name'])

            self.render_memory_model(h, model)

            used_by = h.table(klass='used_by')
            used_by.tr
            used_by.td("Used By:", klass='used_by')
            for role in self.server_roles:
                if role.get('memory-model', "") == model['name']:
                    role_link = used_by.td(klass='used_by')
                    role_link.a(role['name'], href="Server_Roles.html#%s" % role['name'])
            h.br
            h.br

        file_name = "%s/Memory_Models.html" % (self._file_path)
        self.add_artifact(file_name, ArtifactMode.CREATED)
        fp = open(file_name, 'w')
        fp.write(str(h))
        fp.close
