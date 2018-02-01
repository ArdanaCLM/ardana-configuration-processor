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


class ServerRoles(object):

    def render_server_roles(self):

        h = self._create_page()
        roles_table = h.table()

        # Add the Titles
        title_row = roles_table.tr
        title_row.td("", klass='title', align='center')
        title_row.td("Disk Model", klass='title', align='center')
        title_row.td("Interface Model", klass='title', align='center')
        title_row.td("CPU Model", klass='title', align='center')
        title_row.td("Memory Model", klass='title', align='center')

        roles = {}
        for role in self.server_roles:
            roles[role['name']] = role

        for role_name in sorted(roles):
            role = roles[role_name]
            role_row = roles_table.tr
            td = role_row.td('', klass='title')
            td.a(role['name'], name=role['name'])

            td = role_row.td("")
            td.a(role['disk-model'],
                 href="Disk_Models.html#%s" % role['disk-model'])

            td = role_row.td("")
            td.a(role['interface-model'],
                 href="Interface_Models.html#%s" % role['interface-model'])

            if 'cpu-model' in role:
                td = role_row.td("")
                td.a(role['cpu-model'],
                     href="CPU_Models.html#%s" % role['cpu-model'])
            else:
                role_row.td("", klass='title')

            if 'memory-model' in role:
                td = role_row.td("")
                td.a(role['memory-model'],
                     href="Memory_Models.html#%s" % role['memory-model'])
            else:
                role_row.td("", klass='title')

        file_name = "%s/Server_Roles.html" % (self._file_path)
        self.add_artifact(file_name, ArtifactMode.CREATED)
        fp = open(file_name, 'w')
        fp.write(str(h))
        fp.close
