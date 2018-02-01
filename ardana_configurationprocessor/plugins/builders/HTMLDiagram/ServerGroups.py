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

from ardana_configurationprocessor.cp.model.v2_0 \
    import ServerState

from ardana_configurationprocessor.cp.model.BuilderPlugin \
    import ArtifactMode

LOG = logging.getLogger(__name__)

SP = "&nbsp"


class ServerGroups(object):

    def render_server_groups(self):

        def _count_children(group):
            my_count = len(group.get('groups', {}))
            for child_group in group.get('groups', []):
                my_count += _count_children(child_group) - 1
            if my_count == 0:
                my_count = 1
            group['child-count'] = my_count
            return my_count

        def _add_row(table, groups):
            row = table.tr

            # Build a list of all netwok groups and server roles
            all_net_groups = {}
            all_roles = {}
            for group_data in groups:
                if 'network-groups' in group_data:
                    for net_group in group_data['network-groups']:
                        if net_group not in all_net_groups:
                            all_net_groups[net_group] = {}
                        if group_data['name'] not in all_net_groups[net_group]:
                            all_net_groups[net_group][group_data['name']] = 0
                        all_net_groups[net_group][group_data['name']] += 1

                if 'servers' in group_data:
                    for server in group_data['servers']:
                        role = server['role']
                        if role not in all_roles:
                            all_roles[role] = {}
                        if group_data['name'] not in all_roles[role]:
                            all_roles[role][group_data['name']] = 0
                        all_roles[role][group_data['name']] += 1

            role_counts = {}
            for role, counts in all_roles.iteritems():
                role_counts[role] = 0
                for group, count in counts.iteritems():
                    role_counts[role] = max(role_counts[role], count)

            if all_roles or all_net_groups:
                role_text = row.td('', valign='top')
            else:
                role_text = row.td(klass='title')

            group_td = {}
            for group_data in groups:
                group_text = row.td('', valign='top', colspan=str(group_data['child-count']))
                group_td[group_data['name']] = group_text
                group_text.b(group_data['name'])
                group_text.br
            role_text.br

            # Add in any Networks
            if all_net_groups:
                role_text.br
                role_text.i("Network Groups")
                role_text.br
                for group_data in groups:
                    group_text = group_td[group_data['name']]
                    group_text.br
                    if 'networks' in group_data:
                        group_text.i("Networks")
                    else:
                        group_text.br
                    group_text.br

                for net_group in sorted(all_net_groups):
                    role_text.a(net_group, href="Networks.html#%s" % (net_group))
                    role_text.br
                    for group_data in groups:
                        group_text = group_td[group_data['name']]
                        if net_group in group_data.get('network-groups', {}):
                            group_text.text(group_data['network-groups'][net_group])
                        group_text.br

            # Add in any Servers
            if all_roles:
                role_text.br
                role_text.i("Server Roles")
                role_text.br
                for group_data in groups:
                    group_text = group_td[group_data['name']]
                    group_text.br
                    if 'servers' in group_data:
                        group_text.i("Servers")
                    group_text.br

            for role in sorted(all_roles):
                role_text.a(role, href="Server_Roles.html#%s" % role)
                for i in range(0, role_counts[role] + 1):
                    role_text.br

                for group_data in groups:
                    group_text = group_td[group_data['name']]

                    if 'servers' in group_data:
                        allocated = []
                        free = []
                        deleted = []
                        for server in group_data['servers']:
                            s_role = server['role']
                            if s_role != role:
                                continue
                            if server['state'] == ServerState.ALLOCATED:
                                allocated.append(server)
                            elif server['state'] == ServerState.DELETED:
                                deleted.append(server)
                            else:
                                free.append(server)

                        for server in allocated:
                            group_text.a("%s" % server['id'],
                                         href="Servers/%s.html" % server['id'])
                            group_text.text("%s(%s)" % (SP * 2, server['hostname']), escape=False)
                            group_text.br

                        for server in deleted:
                            group_text.a("%s" % server['id'],
                                         href="Servers/%s.html" % server['id'])
                            group_text.br

                        for server in free:
                            group_text.a("%s" % server['id'],
                                         href="Servers/%s.html" % server['id'])
                            group_text.br

                    for i in range(0, role_counts[role] - len(allocated + free) + 1):
                        group_text.br

            children = []
            for group_data in groups:
                for child_group in group_data.get('groups', []):
                    children.append(child_group)

            if children:
                _add_row(table, children)

        h = self._create_page()

        # Build a list of all the top level groups
        top_level_groups = {}
        for group_name, group_data in self.server_groups.iteritems():
            top_level_groups[group_name] = group_data
        for group_name, group_data in self.server_groups.iteritems():
            for child in group_data.get('server-groups', []):
                del top_level_groups[child]

        top_groups = []
        for group_name, group_data in top_level_groups.iteritems():
            _count_children(group_data)
            top_groups.append(group_data)

        # Turn it into a list

        table = h.table()
        _add_row(table, top_groups)

        file_name = "%s/Server_Groups.html" % (self._file_path)
        self.add_artifact(file_name, ArtifactMode.CREATED)
        fp = open(file_name, 'w')
        fp.write(str(h))
        fp.close
