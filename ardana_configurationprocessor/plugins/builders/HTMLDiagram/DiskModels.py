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


class DiskModels(object):

    def render_disk_model(self, h, disk_model):

        table = h.table()

        for vg in disk_model.get('volume-groups', []):
            disk_row = table.tr
            disk_row.td(vg['name'])

            lv_td = disk_row.td
            lv_table = lv_td.table(klass='tab')
            lv_row = lv_table.tr
            for key in ['mount', 'size', 'fstype', 'mkfs-opts']:
                lv_row.td(key, style="font-weight:bold", klass='tab')
            for lv in vg['logical-volumes']:
                lv_row = lv_table.tr
                for key in ['mount', 'size', 'fstype', 'mkfs-opts']:
                    val = lv_row.td(klass='tab')
                    if key in lv:
                        val.text(str(lv[key]))

            device_td = disk_row.td
            device_table = device_td.table(klass='tab')
            for pv in vg['physical-volumes']:
                device_table.tr
                device_table.td(pv, klass='tab')

        for dev_group in disk_model.get('device-groups', []):
            disk_row = table.tr
            disk_row.td(dev_group['name'])
            disk_row.td(dev_group['consumer']['name'])
            device_td = disk_row.td
            device_table = device_td.table(klass='tab')
            for dev in dev_group['devices']:
                device_table.tr
                device_table.td(dev['name'], klass='tab')

    def render_disk_models(self):

        h = self._create_page()

        h.h2("Disk Models")
        for model in self.disk_models:
            model_name = h.h3()
            model_name.a(model['name'], name=model['name'])

            self.render_disk_model(h, model)

            used_by = h.table(klass='used_by')
            used_by.tr
            used_by.td("Used By:", klass='used_by')
            for role in self.server_roles:
                if role.get('disk-model', "") == model['name']:
                    role_link = used_by.td(klass='used_by')
                    role_link.a(role['name'], href="Server_Roles.html#%s" % role['name'])

            h.br
            h.br

        file_name = "%s/Disk_Models.html" % (self._file_path)
        self.add_artifact(file_name, ArtifactMode.CREATED)
        fp = open(file_name, 'w')
        fp.write(str(h))
        fp.close
