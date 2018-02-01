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


class InterfaceModels(object):

    def render_iface_models(self):

        h = self._create_page()
        h.h2("Interface Models")
        for model in self.iface_models:
            model_name = h.h3()
            model_name.a(model['name'], name=model['name'])
            iface_table = h.table()

            title_row = iface_table.tr()
            title_row.td("Network Group", klass="title")
            title_row.td("Interface", colspan='3', klass="title")

            for iface in model.get('network-interfaces', []):
                iface_row = iface_table.tr
                bond_data = iface.get('bond-data', {})
                if bond_data:
                    net_td = iface_row.td(valign='top',
                                          rowspan=str(len(bond_data['devices'])))
                    iface_row.td(iface['device']['name'],
                                 rowspan=str(len(bond_data['devices'])))
                    first_row = True
                    for dev in bond_data.get('devices', []):
                        iface_row.td(dev['name'])
                        if first_row:
                            first_row = False
                            bond_td = iface_row.td(valign='top',
                                                   rowspan=str(len(bond_data['devices'])))
                            iface_row = iface_table.tr

                    bond_opts = bond_td.table(klass='tab')
                    provider_row = bond_opts.tr()
                    provider_row.td('provider:', klass='tab')
                    provider_row.td(bond_data['provider'], klass='tab')
                    for opt, opt_val in bond_data.get('options', {}).iteritems():
                        options_row = bond_opts.tr()
                        options_row.td(opt, klass='tab')
                        options_row.td(str(opt_val), klass='tab')
                else:
                    net_td = iface_row.td(valign='top')
                    td = iface_row.td('', colspan='3')
                    td.text(iface['device']['name'])
                    if 'vf-count' in iface['device']:
                        td.br
                        td.text("%svf-count: %s" % (SP * 4, iface['device']['vf-count']), escape=False)
                    if 'sriov-only' in iface['device']:
                        td.br
                        td.text("%sSR-IOV Only" % (SP * 4), escape=False)
                    if 'pci-pt' in iface['device']:
                        td.br
                        td.text("%sPCI-PT" % (SP * 4), escape=False)

                for group in (iface.get('network-groups', []) +
                              iface.get('forced-network-groups', [])):
                    net_td.a(group, href="Networks.html#%s" % group)
                    net_td.br

            if 'dpdk-devices' in model:
                title_row = iface_table.tr()
                title_row = iface_table.tr()
                title_row.td("DPDK Devices", klass="title")
                title_row.td("Components", klass="title")
                title_row.td("EAL Options", klass="title")
                title_row.td("Component Options", klass="title")

                for dpdk_data in model['dpdk-devices']:
                    row = iface_table.tr()

                    td = row.td()
                    for device in dpdk_data.get('devices', []):
                        td.text("%s (%s)" % (device['name'],
                                             device.get('driver', 'igb_uio')))
                        td.br

                    td = row.td()
                    for comp_name in dpdk_data.get('components', []):
                        td.text("%s" % (comp_name))
                        td.br

                    td = row.td()
                    opts = td.table(klass='tab')
                    for opt in dpdk_data.get('eal-options', []):
                        opt_row = opts.tr()
                        td = opt_row.td(opt['name'], klass='tab')
                        td = opt_row.td(opt['value'], klass='tab')

                    td = row.td()
                    opts = td.table(klass='tab')
                    for opt in dpdk_data.get('component-options', []):
                        opt_row = opts.tr()
                        td = opt_row.td(opt['name'], klass='tab')
                        td = opt_row.td(opt['value'], klass='tab')

            used_by = h.table(klass='used_by')
            used_by.tr
            used_by.td("Used By:", klass='used_by')
            for role in self.server_roles:
                if role['interface-model'] == model['name']:
                    role_link = used_by.td(klass='used_by')
                    role_link.a(role['name'], href="Server_Roles.html#%s" % role['name'])
            h.br
            h.br
        h.br

        file_name = "%s/Interface_Models.html" % (self._file_path)
        self.add_artifact(file_name, ArtifactMode.CREATED)
        fp = open(file_name, 'w')
        fp.write(str(h))
        fp.close
