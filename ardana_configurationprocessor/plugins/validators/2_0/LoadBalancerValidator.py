#
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

from ardana_configurationprocessor.cp.model.ValidatorPlugin \
    import ValidatorPlugin
from ardana_configurationprocessor.cp.model.CPLogging \
    import CPLogging as KenLog


LOG = logging.getLogger(__name__)


class LoadBalancerValidator(ValidatorPlugin):
    def __init__(self, instructions, config_files):
        super(LoadBalancerValidator, self).__init__(
            2.0, instructions, config_files,
            'load-balancer-2.0')
        LOG.info('%s()' % KenLog.fcn())
        self._valid = True

    def validate(self):
        LOG.info('%s()' % KenLog.fcn())
        version = float(self.version())

        # Note Schema validation is performed as part of network-groups and
        # control planes

        control_planes = self._get_config_value(version, 'control-planes')

        components = self._get_dict_from_config_value(version, 'service-components')

        network_groups = self._get_dict_from_config_value(version, 'network-groups')

        # Build a list of the load balancers defined in network groups
        netgroup_load_balancers = []
        netgroup_by_lb_name = {}
        for netgroup_name, netgroup in network_groups.iteritems():
            for lb in netgroup.get('load-balancers', []):
                if isinstance(lb, dict):
                    # In previous versions of Ardana OpenStack load balancers were defined as part
                    # of the network group
                    lb['network-group'] = netgroup_name
                    netgroup_load_balancers.append(lb)
                else:
                    if lb in netgroup_by_lb_name:
                        msg = ("load balancer '%s' is specifed as being attached to more that one "
                               "network group: '%s' and '%s'" %
                               (lb, netgroup_by_lb_name[lb], netgroup_name))
                        self.add_error(msg)
                        self._valid = False
                    else:
                        netgroup_by_lb_name[lb] = netgroup_name

        # Check we only have loadbalacers in control planes or network groups
        cp_load_balancers = []
        for cp in control_planes:
            if 'load-balancers' in cp:
                cp_load_balancers.append(cp['name'])

        if netgroup_load_balancers:
            if cp_load_balancers:
                msg = ("Load Balancers cannot be defined in both network-groups "
                       "and control-planes.")
                self.add_error(msg)
                self._valid = False
            else:
                if len(control_planes) > 1:
                    msg = ("Load Balancers cannot be defined in network-groups "
                           "when the cloud contains more than one control-plane.")
                    self.add_error(msg)
                    self._valid = False

        for cp in control_planes:
            self._create_load_balancers(cp, netgroup_load_balancers, netgroup_by_lb_name)
            self._validate_lb_provider(cp, components)
            self._validate_lb_components(cp, components)
            self._validate_lb_roles(cp)

        self._validate_lb_certs(control_planes)
        self._validate_lb_external_name(control_planes)

        LOG.info('%s()' % KenLog.fcn())
        return self._valid

    #
    # Validate Load Balancers
    #
    def _create_load_balancers(self, cp, netgroup_load_balancers, netgroup_by_lb_name):

        if 'load-balancers' in cp:

            # Convert to a flattened list where the provider is an
            # attribute and add the network group name
            lb_names = set()
            for lb in cp['load-balancers']:

                if lb['name'] not in lb_names:
                    lb_names.add(lb['name'])
                else:
                    msg = ("Control Plane '%s': "
                           "load balancer '%s' defined more than once" %
                           (cp['name'], lb['name']))
                    self.add_error(msg)
                    self._valid = False
                    continue

                lb['defined-in-cp'] = True
                if lb['name'] in netgroup_by_lb_name:
                        lb['network-group'] = netgroup_by_lb_name[lb['name']]
                else:
                    msg = ("Control Plane '%s': "
                           "load balancer '%s' is not assigned to any network group" %
                           (cp['name'], lb['name']))
                    self.add_error(msg)
                    self._valid = False

        else:
            cp['load-balancers'] = netgroup_load_balancers

        # Auto generate cert file names if needed
        for lb in cp['load-balancers']:
            if 'tls-components' in lb and 'cert-file' not in lb:
                lb['cert-file'] = "%s-%s-cert" % (cp['name'], lb['name'])

    #
    # Valdate the provider for a load balancer is a known component
    # and is in the control plane
    #
    def _validate_lb_provider(self, cp, components):

        cp_components = self._get_all_cp_components(cp)
        for lb in cp['load-balancers']:
            if lb['provider'] not in components:
                msg = ("Control Plane '%s': "
                       "Unknown provider '%s' for load balancer %s." %
                       (cp['name'], lb['provider'], lb['name']))
                self.add_error(msg)
                self._valid = False
            elif lb['provider'] not in cp_components:
                msg = ("Control Plane '%s': "
                       "Provider '%s' for load balancer %s is not part of "
                       "any cluster or group in the control plane." %
                       (cp['name'], lb['provider'], lb['name']))
                self.add_error(msg)
                self._valid = False

    #
    # Check that components are valid, and that default is not used
    # more than once for the same role
    #
    def _validate_lb_components(self, cp, components):

        lb_components = {}

        for lb in cp['load-balancers']:
            for comp_name in (lb.get('components', []) +
                              lb.get('tls-component', [])):
                if comp_name != 'default' and comp_name not in components:
                    msg = ("Control Plane '%s': "
                           "Undefined component '%s' in load balancer %s." %
                           (cp['name'], comp_name, lb['name']))
                    self.add_error(msg)
                    self._valid = False
                    continue

                #
                # If the load balancer was defined as part of a control
                # plane we can also check that any
                # explicilty defined component is in the control plane
                #
                if lb.get('defined-in-cp', False):
                    cp_components = self._get_all_cp_components(cp)
                    if comp_name != 'default' and comp_name not in cp_components:
                        msg = ("Control Plane '%s': "
                               "Component '%s' in load balancer %s is not in "
                               "this control plane." %
                               (cp['name'], comp_name, lb['name']))
                        self.add_warning(msg)
                        self._valid = False
                        continue

                for role in lb.get('roles', []):
                    if role not in lb_components:
                        lb_components[role] = {}
                    if comp_name in lb_components[role]:
                        lb_components[role][comp_name].append(lb['name'])
                        if comp_name == 'default':
                            msg = ("Control Plane '%s': "
                                   "Components specified as 'default' for more than one "
                                   "load balancer with a role of %s: %s" %
                                   (cp['name'], role, sorted(lb_components[role][comp_name])))
                        else:
                            msg = ("Control Plane '%s': "
                                   "Component %s is listed for more than one "
                                   "load balancer with a role of %s: %s" %
                                   (cp['name'], comp_name, role, sorted(lb_components[role][comp_name])))
                        self.add_error(msg)
                        self._valid = False
                    else:
                        lb_components[role][comp_name] = [lb['name']]

    #
    # Validate role combinations
    #
    def _validate_lb_roles(self, cp):

        internal_found = False

        for lb in cp['load-balancers']:
            if len(lb.get('roles', [])) == 0:
                msg = ("Control Plane '%s': "
                       "Load balancer '%s' has no roles defined" %
                       (cp['name'], lb['name']))
                self.add_error(msg)
                self._valid = False
                continue

            for role in lb['roles']:
                if role == 'public':
                    if len(lb['roles']) > 1:
                        msg = ("Control Plane '%s': "
                               "Load balancer '%s' role 'public' can not be combined "
                               "with any other role." %
                               (cp['name'], lb['name']))
                        self.add_error(msg)
                        self._valid = False

                elif role in ['internal', 'default']:
                    internal_found = True

        if cp.get('load-balancers', []) and not internal_found:
            msg = ("Control Plane '%s': "
                   "No load balancer defined for role 'internal' or 'default'" %
                   (cp['name']))
            self._valid = False
            self.add_error(msg)

    #
    # Validate cert files
    #
    def _validate_lb_certs(self, control_planes):

        def _add_cert_file(certs, cert_file, cp_name, lb_name):
            if not isinstance(cert_file, str):
                msg = ("Control Plane '%s': "
                       "cert-file for load balancer '%s' is not in a recognised format." %
                       (cp_name, lb_name))
                self.add_error(msg)
                self._valid = False
                return

            if cert_file not in certs:
                certs[cert_file] = []
            certs[cert_file].append((cp_name, lb_name))

        certs = {}
        for cp in control_planes:
            for lb in cp['load-balancers']:
                if 'cert-file' in lb:
                    cert_file = lb['cert-file']
                    if isinstance(cert_file, str):
                        _add_cert_file(certs, cert_file, cp['name'], lb['name'])
                    elif isinstance(cert_file, dict):
                        for cert in cert_file.values():
                            _add_cert_file(certs, cert, cp['name'], lb['name'])

        for cert, lbs in certs.iteritems():
            if len(lbs) > 1:
                msg = ("Cert-file '%s' specified for more than one load balancer: %s" %
                       (cert, str(lbs).strip('[]')))
                self.add_error(msg)
                self._valid = False

    #
    # Validate external names
    #
    def _validate_lb_external_name(self, control_planes):

        ext_names = {}
        for cp in control_planes:
            for lb in cp['load-balancers']:
                if lb.get('external-name'):
                    if lb['external-name'] not in ext_names:
                        ext_names[lb['external-name']] = []
                    ext_names[lb['external-name']].append((cp['name'], lb['name']))

        for ext_name, lb_names in ext_names.iteritems():
            if len(lb_names) > 1:
                msg = ("External name '%s' specified for more than one load balancer: %s" %
                       (ext_name, str(lb_names).strip('[]')))
                self.add_error(msg)

    #
    # return a list of all components in a control plane
    #
    def _get_all_cp_components(self, cp):

        result = set()
        for comp in cp.get('common-service-components', []):
            result.add(comp)
        for cluster in cp.get('clusters', []):
            for comp in cluster['service-components']:
                result.add(comp)
        for r in cp.get('resources', []):
            for comp in r['service-components']:
                result.add(comp)

        return list(result)

    @property
    def instructions(self):
        return self._instructions

    def get_dependencies(self):
        return ['service-components-2.0',
                'control-planes-2.0',
                'network-groups-2.0']
