# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
# (c) Copyright 2017-2018 SUSE LLC
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import logging
import logging.config

from ardana_configurationprocessor.cp.model.CPLogging import \
    CPLogging as KenLog
from ardana_configurationprocessor.cp.model.GeneratorPlugin \
    import GeneratorPlugin
from ardana_configurationprocessor.cp.model.v2_0.CloudModel \
    import CloudModel


LOG = logging.getLogger(__name__)


class CertGenerator(GeneratorPlugin):
    def __init__(self, instructions, models, controllers):
        super(CertGenerator, self).__init__(
            2.0, instructions, models, controllers,
            'cert-generator-2.0')
        LOG.info('%s()' % KenLog.fcn())

        cloud_internal = CloudModel.internal(self._models['CloudModel'])
        self.control_planes = CloudModel.get(cloud_internal, 'control-planes', {})
        self.components = CloudModel.get(cloud_internal, 'components', {})

    def generate(self):

        #
        # Generate a host cert for a aserver, and if the server hosts a load balancer
        # add it to the list of targte hosts for that load balancer cert
        #
        def _process_server(server, lb_certs, host_certs, service_certs, cp_endpoints, cp_name):
            host_certs.append(self._generate_host_cert(server, service_certs, cp_endpoints, cp_name))
            for provider, certs in lb_certs.iteritems():
                if provider in server['components']:
                    for cert, cert_data in certs.iteritems():
                        cert_data['ansible_hosts'].append(server['ardana_ansible_host'])

        LOG.info('%s()' % KenLog.fcn())

        self._action = KenLog.fcn()

        for cp_name, cp in self.control_planes.iteritems():

            # Generate the cert data for any load balancers
            service_certs = {}
            lb_certs = self._generate_lb_certs(cp['load-balancer-config'], service_certs, cp_name)

            host_certs = []
            for cluster in cp['clusters']:
                for server in cluster.get('servers', []):
                    _process_server(server, lb_certs, host_certs, service_certs,
                                    cp['endpoints'], cp_name)

            for r_name, r in cp.get('resources', {}).iteritems():
                for server in r.get('servers', []):
                    _process_server(server, lb_certs, host_certs, service_certs,
                                    cp['endpoints'], cp_name)

            # This is used to produce a cert_data entry under the component stanza
            # in group_vars.  It can be removed once the playbooks have been updated
            # to generate ilb certs data from the new service cert data in group_vars all
            cp['lb-cert-data'] = lb_certs

            # Create a service cert entry for the load balancer certs, so that they
            # can be processed as any other service certs
            for comp_name, certs in lb_certs.iteritems():
                for cert_name, cert_data in certs.iteritems():
                    self._create_or_update_service_cert(comp_name, cp_name, service_certs,
                                                        ansible_hosts=cert_data['ansible_hosts'],
                                                        names=cert_data['names'],
                                                        addresses=cert_data['vips'],
                                                        cert_name=cert_name)

            # Add the cert data to the control plane
            cp['cert-data'] = {'hosts': host_certs,
                               'services': service_certs}

    #
    # Generate cert data for a set of load balancers.  If there is a service
    # that appears as a TLS VIP but tls is not terminated at the load balancer
    # then create an entry for that in the set of service_certs as teh VIP name
    # and address will need to be in that cert.
    #
    def _generate_lb_certs(self, load_balancers, service_certs, cp_name):

        lb_certs = {}

        for lb_provider, lb_data in load_balancers.iteritems():

            if lb_provider not in lb_certs:
                lb_certs[lb_provider] = {}

            for comp_name, comp_data in lb_data.iteritems():
                for net_data in comp_data['networks']:
                    if 'cert-file' not in net_data:
                        continue

                    if net_data['cert-file'] not in lb_certs[lb_provider]:
                        lb_certs[lb_provider][net_data['cert-file']] = {'names': [],
                                                                        'vips': [],
                                                                        'ansible_hosts': []}
                    cert_data = lb_certs[lb_provider][net_data['cert-file']]

                    if 'external-name' in net_data:
                        if net_data['external-name'] not in cert_data['names']:
                            cert_data['names'].append(net_data['external-name'])

                    # Only add data for VIp entries we terminate TLS for
                    if net_data['vip-tls'] and net_data['vip-tls-terminator']:
                        if net_data['hostname'] not in cert_data['names']:
                            cert_data['names'].append(net_data['hostname'])

                        if net_data['ip-address'] not in cert_data['vips']:
                            cert_data['vips'].append(net_data['ip-address'])

                        for role, alias in net_data['aliases'].iteritems():
                            # Only add an alias if its not already in hosts
                            if alias not in cert_data['names']:
                                cert_data['names'].append(alias)

                    elif comp_data['host-tls'] and not net_data['vip-tls-terminator']:
                        #
                        # If the service is passing TLS through the LB then we need
                        # to create a cert for the service which will be installed
                        # on the servers.
                        #
                        ansible_hosts = [host['ardana_ansible_host'] for host in comp_data['hosts']]
                        names = [alias for role, alias in net_data['aliases'].iteritems()]

                        self._create_or_update_service_cert(comp_name, cp_name, service_certs,
                                                            ansible_hosts=ansible_hosts,
                                                            names=names,
                                                            addresses=[net_data['ip-address']])

        return lb_certs

    #
    # Create a service cert is if doesn't already exist
    # Update it to include a list of ansible hosts, names and ip addresses
    #
    def _create_or_update_service_cert(self, comp_name, cp_name, service_certs,
                                       ansible_hosts, names, addresses,
                                       cert_name=None):

        if not cert_name:
            cert_name = "%s-%s-internal-cert" % (cp_name, comp_name)

        # See if we already have a cert with this name
        for cert in service_certs.get(comp_name, []):
            if cert['cert_name'] == cert_name:
                service_cert = cert
                break
        else:
            if comp_name not in service_certs:
                service_certs[comp_name] = []

            service_cert = {'cert_name': cert_name,
                            'names': [],
                            'ips': [],
                            'ansible_hosts': []}
            service_certs[comp_name].append(service_cert)

        for host in ansible_hosts:
            if host not in service_cert['ansible_hosts']:
                service_cert['ansible_hosts'].append(host)

        for name in names:
            if name not in service_cert['names']:
                service_cert['names'].append(name)

        for addr in addresses:
            if addr not in service_cert['ips']:
                service_cert['ips'].append(addr)

    #
    # Generate the host cert data for a server.  Include all names and IP
    # addresses configured for the server.
    #
    # If there are any conponents on the server that do thier own TLS
    # termination then add the address and name for that service to the
    # service cert
    #
    def _generate_host_cert(self, server, service_certs, cp_endpoints, cp_name):

        host_cert = {'ansible_host': server['ardana_ansible_host'],
                     'names': [],
                     'ips': []}

        for iface_name, iface_data in server['interfaces'].iteritems():
            for net_name, net_data in iface_data.get('networks', {}).iteritems():
                if 'addr' in net_data:
                    host_cert['names'].append(net_data['hostname'])
                    host_cert['ips'].append(net_data['addr'])

        # Need to see if any compoents terminate tls here
        for comp_name in server['components']:
            for ep_role, ep_list in cp_endpoints.get(comp_name, {}).iteritems():
                for ep_data in ep_list:
                    if ep_data['bind']['tls']:
                        for member in ep_data['access'].get('members', []):
                            if member['ardana_ansible_host'] == server['ardana_ansible_host']:
                                self._create_or_update_service_cert(comp_name, cp_name, service_certs,
                                                                    ansible_hosts=[member['ardana_ansible_host']],
                                                                    names=[member['hostname']],
                                                                    addresses=[member['ip_address']])

        return host_cert

    def get_dependencies(self):
        return ['encryption-key',
                'internal-model-2.0',
                'cloud-cplite-2.0']
