#
# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
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


class CpuModelValidator(ValidatorPlugin):
    def __init__(self, instructions, config_files):
        super(CpuModelValidator, self).__init__(
            2.0, instructions, config_files,
            'cpu-model-2.0')
        self._valid = False
        LOG.info('%s()' % KenLog.fcn())

    def validate(self):
        LOG.info('%s()' % KenLog.fcn())

        version = float(self.version())

        input = self._create_content(version, "cpu-models")

        # Resource assigments are options
        if not input:
            return True

        self._valid = self.validate_schema(input, "cpu_models")

        if self._valid:
            cpu_models = input['cpu-models']
            components = self._get_dict_from_config_value(version, 'service-components')
            self._validate_names(cpu_models)
            for model in cpu_models:
                self._validate_components(model, components)
                self._validate_cpu(model)
                self._validate_vm_size(model)

        return self._valid

    def _validate_names(self, models):

        #
        # Check each model is only defined once
        #
        names = set()
        for model in models:
            if model['name'] in names:
                msg = ("CPU Model '%s' is defined more than once." %
                       (model['name']))
                self.add_error(msg)
                self._valid = False
            else:
                names.add(model['name'])

    def _validate_vm_size(self, model):
        if 'vm-size' in model:
            vm_cores = model['vm-size']['vcpus']
            vm_cores_reqd = 1
            for service_data in model.get('assignments', []):
                for cpu_data in service_data.get('cpu', []):
                    vm_cores_reqd = max(vm_cores_reqd, sorted(cpu_data['processor-ids'])[-1] + 1)
            if vm_cores < vm_cores_reqd:
                msg = ("CPU model '%s' has a 'vm-size' stanza that doesn't specify "
                       "enough vcpus.  Please increase to at least %s" %
                       (model['name'], vm_cores_reqd))
                self.add_error(msg)
                self._valid = False

    def _validate_components(self, model, components):

        comp_set = set()
        for service_data in model.get('assignments', []):
            for comp_name in service_data.get('components', []):
                if comp_name not in components:
                    msg = ("Invalid component '%s' in CPU model '%s'."
                           % (comp_name, model['name']))
                    self.add_error(msg)
                    self._valid = False
                    continue

                if comp_name in comp_set:
                    msg = ("Component '%s' listed more than once in CPU model '%s'."
                           % (comp_name, model['name']))
                    self.add_error(msg)
                    self._valid = False
                    continue
                else:
                    comp_set.add(comp_name)

                component = components[comp_name]
                supported_allocations = component.get('supported-resource-allocations', {})
                if not supported_allocations:
                    msg = ("Component '%s' in CPU model '%s' does not support "
                           "resource allocations." % (comp_name, model['name']))
                    self.add_error(msg)
                    self._valid = False
                    continue

                if 'cpu' in service_data:
                    if not supported_allocations.get('cpu', False):
                        msg = ("Component '%s' in CPU model '%s' does not support "
                               "cpu resource allocations." % (comp_name, model['name']))
                        self.add_error(msg)
                        self._valid = False
                    else:
                        for cpu_data in service_data['cpu']:
                            if cpu_data['role'] not in supported_allocations['cpu-roles']:
                                msg = ("Component '%s' in CPU model '%s' does not support "
                                       "cpu resource allocations for role '%s'. "
                                       "Supported roles are: %s"
                                       % (comp_name, model['name'], cpu_data['role'],
                                          str(supported_allocations['cpu-roles']).strip('[]')))
                                self.add_error(msg)
                                self._valid = False

    def _validate_cpu(self, model):

        def _is_int(context, id):
            if id.isdigit():
                return True
            else:
                msg = ("'%s' in CPU model '%s' is not a valid "
                       "Processor ID" % (id, context))
                self.add_error(msg)
                self._valid = False
                return False

        def _invalid_range(context, r):
            msg = ("'%s' in CPU model '%s' is not a valid range." %
                   (r, context))
            self.add_error(msg)
            self._valid = False

        def _get_cpu_list(context, cpu_ids):
            cpus = []
            for r in str(cpu_ids).split(","):
                if "-" in r:
                    x = r.split("-")
                    if len(x) == 2:
                        start = x[0]
                        end = x[1]
                        if not start or not end:
                            _invalid_range(context, r)
                            continue

                        r_context = "%s '%s'" % (context, r)
                        if _is_int(r_context, start) and _is_int(r_context, end):
                            if int(start) < int(end):
                                cpus.extend(range(int(start), int(end) + 1))
                            else:
                                _invalid_range(context, r)
                    else:
                        _invalid_range(context, r)
                else:
                    if _is_int(context, r):
                        cpus.append(int(r))

            return cpus

        server_cpus = []
        for service_data in model.get('assignments', []):
            context = "%s:%s" % (model['name'], service_data['components'])
            for cpu_data in service_data.get('cpu', []):
                cpu_list = _get_cpu_list(context, cpu_data['processor-ids'])
                for cpu_id in cpu_list:
                    if cpu_id not in server_cpus:
                        server_cpus.append(cpu_id)
                    else:
                        msg = ("Processor id '%s' is assigned more than once in "
                               "CPU model %s" %
                               (cpu_id, model['name']))
                        self.add_error(msg)
                        self._valid = False

                cpu_data['processor-id-string'] = cpu_data['processor-ids']
                cpu_data['processor-ids'] = cpu_list

    @property
    def instructions(self):
        return self._instructions

    def get_dependencies(self):
        return ['service-components-2.0']
