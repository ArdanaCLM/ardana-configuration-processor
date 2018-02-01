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
import re
from stevedore import driver

from ardana_configurationprocessor.cp.model.StatePersistor \
    import StatePersistor
from ardana_configurationprocessor.cp.model.Version \
    import Version
from ardana_configurationprocessor.cp.model.CPSecurity \
    import CPSecurity


class ArdanaVariable(object):
    @staticmethod
    def generate_value(instructions, models, controllers, name, value,
                       warnings, errors, payload=None):

        if not isinstance(value, str):
            return value

        if value.count('%') != 2:
            return value

        cp = payload['context'].get('cp')

        sp = StatePersistor(models, controllers, 'private_data_%s.yml' % cp)
        sp_old = StatePersistor(models, controllers, 'private_data_old_working_%s.yml' % cp)
        sp_non_scoped = StatePersistor(models, controllers, 'private_data.yml')
        #
        # Set-up a work-space in persistent state to hold the values of all variables with
        # scope cloud.  This is a temporary workspace that is not written out to disk.  The
        # cloud scoped variables are persisted in the private_data spaces of the control
        # planes on which the variables are defined.  We use this temporary workspace in a
        # couple of ways:
        #    We use it to populate cloud-scoped variables when we regenerate their values -
        #  we don't know which control-plane will get to regenerate their value so the first
        #  time we regenerate the value we store it in this temporary workspace
        #    We use it to determine which variables are cloud-scoped, and write the names of
        #  these variables out to private_data_cloud_variables.yml in PersistentStateBuilder.
        #    We also write the metadata for cloud scoped variables to their own informational
        #  file.
        #
        sp_cloud = StatePersistor(models, controllers, 'private_data_cloud.yml')

        try:
            key_name = payload['key-name']
        except (TypeError, KeyError):
            key_name = name

        ArdanaVariable.process_immutability(instructions, models, controllers, payload, value)

        ri, user_supplied = ArdanaVariable._check_for_existing_process_creds_change(instructions,
                                                                                    models,
                                                                                    key_name,
                                                                                    payload, sp,
                                                                                    sp_old,
                                                                                    sp_non_scoped)
        if (ri is not None and ri != {}) and not user_supplied:
            if payload['scope'] == 'cloud':
                sp_cloud.persist_info({key_name: ri})
            return ri
        elif (ri is None or ri == {} and ri != '0') and not user_supplied:
            ri, success = ArdanaVariable._generate_new_value(instructions, models, controllers,
                                                             key_name, value, payload, warnings)
            if ri is None:
                return None
            elif not success:
                return ri

        if payload['scope'] == 'cloud':
            sp_cloud.persist_info({key_name: ri})
        value = ri

        context = payload.get('context')
        meta_data = sp.recall_info(["%s__metadata" % key_name])
        if meta_data:
            meta_data = ArdanaVariable._add_context_to_meta(meta_data, context=context)
        else:
            meta_data = [context]

        if 'encryption_key' in instructions:
            key = instructions['encryption_key']
            secure_value = CPSecurity.encrypt(key, value)
            is_secure_val = True
        else:
            secure_value = value
            is_secure_val = False

        ArdanaVariable.persist_value(sp, key_name, secure_value, is_secure_val,
                                     meta_data=meta_data)

        return value

    @staticmethod
    def get_old_value(instructions, models, controllers, name, value, warnings, errors,
                      payload=None):

        if not isinstance(value, str):
            return None

        if value.count('%') != 2:
            return None

        try:
            key_name = payload['key-name']
        except (TypeError, KeyError):
            key_name = name

        cp = payload['context'].get('cp')

        sp_old = StatePersistor(models, controllers, 'private_data_old_working_%s.yml' % cp)
        sp_old_disk = StatePersistor(models, controllers, 'private_data_old_%s.yml' % cp)
        sp_old_disk_non_scoped = StatePersistor(models, controllers, 'private_data_old.yml')

        ri = sp_old.recall_info([key_name])
        ri_e = sp_old.recall_info(['%s__is_secure' % key_name])

        if ri is None or ri == {}:
            ri_d = sp_old_disk.recall_info([key_name])
            ri_d_e = sp_old_disk.recall_info(['%s__is_secure' % key_name])

            if ri_d is None or ri_d == {}:
                ri_d = sp_old_disk_non_scoped.recall_info([key_name])
                ri_d_e = sp_old_disk_non_scoped.recall_info(['%s__is_secure' % key_name])

            if (ri_d is not None and ri_d != {}) and not ri_d_e:
                ArdanaVariable._encrypt(sp_old_disk, instructions, key_name, ri_d)
                return ri_d
            elif (ri_d is not None and ri_d != {}) and ri_d_e:
                return ArdanaVariable.decrypt_value(ri_d, instructions)
            else:
                return None

        if not ri_e:
            ArdanaVariable._encrypt(sp_old, instructions, key_name, ri)
            return ri
        elif ri_e:
            return ArdanaVariable.decrypt_value(ri, instructions)

    @staticmethod
    def _encrypt(sp, instructions, key, value):
        if 'encryption_key' in instructions:
            encrypt = instructions['encryption_key']
            secure_value = CPSecurity.encrypt(encrypt, value)
            ArdanaVariable.persist_value(sp, key, secure_value, True, meta_data=None)

    @staticmethod
    def _generate_new_value(instructions, models, controllers, name, value, payload, warnings):
        #
        # Set-up a work-space in persistent state to hold the values of all variables with
        # scope cloud.  This is a temporary workspace that is not written out to disk.  The
        # cloud scoped variables are persisted in the private_data spaces of the control
        # planes on which the variables are defined.  We use this temporary workspace in a
        # couple of ways:
        #    We use it to populate cloud-scoped variables when we regenerate their values -
        #  we don't know which control-plane will get to regenerate their value so the first
        #  time we regenerate the value we store it in this temporary workspace
        #    We use it to determine which variables are cloud-scoped, and write the names of
        #  these variables out to private_data_cloud_variables.yml in PersistentStateBuilder.
        #    We also write the metadata for cloud scoped variables to their own informational
        #  file.
        #
        sp_cloud = StatePersistor(models, controllers, 'private_data_cloud.yml')
        p1 = value.find('%') + 1
        p2 = value.rfind('%')
        variable_type = value[p1:p2]

        version = instructions['model_version']
        version = Version.normalize(version)
        if float(version) > 1.0:
            variable_type += '-%s' % version

        #
        # Search for existing values in all instances of private_data_<control-plane>
        # To do this we exclude all instances of private_data_old,
        # private_data_old_<control-plane>, private_data_encryption_validator
        # and private_data_cloud
        #
        values = []
        pattern = re.compile('^private_data_((?!old.*)(?!encryption.)(?!cloud.*))')
        for key, v in models['persistent_state'].iteritems():
            if re.search(pattern, key):
                if name in v:
                    values.append(v.get(name))

        if payload['scope'] == 'cloud':
            regen, ri_u = ArdanaVariable._check_for_user_supplied_secret(models, payload, name)
            if regen:
                val = sp_cloud.recall_info([name])
                if val or val == 0:
                    return val, True
            elif not regen and values:
                sp_cloud.persist_info({name: values[0]})
                return values[0], True

        value, success = ArdanaVariable._generate(instructions, models, controllers, name,
                                                  variable_type, value, payload, warnings)

        if not success or not values:
            if payload['scope'] == 'cloud' and success:
                sp_cloud.persist_info({name: value})
            return value, success

        while value in values:
            value, success = ArdanaVariable._generate(instructions, models, controllers, name,
                                                      variable_type, value, payload, warnings)

        return value, success

    @staticmethod
    def _generate(instructions, models, controllers, name, variable_type, value, payload, warnings):
        try:
            namespace = 'ardana.configurationprocessor.variable'

            mgr = driver.DriverManager(
                namespace=namespace, name=variable_type, invoke_on_load=True,
                invoke_args=(instructions, models, controllers))

        except RuntimeError as e:
            return value, False

        value = mgr.driver.calculate(payload)

        if not mgr.driver.ok:
            msg = 'Variable %s Failed to complete for name %s:\n' % (
                  variable_type, name)
            for e in mgr.driver.errors:
                msg += '\t%s\n' % e
            ArdanaVariable._add_warning(warnings, msg)
            return None, False

        return value, True

    @staticmethod
    def encrypt_and_persist_value(sp, instructions, key_name, value, encrypted, meta_data=None):
        if 'encryption_key' in instructions and not encrypted:
            key = instructions['encryption_key']
            secure_value = CPSecurity.encrypt(key, value)
            ArdanaVariable.persist_value(sp, key_name, secure_value, True, meta_data=meta_data)
        else:
            ArdanaVariable.persist_value(sp, key_name, value, encrypted, meta_data=meta_data)

    @staticmethod
    def process_immutability(instructions, models, controllers, payload, value):
        if 'immutable' not in payload:
            p1 = value.find('%') + 1
            p2 = value.rfind('%')
            variable_type = value[p1:p2]

            version = instructions['model_version']
            version = Version.normalize(version)
            if float(version) > 1.0:
                variable_type += '-%s' % version

            try:
                namespace = 'ardana.configurationprocessor.variable'

                mgr = driver.DriverManager(
                    namespace=namespace, name=variable_type, invoke_on_load=True,
                    invoke_args=(instructions, models, controllers))

            except RuntimeError:
                payload['immutable'] = False
                return

            payload['immutable'] = mgr.driver.is_immutable()
            return

    @staticmethod
    def _check_for_existing_process_creds_change(instructions, models, key_name,
                                                 payload, sp, sp_old, sp_non_scoped):

        ri = sp.recall_info([key_name])
        ri_m = sp.recall_info(["%s__metadata" % key_name])
        ri_e = ArdanaVariable.was_persisted_value_encrypted(sp, key_name)

        if not ri and ri != 0:
            ri = sp_non_scoped.recall_info([key_name])
            ri_m = sp_non_scoped.recall_info(["%s__metadata" % key_name])
            ri_e = ArdanaVariable.was_persisted_value_encrypted(sp_non_scoped, key_name)

        if ri and payload.get('immutable'):
            context = payload.get('context')
            ri_m = ArdanaVariable._add_context_to_meta(ri_m, context=context) if ri_m else [context]
            ArdanaVariable.encrypt_and_persist_value(sp, instructions, key_name,
                                                     ri, ri_e, meta_data=ri_m)
            if ri_e:
                return ArdanaVariable.decrypt_value(ri, instructions), False
            else:
                return ri, False

        if not instructions['refresh_all_secrets']:
            regen, ri_u = ArdanaVariable._check_for_user_supplied_secret(models, payload, key_name)
        else:
            regen = True
            ri_u = None

        ri_o = sp_old.recall_info([key_name])

        if ri_u is not None:
            if (ri_o is None or ri_o == {}) and ri is not None:
                ArdanaVariable.encrypt_and_persist_value(sp_old, instructions, key_name,
                                                         ri, ri_e, meta_data=ri_m)
            return ri_u, True

        #
        # If we've generated metadata, we know that the value has already been regenerated
        #
        if (not regen) or ri_m:
            context = payload.get('context')
            ri_m = ArdanaVariable._add_context_to_meta(ri_m, context=context) if ri_m else [context]
            if (ri is not None and ri != {}) and not ri_e:
                ArdanaVariable.encrypt_and_persist_value(sp, instructions, key_name,
                                                         ri, ri_e, meta_data=ri_m)
                return ri, False
            elif (ri is not None and ri != {}) and ri_e:
                ArdanaVariable.encrypt_and_persist_value(sp, instructions, key_name,
                                                         ri, ri_e, meta_data=ri_m)
                return ArdanaVariable.decrypt_value(ri, instructions), False
            else:
                return ri, False
        else:
            if (ri_o is None or ri_o == {}) and ri is not None:
                ArdanaVariable.encrypt_and_persist_value(sp_old, instructions, key_name,
                                                         ri, ri_e, meta_data=ri_m)
            return None, False

        return None, False

    @staticmethod
    def _add_context_to_meta(meta_data, context=None):
        if context:
            not_there = True
            for meta in meta_data:
                unmatched = cmp(meta, context)
                if unmatched == 0:
                    not_there = False
            if not_there:
                meta_data.append(context)
        return meta_data

    @staticmethod
    def _check_for_user_supplied_secret(models, payload, key):
        if 'user_creds_change' in models:
            cp = payload['context'].get('cp')
            if cp in models['user_creds_change']:
                if key in models['user_creds_change'][cp]:
                    if 'value' in models['user_creds_change'][cp][key]:
                        value = models['user_creds_change'][cp][key].get('value')
                        return False, value
                    else:
                        return True, None
        return False, None

    @staticmethod
    def _add_warning(warnings, warning):
        if warning not in warnings:
            warnings.append(warning)

    @staticmethod
    def _add_error(errors, error):
        if error not in errors:
            errors.append(error)

    @staticmethod
    def persist_value(sp, name, secure_value, is_secure_val, meta_data=None):
        pi = {name: secure_value}
        is_secure = '%s__is_secure' % name
        pi[is_secure] = is_secure_val
        if meta_data:
            meta = '%s__metadata' % name
            pi[meta] = meta_data

        sp.persist_info(pi)

    @staticmethod
    def was_persisted_value_encrypted(sp, property_name):
        secure_property_name = '%s__is_secure' % property_name

        value = sp.recall_info([secure_property_name])
        if value is None:
            return False

        return value is not False

    @staticmethod
    def decrypt_value(value, instructions):
        return CPSecurity.decrypt(instructions['encryption_key'], value)
