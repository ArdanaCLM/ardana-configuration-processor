#
# (c) Copyright 2019 SUSE LLC
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
from netaddr import IPAddress, AddrFormatError


def is_ipv6(address):
    try:
        ip = IPAddress(address)
        if ip.version == 6:
            return True
        else:
            return False
    except AddrFormatError:
        return False


def wrap_ip(address):
    if is_ipv6(address):
        return address.join(['[', ']'])
    return address
