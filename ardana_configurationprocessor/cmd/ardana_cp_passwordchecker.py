#
# (c) Copyright 2015 Hewlett Packard Enterprise Development LP
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
import sys
import getpass

from ardana_configurationprocessor.cp.model.CPSecurityHelper \
    import CPSecurityHelper


def main():
    try:
        password = sys.argv[1]
    except Exception:
        password = getpass.getpass(
            'Enter the current key to be used for decryption: ')

    ksh = CPSecurityHelper()
    score, status = ksh.calculate_complexity(password)
    print('Your score is: %d' % score)
    print('Your status is: %s' % status)
    return 0


if __name__ == "__main__":
    sys.exit(main())
