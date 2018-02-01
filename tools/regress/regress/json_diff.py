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
import difflib

import json
import json_delta

from .utils import read_json, read_yaml
from .comparator import EQUAL, DIFFER


# json.JSONEncoder cannot serialize python sets, so create an extension that
# handles them gracefully
class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return sorted(list(obj))
        return json.JSONEncoder.default(self, obj)


def json_diff(d1, d2, file):
    j1 = read_json(d1, file)
    j2 = read_json(d2, file)

    return compare_json(j1, j2)


def yaml_diff(d1, d2, file):
    j1 = read_yaml(d1, file)
    j2 = read_yaml(d2, file)

    return compare_json(j1, j2)


def compare_json(j1, j2):

    if j1 == j2:
        return EQUAL, None

    # If the contents are not equal, use json_delta.diff to calculate the exact
    # differences.  Some of our yaml files include sets, which json_delta
    # cannot handle, so in those cases, fall back to doing a diff of the
    # formatted json.
    try:
        diff = json_delta.diff(j1, j2, False, False)
        return DIFFER, '\n'.join(json_delta.udiff(j1, j2, diff, 2))
    except Exception:
        print("################ EXCEPTION ################")
        print("#                                         #")
        print("# json_delta raised an exception          #")
        print("# using fallback of difflib.unified()     #")
        print("#                                         #")
        print("###########################################")

        diff = difflib.unified_diff(
            json.dumps(j1, indent=2, cls=SetEncoder).split('\n'),
            json.dumps(j2, indent=2, cls=SetEncoder).split('\n'))
        return DIFFER, '\n'.join(diff)
