#
# (c) Copyright 2015,2016 Hewlett Packard Enterprise Development LP
# (c) Copyright 2017 SUSE LLC
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

This test represents a number of server lifecycle steps each
of which uses the persisted state from the previous step to
check the server persistance handling:

Changes are made to both a cluster (servers 1-3) and a resource
group (servers 4-6) to exercise both code paths

Step-1:  3 servers defined, only 2 needed for cluster

               Initial State       Final State
    server1/4: Free                Allocated
    server2/5: Free                Allocated
    server3/6: Free                Free


Step-2:  Servers 2 & 5 deleted

               Initial State       Final State
    server1/4: Allocated           Allocated
    server2/5: Free                Deleted
    server3/6: Free                Allocated


Step-3:  Servers 2 and 5 un-deleted.  Stays in a deleted state
         because the cluster it came from is full

               Initial State       Final State
    server1/4: Allocated           Allocated
    server2/5: Deleted             Deleted
    server3/6: Allocated           Allocated


Step-3a:  Servers 2 and 5 un-deleted and CP run with
          remove-deleted-severs, so servers go to Available

               Initial State       Final State
    server1/4: Allocated           Allocated
    server2/5: Deleted             Avaliable
    server3/6: Allocated           Allocated


Step-4:  (from Step 3) Cluster size increased to 3

               Initial State       Final State
    server1/4: Allocated           Allocated
    server2/5: Deleted             Allocated
    server3/6: Allocated           Allocated


Step-5:  Cluster size decreased to 2

               Initial State       Final State
    server1/4: Allocated           Allocated
    server2/5: Allocated           Allocated
    server3/6: Allocated           Allocated


Step-6:  Servers 3/6 deleted and CP run with remove-deleted-servers

               Initial State       Final State
    server1/4: Allocated           Allocated
    server2/5: Allocated           Allocated
    server3/6: Allocated
